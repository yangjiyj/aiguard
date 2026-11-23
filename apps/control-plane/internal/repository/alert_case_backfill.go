package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 告警案件物化：历史回填。

// backfillAlertCases 回填一个租户的下一批历史事件；最后一批完成时重聚合该租户全部案件并标记完成。
// 进度按事件编号推进，每批一个事务，中断后从上次提交的位置继续，重跑同一批结果相同。
func backfillAlertCases(ctx context.Context, db *pgxpool.Pool, useReadMetadata bool, tenant string, batch int) (bool, error) {
	finished := false
	err := pgx.BeginTxFunc(ctx, db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := alertCaseTenantLock(ctx, tx, tenant); err != nil {
			return err
		}
		var cursor string
		var done bool
		err := tx.QueryRow(ctx, `SELECT cursor_event_id,done FROM alert_case_backfill WHERE tenant_id=$1 FOR UPDATE`, tenant).Scan(&cursor, &done)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && done) {
			finished = true
			return nil
		}
		if err != nil {
			return err
		}
		var events []string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(id ORDER BY id),'{}') FROM (
 SELECT id FROM security_events WHERE tenant_id=$1 AND id>$2 ORDER BY id LIMIT $3) batch`, tenant, cursor, batch).Scan(&events); err != nil {
			return err
		}
		if len(events) > 0 {
			if _, err := refreshAlertCaseMembers(ctx, tx, useReadMetadata, tenant, events, nil); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE alert_case_backfill SET cursor_event_id=$2,updated_at=now() WHERE tenant_id=$1`, tenant, events[len(events)-1])
			return err
		}
		// 回填期间折叠标记以各事件写入时的告警组状态为准，收尾时按告警组统一刷新一遍再整体聚合。
		var groups []string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT gid),'{}') FROM (
 SELECT id AS gid FROM alert_groups WHERE tenant_id=$1
 UNION SELECT alert_group_id FROM alert_case_members WHERE tenant_id=$1 AND alert_group_id<>'') g`, tenant).Scan(&groups); err != nil {
			return err
		}
		if _, err := refreshAlertCaseMembers(ctx, tx, useReadMetadata, tenant, nil, groups); err != nil {
			return err
		}
		// 重建期间（作废后到回填完成前）删掉的事件不会再有登记，它们的命中行在这里清掉，再整体聚合。
		if _, err := tx.Exec(ctx, `DELETE FROM alert_case_members m WHERE m.tenant_id=$1
 AND NOT EXISTS (SELECT 1 FROM security_events se WHERE se.tenant_id=m.tenant_id AND se.id=m.event_id)`, tenant); err != nil {
			return err
		}
		if err := refreshAlertCases(ctx, tx, tenant, nil, true); err != nil {
			return err
		}
		finished = true
		_, err = tx.Exec(ctx, `UPDATE alert_case_backfill SET done=TRUE,updated_at=now() WHERE tenant_id=$1`, tenant)
		return err
	})
	return finished, err
}
