package internaltitle

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Beginner 由连接池或测试事务提供；正文清理与派生标记失效在同一事务内提交。
type Beginner interface {
	Begin(context.Context) (pgx.Tx, error)
}

// Prune 复用原保留期条件分批删除，并在同一事务使对应的标题缓存失效。
// 先取固定候选，再按父请求主键顺序锁父行，最后删除；删除数保持为正文行数。
// table/condition 只能由程序传入固定 SQL，参数只通过 args 绑定。
func Prune(ctx context.Context, db Beginner, table, condition string, internalID bool, batch int, args ...any) (pgconn.CommandTag, error) {
	switch table {
	case "content_logs", "content_log_entries", "content_logs_legacy", "access_content_logs":
	default:
		return pgconn.CommandTag{}, fmt.Errorf("不支持的留存表：%s", table)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, fmt.Sprintf("SELECT id, tenant_id, request_id FROM %s WHERE %s LIMIT %d", table, condition, batch), args...)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	var ids, tenants, requests []string
	for rows.Next() {
		var id, tenant, request string
		if err = rows.Scan(&id, &tenant, &request); err != nil {
			rows.Close()
			return pgconn.CommandTag{}, err
		}
		ids = append(ids, id)
		tenants = append(tenants, tenant)
		requests = append(requests, request)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return pgconn.CommandTag{}, err
	}
	if len(ids) == 0 {
		return pgconn.NewCommandTag("DELETE 0"), nil
	}
	key := "request_id"
	if internalID {
		key = "id"
	}
	parentWhere := "EXISTS (SELECT 1 FROM unnest($1::text[],$2::text[]) AS candidate(tenant,request) WHERE rl.tenant_id=candidate.tenant AND rl." + key + "=candidate.request)"
	// 按父请求主键固定加锁顺序，避免两批候选的消息顺序不同引发死锁。
	lockRows, err := tx.Query(ctx, "SELECT rl.id FROM request_logs rl WHERE "+parentWhere+" ORDER BY rl.id FOR UPDATE", tenants, requests)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	for lockRows.Next() {
	}
	lockRows.Close()
	if err = lockRows.Err(); err != nil {
		return pgconn.CommandTag{}, err
	}
	if _, err = tx.Exec(ctx, "UPDATE request_logs rl SET internal_title_request=NULL WHERE rl.internal_title_request IS NOT NULL AND "+parentWhere, tenants, requests); err != nil {
		return pgconn.CommandTag{}, err
	}
	deleteArgs := append(append([]any{}, args...), ids)
	tag, err := tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE %s AND id = ANY($%d::text[])", table, condition, len(deleteArgs)), deleteArgs...)
	if err != nil {
		return tag, err
	}
	if err = tx.Commit(ctx); err != nil {
		return tag, err
	}
	return tag, nil
}
