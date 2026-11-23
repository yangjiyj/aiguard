package repository

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 告警案件物化：待重算队列的消化（读前限时消化、处置后同步消化、后台批量消化）。

// prepareAlertCaseReads 决定这次读能不能走物化表：表已迁移、登记触发器定义与迁移记下的一致、该租户历史回填已完成、
// 没有隔离中的坏条目、待重算队列不超过上限。能走时先消化该租户的队列：
//   - 列表、汇总、命中明细（exact=false）：最多 alertCaseReadDrainBudget，只取牵动事件少的条目、最新的先取；
//     后台占着租户锁时不等，直接读已物化结果；
//   - 处置授权（exact=true）：要判断“有无新证据”，必须消化完；只消化窄条目，等锁最多 alertCaseExactLockWait、总共最多
//     alertCaseExactDrainBudget、最多 alertCaseExactDrainRounds 批；队列里有告警组、凭据条目或超出上限就改走实时查询
//     （可串行化事务里同样正确）。
func prepareAlertCaseReads(ctx context.Context, db *pgxpool.Pool, useReadMetadata bool, tenant string, exact bool) (bool, error) {
	usable, err := alertCaseStoreUsable(ctx, db)
	if err != nil || !usable {
		return false, err
	}
	var done, current, quarantined bool
	var pending int
	version, err := alertCaseLogicVersion(useReadMetadata)
	if err != nil {
		logAlertCaseShapeError(err)
		return false, nil
	}
	if err := db.QueryRow(ctx, `SELECT COALESCE((SELECT done FROM alert_case_backfill WHERE tenant_id=$1),TRUE),
 (SELECT COUNT(*) FROM (SELECT 1 FROM alert_case_dirty WHERE tenant_id=$1 LIMIT $2) pending),
 COALESCE((SELECT logic_version FROM alert_case_store_version),'')=`+alertCaseFullVersionSQL("$3::text")+`,
 EXISTS(SELECT 1 FROM alert_case_dirty_quarantine WHERE tenant_id=$1)`, tenant, alertCaseStaleLimit+1, version).Scan(&done, &pending, &current, &quarantined); err != nil {
		return false, err
	}
	if !done || !current || quarantined || pending > alertCaseStaleLimit || (exact && pending > alertCaseReadBacklogLimit) {
		return false, nil
	}
	if !exact {
		deadline := time.Now().Add(alertCaseReadDrainBudget)
		for pending > 0 {
			started := time.Now()
			n, err := drainAlertCases(ctx, db, useReadMetadata, tenant, alertCaseReadDrainChunk, alertCaseDrainBeforeRead)
			if errors.Is(err, errAlertCaseTenantBusy) {
				// 后台正在消化这个租户：不等，直接读已物化的结果（最多落后后台这一批）。
				break
			}
			if err != nil {
				alertCaseLogf("read:"+tenant, "[alert-cases] drain before read failed for tenant %s, using live query: %v", tenant, err)
				return false, nil
			}
			// 下一块预计与这块耗时相当，放不进预算就留给后台。
			if n < alertCaseReadDrainChunk || time.Now().Add(time.Since(started)).After(deadline) {
				break
			}
		}
		return true, nil
	}
	deadline := time.Now().Add(alertCaseExactDrainBudget)
	for round := 0; round < alertCaseExactDrainRounds; round++ {
		n, err := drainNarrowAlertCases(ctx, db, useReadMetadata, tenant, alertCaseLock{wait: alertCaseExactLockWait})
		if err != nil {
			// 等锁超时、消化失败都不影响这次授权：改走实时查询，队列留给后台。
			alertCaseLogf("exact:"+tenant, "[alert-cases] drain before authorization did not finish for tenant %s, using live query: %v", tenant, err)
			return false, nil
		}
		if n == 0 {
			// 处置授权只在请求路径上消化窄条目：告警组、凭据条目一条就可能牵动上千条事件、分好几个事务，
			// 截止时间管不住，留给后台，这次改走实时查询授权。
			var wide bool
			if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM alert_case_dirty d WHERE d.tenant_id=$1 AND NOT `+alertCaseNarrowKindSQL+`)`, tenant).Scan(&wide); err != nil || wide {
				return false, nil
			}
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, nil
		}
	}
	return false, nil
}

// drainNarrowAlertCases 消化一批窄条目（事件、请求、处置），最早登记的先取。
func drainNarrowAlertCases(ctx context.Context, db *pgxpool.Pool, useReadMetadata bool, tenant string, lock alertCaseLock) (int, error) {
	return processAlertCaseDirty(ctx, db, useReadMetadata, tenant, lock,
		`DELETE FROM alert_case_dirty WHERE id IN (
 SELECT d.id FROM alert_case_dirty d WHERE d.tenant_id=$1 AND `+alertCaseNarrowKindSQL+` ORDER BY d.id LIMIT $2) RETURNING kind,ref`,
		tenant, alertCaseBackgroundNarrowBatch)
}

// alertCaseDrainMode 是读前消化取待重算条目的方式。重算总是按库里的现状，先后不影响结果。
type alertCaseDrainMode struct {
	newestFirst bool
	// narrowOnly 只取牵动事件少的条目：事件、请求、处置，以及事件不超过 alertCaseReadSmallFanout 条的告警组、凭据。
	// 大告警组、大凭据改标记会牵动上千条事件（670 万条正文的量级下一条凭据约 0.5 秒），留给后台。
	narrowOnly bool
	// tryLock 拿不到租户锁（后台正在消化）时不等，返回 errAlertCaseTenantBusy。
	tryLock bool
}

// alertCaseLock 是消化事务取租户锁的方式。
type alertCaseLock struct {
	// try：拿不到就返回 errAlertCaseTenantBusy，不等。
	try bool
	// wait 大于 0 时最多等这么久（超时报错）；为 0 时一直等（后台）。
	wait time.Duration
	// statementTimeout 大于 0 时事务里每条语句的上限（请求路径上的同步消化用）。
	statementTimeout time.Duration
}

var errAlertCaseTenantBusy = errors.New("alert case tenant is being drained")

// alertCaseDrainBeforeRead：列表、汇总、命中明细读前的限时消化，最新登记的先消化（刚做的处置、刚到的告警），
// 后台占着租户锁时不等。
var alertCaseDrainBeforeRead = alertCaseDrainMode{newestFirst: true, narrowOnly: true, tryLock: true}

// alertCaseChunkObserver 测试用：每个消化事务重算的事件数。
var alertCaseChunkObserver func(events int)

// alertCaseNarrowKindSQL：只牵动少数事件的条目（事件、请求、处置）。
const alertCaseNarrowKindSQL = "d.kind IN ('event','request','case')"

// alertCaseSmallFanoutSQL：牵动事件少的条目——窄条目，以及事件不超过 alertCaseReadSmallFanout 条的告警组、凭据。
func alertCaseSmallFanoutSQL() string {
	return fmt.Sprintf(`(`+alertCaseNarrowKindSQL+`
 OR (d.kind='group' AND (SELECT COUNT(*) FROM (SELECT 1 FROM security_events se WHERE se.tenant_id=d.tenant_id AND se.alert_group_id=d.ref LIMIT %[1]d) g)<%[1]d)
 OR (d.kind='key' AND (SELECT COUNT(*) FROM (SELECT 1 FROM alert_case_members m WHERE m.tenant_id=d.tenant_id AND m.lane_key_id=d.ref LIMIT %[1]d) k)<%[1]d))`, alertCaseReadSmallFanout+1)
}

func alertCaseTenantLock(ctx context.Context, tx pgx.Tx, tenant string) error {
	_, err := alertCaseTenantLockWith(ctx, tx, tenant, alertCaseLock{})
	return err
}

// alertCaseTenantLockWith 按 lock 取租户锁；try 时拿不到返回 false。
func alertCaseTenantLockWith(ctx context.Context, tx pgx.Tx, tenant string, lock alertCaseLock) (bool, error) {
	settings := "SET LOCAL jit = off"
	if lock.wait > 0 {
		settings += fmt.Sprintf("; SET LOCAL lock_timeout = '%dms'", lock.wait.Milliseconds())
	}
	if lock.statementTimeout > 0 {
		settings += fmt.Sprintf("; SET LOCAL statement_timeout = '%dms'", lock.statementTimeout.Milliseconds())
	}
	if _, err := tx.Exec(ctx, settings); err != nil {
		return false, err
	}
	if !lock.try {
		_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('jjd_alert_cases:'||$1,0))`, tenant)
		return err == nil, err
	}
	var acquired bool
	err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('jjd_alert_cases:'||$1,0))`, tenant).Scan(&acquired)
	return acquired, err
}

// drainAlertCases 读前消化一个租户的一块待重算条目（见 alertCaseDrainMode），返回条目数。
func drainAlertCases(ctx context.Context, db *pgxpool.Pool, useReadMetadata bool, tenant string, limit int, mode alertCaseDrainMode) (int, error) {
	pick := "SELECT d.id FROM alert_case_dirty d WHERE d.tenant_id=$1"
	if mode.narrowOnly {
		pick += " AND " + alertCaseSmallFanoutSQL()
	}
	pick += " ORDER BY d.id"
	if mode.newestFirst {
		pick += " DESC"
	}
	return processAlertCaseDirty(ctx, db, useReadMetadata, tenant, alertCaseLock{try: mode.tryLock},
		`DELETE FROM alert_case_dirty WHERE id IN (`+pick+` LIMIT $2) RETURNING kind,ref`, tenant, limit)
}

// drainAlertCaseRefs 消化指定的几条登记（处置类写入提交后调用，只限这次写入涉及的案件、事件、请求、告警组）。
// 只取牵动事件少的条目（大告警组改状态留给后台）；等租户锁最多 alertCaseSyncLockWait，每条语句最多
// alertCaseSyncStatementTimeout。队列里已经没有这些条目（后台刚消化完）时什么也不做。
func drainAlertCaseRefs(ctx context.Context, db *pgxpool.Pool, useReadMetadata bool, tenant string, refs map[string][]string) (int, error) {
	kinds, values := []string{}, []string{}
	for kind, list := range refs {
		for _, ref := range list {
			if strings.TrimSpace(ref) != "" {
				kinds, values = append(kinds, kind), append(values, ref)
			}
		}
	}
	if len(kinds) == 0 {
		return 0, nil
	}
	return processAlertCaseDirty(ctx, db, useReadMetadata, tenant, alertCaseLock{wait: alertCaseSyncLockWait, statementTimeout: alertCaseSyncStatementTimeout},
		`DELETE FROM alert_case_dirty WHERE id IN (
 SELECT d.id FROM alert_case_dirty d JOIN unnest($2::text[],$3::text[]) AS wanted(kind,ref) ON d.kind=wanted.kind AND d.ref=wanted.ref
 WHERE d.tenant_id=$1 AND `+alertCaseSmallFanoutSQL()+`) RETURNING kind,ref`, tenant, kinds, values)
}

// syncAlertCaseRefs 在处置类写入（事件误报、案件处置、告警组状态）提交后同步消化这次登记的条目，让用户
// 刚做的处置在下一次读里就能看到。失败只记日志：写入已经提交，条目留给后台。
func syncAlertCaseRefs(ctx context.Context, db *pgxpool.Pool, tenant string, refs map[string][]string) {
	if db == nil || alertCaseStoreOff {
		return
	}
	usable, err := alertCaseStoreUsable(ctx, db)
	if err != nil || !usable {
		return
	}
	useMeta, err := alertCaseReadMetadata(ctx, db)
	if err != nil {
		return
	}
	if _, err := drainAlertCaseRefs(ctx, db, useMeta, tenant, refs); err != nil {
		alertCaseLogf("sync:"+tenant, "[alert-cases] sync after disposition failed for tenant %s, left to background: %v", tenant, err)
	}
}

// processAlertCaseDirty 在一个事务里取租户锁、按 query 取出（删除）待重算条目并重算，返回条目数。
func processAlertCaseDirty(ctx context.Context, db *pgxpool.Pool, useReadMetadata bool, tenant string, lock alertCaseLock, query string, args ...any) (int, error) {
	processed := 0
	err := pgx.BeginTxFunc(ctx, db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		acquired, err := alertCaseTenantLockWith(ctx, tx, tenant, lock)
		if err != nil {
			return err
		}
		if !acquired {
			return errAlertCaseTenantBusy
		}
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		refs := map[string][]string{}
		for rows.Next() {
			var kind, ref string
			if err := rows.Scan(&kind, &ref); err != nil {
				rows.Close()
				return err
			}
			refs[kind] = append(refs[kind], ref)
			processed++
		}
		rows.Close()
		if err := rows.Err(); err != nil || processed == 0 {
			return err
		}
		return processAlertCaseRefsTx(ctx, tx, useReadMetadata, tenant, refs)
	})
	return processed, err
}

// expandAlertCaseRefs 把登记条目展开成要重算的事件：事件本身、请求和告警组下的事件、凭据牵动的已物化命中。
func expandAlertCaseRefs(ctx context.Context, tx pgx.Tx, tenant string, refs map[string][]string) ([]string, error) {
	var events []string
	err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT id ORDER BY id),'{}') FROM (
 SELECT unnest($2::text[]) AS id
 UNION ALL SELECT se.id FROM security_events se WHERE se.tenant_id=$1 AND se.request_id = ANY($3::text[])
 UNION ALL SELECT se.id FROM security_events se WHERE se.tenant_id=$1 AND se.alert_group_id = ANY($4::text[])
 UNION ALL SELECT m.event_id FROM alert_case_members m WHERE m.tenant_id=$1
   AND (m.request_id = ANY($3::text[]) OR m.alert_group_id = ANY($4::text[]) OR m.lane_key_id = ANY($5::text[]))
) touched`, tenant, nonNilStrings(refs["event"]), nonNilStrings(refs["request"]), nonNilStrings(refs["group"]), nonNilStrings(refs["key"])).Scan(&events)
	return events, err
}

// processAlertCaseRefsTx 在已取得租户锁的事务里重算 refs 牵动的事件：重算命中行、刷新开发作用域折叠标记、
// 重聚合受影响的案件。
func processAlertCaseRefsTx(ctx context.Context, tx pgx.Tx, useReadMetadata bool, tenant string, refs map[string][]string) error {
	events, err := expandAlertCaseRefs(ctx, tx, tenant, refs)
	if err != nil {
		return err
	}
	if alertCaseChunkObserver != nil {
		alertCaseChunkObserver(len(events))
	}
	cases, err := refreshAlertCaseMembers(ctx, tx, useReadMetadata, tenant, events, nonNilStrings(refs["group"]))
	if err != nil {
		return err
	}
	return refreshAlertCases(ctx, tx, tenant, append(cases, refs["case"]...), false)
}

// drainAlertCasesInBatches 按批消化一个租户（后台、处置授权、一次性准备用）：先消化一批窄条目（最多
// alertCaseBackgroundNarrowBatch 条），窄条目没了再处理一条告警组或凭据条目——展开后的事件按
// alertCaseBackgroundEventBatch 分成几个事务，每个事务持锁时间都短。isolate 为真时（后台）一批失败就逐条重试，
// 仍失败的移进隔离表并返回 errAlertCaseQuarantined；否则直接返回错误。返回处理（含隔离）的条目数，0 表示队列空了。
func drainAlertCasesInBatches(ctx context.Context, db *pgxpool.Pool, useReadMetadata bool, tenant string, lock alertCaseLock, isolate bool) (int, error) {
	n, err := drainNarrowAlertCases(ctx, db, useReadMetadata, tenant, lock)
	if err != nil {
		if !isolate || alertCaseLockFailure(err) {
			return n, err
		}
		return isolateAlertCaseEntries(ctx, db, useReadMetadata, tenant, lock, alertCaseNarrowKindSQL, alertCaseBackgroundNarrowBatch, err)
	}
	if n > 0 {
		return n, nil
	}
	return drainWideAlertCaseEntry(ctx, db, useReadMetadata, tenant, lock, isolate)
}

// drainWideAlertCaseEntry 处理最早的一条告警组或凭据条目：先展开成事件，再按 alertCaseBackgroundEventBatch 分事务
// 重算，最后一个事务删掉条目（中途中断时条目还在，下次从头再算一遍，结果相同）。
func drainWideAlertCaseEntry(ctx context.Context, db *pgxpool.Pool, useReadMetadata bool, tenant string, lock alertCaseLock, isolate bool) (int, error) {
	var id int64
	var kind, ref string
	var events []string
	err := pgx.BeginTxFunc(ctx, db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		acquired, err := alertCaseTenantLockWith(ctx, tx, tenant, lock)
		if err != nil {
			return err
		}
		if !acquired {
			return errAlertCaseTenantBusy
		}
		err = tx.QueryRow(ctx, `SELECT d.id,d.kind,d.ref FROM alert_case_dirty d WHERE d.tenant_id=$1 AND NOT `+alertCaseNarrowKindSQL+` ORDER BY d.id LIMIT 1`, tenant).Scan(&id, &kind, &ref)
		if errors.Is(err, pgx.ErrNoRows) {
			id = 0
			return nil
		}
		if err != nil {
			return err
		}
		events, err = expandAlertCaseRefs(ctx, tx, tenant, map[string][]string{kind: {ref}})
		return err
	})
	if err != nil || id == 0 {
		return 0, err
	}
	chunks := [][]string{}
	for start := 0; start < len(events); start += alertCaseBackgroundEventBatch {
		chunks = append(chunks, events[start:min(start+alertCaseBackgroundEventBatch, len(events))])
	}
	if len(chunks) == 0 {
		chunks = [][]string{nil}
	}
	for i, chunk := range chunks {
		last := i == len(chunks)-1
		err := pgx.BeginTxFunc(ctx, db, pgx.TxOptions{}, func(tx pgx.Tx) error {
			acquired, err := alertCaseTenantLockWith(ctx, tx, tenant, lock)
			if err != nil {
				return err
			}
			if !acquired {
				return errAlertCaseTenantBusy
			}
			var groups []string
			if last {
				if _, err := tx.Exec(ctx, `DELETE FROM alert_case_dirty WHERE id=$1`, id); err != nil {
					return err
				}
				if kind == "group" {
					groups = []string{ref}
				}
			}
			if alertCaseChunkObserver != nil {
				alertCaseChunkObserver(len(chunk))
			}
			cases, err := refreshAlertCaseMembers(ctx, tx, useReadMetadata, tenant, chunk, groups)
			if err != nil {
				return err
			}
			return refreshAlertCases(ctx, tx, tenant, cases, false)
		})
		if err != nil {
			if !isolate || alertCaseLockFailure(err) {
				return 0, err
			}
			if qerr := quarantineAlertCaseEntry(ctx, db, tenant, id, err); qerr != nil {
				return 0, qerr
			}
			return 1, fmt.Errorf("%w: %s %s: %v", errAlertCaseQuarantined, kind, ref, err)
		}
	}
	return 1, nil
}

var errAlertCaseQuarantined = errors.New("alert case entries quarantined")

// alertCaseLockFailure：等锁超时、拿不到锁、调用方取消——不是条目本身的问题，不隔离。
func alertCaseLockFailure(err error) bool {
	if errors.Is(err, errAlertCaseTenantBusy) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "55P03" || pgErr.Code == "57014")
}

// isolateAlertCaseEntries 一批失败后逐条重试最早的 limit 条（kindSQL 那类）条目：成功的照常消化，仍失败的移进隔离表。
func isolateAlertCaseEntries(ctx context.Context, db *pgxpool.Pool, useReadMetadata bool, tenant string, lock alertCaseLock, kindSQL string, limit int, cause error) (int, error) {
	var ids []int64
	if err := db.QueryRow(ctx, `SELECT COALESCE(array_agg(id ORDER BY id),'{}') FROM (
 SELECT d.id FROM alert_case_dirty d WHERE d.tenant_id=$1 AND `+kindSQL+` ORDER BY d.id LIMIT $2) batch`, tenant, limit).Scan(&ids); err != nil {
		return 0, err
	}
	handled, quarantined := 0, 0
	for _, id := range ids {
		_, err := processAlertCaseDirty(ctx, db, useReadMetadata, tenant, lock, `DELETE FROM alert_case_dirty WHERE id=$2 AND tenant_id=$1 RETURNING kind,ref`, tenant, id)
		if err == nil {
			handled++
			continue
		}
		if alertCaseLockFailure(err) {
			return handled, err
		}
		if qerr := quarantineAlertCaseEntry(ctx, db, tenant, id, err); qerr != nil {
			return handled, qerr
		}
		handled++
		quarantined++
	}
	if quarantined > 0 {
		return handled, fmt.Errorf("%w: %d entries for tenant %s (batch error: %v)", errAlertCaseQuarantined, quarantined, tenant, cause)
	}
	return handled, nil
}

// quarantineAlertCaseEntry 把一条处理不了的条目移进隔离表（同租户同条目已在隔离表里时累加次数）。
func quarantineAlertCaseEntry(ctx context.Context, db *pgxpool.Pool, tenant string, id int64, cause error) error {
	message := cause.Error()
	if len(message) > 2000 {
		message = message[:2000]
	}
	_, err := db.Exec(ctx, `WITH moved AS (DELETE FROM alert_case_dirty WHERE id=$1 AND tenant_id=$2 RETURNING tenant_id,kind,ref),
bumped AS (
 UPDATE alert_case_dirty_quarantine q SET attempts=q.attempts+1,last_error=$3,last_failed_at=now()
 FROM moved WHERE q.tenant_id=moved.tenant_id AND q.kind=moved.kind AND q.ref=moved.ref RETURNING q.id)
INSERT INTO alert_case_dirty_quarantine(tenant_id,kind,ref,last_error)
SELECT tenant_id,kind,ref,$3 FROM moved WHERE NOT EXISTS (SELECT 1 FROM bumped)`, id, tenant, message)
	alertCaseLogf("quarantine:"+tenant, "[alert-cases] WARN quarantined a dirty entry for tenant %s (reads for this tenant use the live query until it is retried): %v", tenant, cause)
	return err
}

// retryAlertCaseQuarantine 重试隔离超过 alertCaseQuarantineRetryAfter 的条目：成功就移除，失败累加次数。
func retryAlertCaseQuarantine(ctx context.Context, db *pgxpool.Pool, useReadMetadata bool, tenant string) (int, error) {
	type entry struct {
		id        int64
		kind, ref string
	}
	rows, err := db.Query(ctx, `SELECT id,kind,ref FROM alert_case_dirty_quarantine WHERE tenant_id=$1
 AND last_failed_at <= now() - make_interval(secs => $2) ORDER BY id LIMIT 20`, tenant, alertCaseQuarantineRetryAfter.Seconds())
	if err != nil {
		return 0, err
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.kind, &e.ref); err != nil {
			rows.Close()
			return 0, err
		}
		entries = append(entries, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	cleared := 0
	for _, e := range entries {
		err := pgx.BeginTxFunc(ctx, db, pgx.TxOptions{}, func(tx pgx.Tx) error {
			if err := alertCaseTenantLock(ctx, tx, tenant); err != nil {
				return err
			}
			if err := processAlertCaseRefsTx(ctx, tx, useReadMetadata, tenant, map[string][]string{e.kind: {e.ref}}); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `DELETE FROM alert_case_dirty_quarantine WHERE id=$1`, e.id)
			return err
		})
		if err == nil {
			cleared++
			continue
		}
		message := err.Error()
		if len(message) > 2000 {
			message = message[:2000]
		}
		if _, uerr := db.Exec(ctx, `UPDATE alert_case_dirty_quarantine SET attempts=attempts+1,last_error=$2,last_failed_at=now() WHERE id=$1`, e.id, message); uerr != nil {
			return cleared, uerr
		}
		alertCaseLogf("quarantine:"+tenant, "[alert-cases] WARN retry of a quarantined entry failed for tenant %s: %v", tenant, err)
	}
	return cleared, nil
}

var (
	alertCaseLogMu   sync.Mutex
	alertCaseLogLast = map[string]time.Time{}
)

// alertCaseLogf 按 key 限频记日志（同一 key 每 alertCaseLogInterval 最多一条）。
func alertCaseLogf(key, format string, args ...any) {
	alertCaseLogMu.Lock()
	now := time.Now()
	if last, ok := alertCaseLogLast[key]; ok && now.Sub(last) < alertCaseLogInterval {
		alertCaseLogMu.Unlock()
		return
	}
	alertCaseLogLast[key] = now
	alertCaseLogMu.Unlock()
	log.Printf(format, args...)
}

// refreshAlertCaseMembers 重算一批事件的命中行，并刷新这些事件（以及额外给出的告警组）所在告警组全体命中的
// 开发作用域折叠标记。返回受影响的案件编号（新旧都算）。
func refreshAlertCaseMembers(ctx context.Context, tx pgx.Tx, useReadMetadata bool, tenant string, events, groups []string) ([]string, error) {
	cases := []string{}
	if len(events) > 0 {
		// 这批事件现在和原来所在的告警组（改了告警组的事件两边都算）都要重新求折叠标记。
		var currentGroups []string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT gid),'{}') FROM (
 SELECT alert_group_id AS gid FROM security_events WHERE tenant_id=$1 AND id = ANY($2::text[]) AND COALESCE(alert_group_id,'')<>''
 UNION SELECT alert_group_id FROM alert_case_members WHERE tenant_id=$1 AND event_id = ANY($2::text[]) AND alert_group_id<>'') g`,
			tenant, events).Scan(&currentGroups); err != nil {
			return nil, err
		}
		groups = append(groups, currentGroups...)
	}
	groupIDs, flags, err := alertCaseGroupFlags(ctx, tx, tenant, groups)
	if err != nil {
		return nil, err
	}
	if len(events) > 0 {
		var removedCases []string
		if err := tx.QueryRow(ctx, `WITH removed AS (
 DELETE FROM alert_case_members WHERE tenant_id=$1 AND event_id = ANY($2::text[]) RETURNING case_id)
SELECT COALESCE(array_agg(DISTINCT case_id),'{}') FROM removed`, tenant, events).Scan(&removedCases); err != nil {
			return nil, err
		}
		cases = append(cases, removedCases...)
		query, args, err := buildAlertCaseMemberInsert(useReadMetadata, tenant, events, groupIDs, flags)
		if err != nil {
			return nil, err
		}
		var insertedCases []string
		if err := tx.QueryRow(ctx, query, args...).Scan(&insertedCases); err != nil {
			return nil, fmt.Errorf("refresh alert case members: %w", err)
		}
		cases = append(cases, insertedCases...)
	}
	if len(groupIDs) > 0 {
		var flagged []string
		if err := tx.QueryRow(ctx, `WITH flags AS (SELECT * FROM unnest($2::text[],$3::boolean[]) AS f(gid,folded)),
stored AS (
 INSERT INTO alert_case_groups (tenant_id,group_id,folded) SELECT $1,gid,folded FROM flags
 ON CONFLICT (tenant_id,group_id) DO UPDATE SET folded=EXCLUDED.folded,refreshed_at=now()
 RETURNING group_id
), changed AS (
 UPDATE alert_case_members m SET dev_folded=flags.folded,refreshed_at=now() FROM flags
 WHERE m.tenant_id=$1 AND m.alert_group_id=flags.gid AND m.dev_folded IS DISTINCT FROM flags.folded
 RETURNING m.case_id)
SELECT COALESCE(array_agg(DISTINCT case_id),'{}') FROM changed`, tenant, groupIDs, flags).Scan(&flagged); err != nil {
			return nil, err
		}
		cases = append(cases, flagged...)
	}
	return cases, nil
}

// alertCaseGroupFoldQuery 求一个告警组的开发作用域折叠标记，判断与 developmentFoldedEventExpr 相同。
// 一次只查一个组：多个组放进同一条语句时，计划会把折叠条件里的子查询做成对全租户请求记录的哈希子计划
// （客户A量级下一批几百个组就要一两秒）；单组查询走索引。
var alertCaseGroupFoldQuery = `SELECT ` + developmentAlertGroupFoldExpr("dev_group") + ` FROM alert_groups dev_group WHERE dev_group.tenant_id=$1 AND dev_group.id=$2`

// alertCaseGroupFlags 用一次批量往返求一组告警组的折叠标记；不存在的组按不折叠。
func alertCaseGroupFlags(ctx context.Context, tx pgx.Tx, tenant string, groups []string) ([]string, []bool, error) {
	seen := map[string]bool{}
	ids := []string{}
	for _, group := range groups {
		if group != "" && !seen[group] {
			seen[group] = true
			ids = append(ids, group)
		}
	}
	flags := make([]bool, len(ids))
	if len(ids) == 0 {
		return ids, flags, nil
	}
	batch := &pgx.Batch{}
	for _, id := range ids {
		batch.Queue(alertCaseGroupFoldQuery, tenant, id)
	}
	results := tx.SendBatch(ctx, batch)
	for index := range ids {
		var folded bool
		err := results.QueryRow().Scan(&folded)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			results.Close()
			return nil, nil, err
		}
		flags[index] = err == nil && folded
	}
	return ids, flags, results.Close()
}

// buildAlertCaseMemberInsert 用实时查询的同一段 SQL（到 keyed 为止）算出这批事件的命中行并写入。
func buildAlertCaseMemberInsert(useReadMetadata bool, tenant string, events, groupIDs []string, groupFlags []bool) (string, []any, error) {
	f := AlertOccurrenceFilter{TenantID: tenant, Grouping: "cases", LaneAware: true, IncludeDevTraffic: true,
		IncludeSuppressed: true, Limit: 1, useReadMetadata: useReadMetadata, eventIDs: events}
	query, args := buildAlertOccurrenceQuery(f)
	args = append(args, groupIDs, groupFlags)
	groupsArg, flagsArg := fmt.Sprintf("$%d", len(args)-1), fmt.Sprintf("$%d", len(args))
	before, err := sqlBeforeMarker(query, "ranked AS (")
	if err != nil {
		return "", nil, err
	}
	head := strings.TrimSuffix(strings.TrimRight(before, " \n"), ",")
	columns := strings.Join(alertCaseMemberColumns, ",")
	// 折叠标记与实时查询的 developmentFoldedEventExpr 同一判断，但只对这批事件所在的告警组求值一次。
	// 操作人、请求会话与实时查询按用户、会话筛选时关联请求记录的口径相同（alertOccurrenceRequestJoin）。
	return head + `,
inserted AS (
 INSERT INTO alert_case_members (` + columns + `,finding_slot,dev_folded,lane_key_id,actor_user_id,filter_session_id,endpoint_session_id)
 SELECT ` + prefixedColumns("k", alertCaseMemberColumns) + `,COALESCE(k.finding_index,-1),
   COALESCE(batch_groups.folded,FALSE),
   COALESCE(NULLIF(lane_key.principal_context_json->>'key_id',''),NULLIF(lane_key.client_id,''),''),
   COALESCE(` + occurrenceActorExpr + `,''),
   COALESCE(rl.session_id,''),
   CASE WHEN se.matched_summary->>'source'='agent_endpoint' THEN COALESCE(se.matched_summary->>'session_id','') ELSE '' END
 FROM keyed k
 JOIN security_events se ON se.tenant_id=k.tenant_id AND se.id=k.event_id
 LEFT JOIN unnest(` + groupsArg + `::text[],` + flagsArg + `::boolean[]) AS batch_groups(gid,folded) ON batch_groups.gid=se.alert_group_id` + alertOccurrenceRequestJoin + `
 LEFT JOIN LATERAL (
   SELECT r.principal_context_json,r.client_id FROM request_logs r
   WHERE r.tenant_id=se.tenant_id AND r.request_id=se.request_id ORDER BY r.created_at,r.id LIMIT 1
 ) lane_key ON TRUE
 WHERE $2::boolean IS NOT NULL AND $3::boolean IS NOT NULL AND $4::boolean IS NOT NULL AND $5::integer>=0 AND $6::integer>=0
 RETURNING case_id
)
SELECT COALESCE(array_agg(DISTINCT case_id),'{}') FROM inserted`, args, nil
}

// refreshAlertCases 按当前命中行重聚合给定案件（all 为真时重聚合该租户全部案件）。
func refreshAlertCases(ctx context.Context, tx pgx.Tx, tenant string, cases []string, all bool) error {
	if !all && len(cases) == 0 {
		return nil
	}
	filter := "m.tenant_id=$1"
	args := []any{tenant}
	if !all {
		filter += " AND m.case_id = ANY($2::text[])"
		args = append(args, cases)
		if _, err := tx.Exec(ctx, `DELETE FROM alert_cases WHERE tenant_id=$1 AND case_id = ANY($2::text[])`, args...); err != nil {
			return err
		}
	} else if _, err := tx.Exec(ctx, `DELETE FROM alert_cases WHERE tenant_id=$1`, tenant); err != nil {
		return err
	}
	// 只扫一遍命中行：没有开发作用域折叠命中的案件，customer 范围的聚合与 all 完全相同，直接复用；
	// 只有含折叠命中的案件（开发作用域的语义告警，少数）再按去掉折叠命中重聚合一次。
	columns := strings.Join(alertCaseColumns, ",")
	_, err := tx.Exec(ctx, `WITH all_scope AS MATERIALIZED (`+alertCaseAggregateSQL("SELECT m.* FROM alert_case_members m WHERE "+filter)+`),
customer_dev AS MATERIALIZED (`+alertCaseAggregateSQL("SELECT m.* FROM alert_case_members m WHERE m.tenant_id=$1 AND NOT m.dev_folded AND m.case_id IN (SELECT case_id FROM all_scope WHERE has_dev_folded)")+`)
INSERT INTO alert_cases (scope,`+columns+`)
SELECT 'all',`+columns+` FROM all_scope
UNION ALL SELECT 'customer',`+columns+` FROM all_scope WHERE NOT has_dev_folded
UNION ALL SELECT 'customer',`+columns+` FROM customer_dev`, args...)
	return err
}
