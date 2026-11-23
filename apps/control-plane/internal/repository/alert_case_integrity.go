package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 告警案件物化：可用性与完整性（表是否迁移、登记触发器定义摘要、物化口径指纹）。

var errAlertCaseStoreMissing = errors.New("alert case store not migrated")
var errAlertCaseTriggersMissing = errors.New("alert case dirty triggers incomplete")

// alertCaseDirtyTriggers 是迁移 1003 建、1006 改的变更登记触发器（表、触发器名）。缺任何一个、被停用，或定义
// 被降回旧版本（按 1003 的回滚说明回滚后只重跑了 1003），相关变化就不会进待重算队列，物化结果会悄悄过期，
// 所以用物化表前比对这些触发器的定义摘要（alertCaseTriggerDigestSQL）。
var alertCaseDirtyTriggers = [][2]string{
	{"security_events", "trg_alert_case_dirty_event_insert"},
	{"security_events", "trg_alert_case_dirty_event_delete"},
	{"security_events", "trg_alert_case_dirty_event_update"},
	{"request_logs", "trg_alert_case_dirty_request_update"},
	{"access_content_logs", "trg_alert_case_dirty_access_insert"},
	{"access_content_logs", "trg_alert_case_dirty_access_delete"},
	{"access_content_logs", "trg_alert_case_dirty_access_update"},
	{"audit_dispositions", "trg_alert_case_dirty_disposition"},
	{"alert_groups", "trg_alert_case_dirty_group_insert_delete"},
	{"alert_groups", "trg_alert_case_dirty_group_update"},
	{"internal_keys", "trg_alert_case_dirty_key_insert_delete"},
	{"internal_keys", "trg_alert_case_dirty_key_update"},
}

// alertCaseTriggerDigestSQL 是登记触发器定义的摘要：每个触发器的 pg_get_triggerdef、启用状态和触发器函数体，
// 缺的记 missing。迁移 1008 用同一个表达式把升级时的摘要记进 alert_case_trigger_expected（测试核对两边一字不差）；
// 摘要也并进物化口径指纹（alertCaseFullVersionSQL），以后有迁移改了触发器、重新记了摘要，物化结果随之重建。
var alertCaseTriggerDigestSQL = func() string {
	tables, names := make([]string, len(alertCaseDirtyTriggers)), make([]string, len(alertCaseDirtyTriggers))
	for i, trigger := range alertCaseDirtyTriggers {
		tables[i], names[i] = "'"+trigger[0]+"'", "'"+trigger[1]+"'"
	}
	return "(SELECT md5(string_agg(wanted.tbl||'.'||wanted.name||'='||COALESCE(pg_get_triggerdef(t.oid)||' enabled='||t.tgenabled::text||' function='||p.prosrc,'missing')," +
		" E'\\n' ORDER BY wanted.tbl, wanted.name))" +
		" FROM unnest(ARRAY[" + strings.Join(tables, ",") + "]::text[], ARRAY[" + strings.Join(names, ",") + "]::text[]) AS wanted(tbl, name)" +
		" LEFT JOIN pg_trigger t ON t.tgrelid = to_regclass(wanted.tbl) AND t.tgname = wanted.name AND NOT t.tgisinternal" +
		" LEFT JOIN pg_proc p ON p.oid = t.tgfoid)"
}()

// alertCaseTriggersAsExpected：登记触发器的定义摘要与迁移记下的一致（都在、都启用、定义和函数体都是最新的）。
func alertCaseTriggersAsExpected(ctx context.Context, db auditDispositionQueryRower) (bool, error) {
	ok, _, _, err := alertCaseTriggerDigests(ctx, db)
	return ok, err
}

// alertCaseTriggerDigests 返回是否一致、迁移记下的摘要、现算的摘要。
func alertCaseTriggerDigests(ctx context.Context, db auditDispositionQueryRower) (bool, string, string, error) {
	var expected, current string
	err := db.QueryRow(ctx, `SELECT COALESCE((SELECT digest FROM alert_case_trigger_expected),''),COALESCE(`+alertCaseTriggerDigestSQL+`,'')`).Scan(&expected, &current)
	return err == nil && expected != "" && expected == current, expected, current, err
}

var alertCaseCheck = struct {
	sync.Mutex
	usableUntil map[*pgxpool.Pool]time.Time
	// mismatch 记下上一次检查时触发器摘要是否不一致，状态变化时才记日志。
	mismatch bool
}{usableUntil: map[*pgxpool.Pool]time.Time{}}

// resetAlertCaseStoreCheckCache 清掉可用性检查缓存（改了触发器之后的测试用）。
func resetAlertCaseStoreCheckCache() {
	alertCaseCheck.Lock()
	alertCaseCheck.usableUntil = map[*pgxpool.Pool]time.Time{}
	alertCaseCheck.Unlock()
}

// noteAlertCaseTriggerState 在触发器摘要一致与否发生变化时记一条日志（WARN 或恢复）。
func noteAlertCaseTriggerState(mismatch bool, expected, current string) {
	alertCaseCheck.Lock()
	changed := alertCaseCheck.mismatch != mismatch
	alertCaseCheck.mismatch = mismatch
	alertCaseCheck.Unlock()
	if !changed {
		return
	}
	if mismatch {
		log.Printf("[alert-cases] WARN dirty trigger definitions differ from the digest recorded by migration 1008 (expected %s, current %s): "+
			"alert reads use the live query and the store is invalidated until the definitions are restored; see docs/operations/alert-case-store.md", expected, current)
		return
	}
	log.Printf("[alert-cases] dirty trigger definitions match the recorded digest again; the store will be rebuilt in the background")
}

// invalidateAlertCaseStore 作废物化结果：清掉口径指纹、把所有回填置为未完成。触发器补回后由后台重建。
func invalidateAlertCaseStore(ctx context.Context, db *pgxpool.Pool) error {
	resetAlertCaseStoreCheckCache()
	_, err := db.Exec(ctx, `WITH version AS (UPDATE alert_case_store_version SET logic_version='',updated_at=now() WHERE logic_version<>'' RETURNING 1)
UPDATE alert_case_backfill SET done=FALSE,cursor_event_id='',updated_at=now() WHERE done OR cursor_event_id<>''`)
	return err
}

// alertCaseStoreUsable：表已迁移且登记触发器与迁移记下的定义一致；不一致时顺带作废物化结果并记 WARN（状态变化时）。
// 一致的结果在进程内缓存 alertCaseStoreCheckTTL，不一致不缓存。
func alertCaseStoreUsable(ctx context.Context, db *pgxpool.Pool) (bool, error) {
	alertCaseCheck.Lock()
	until, cached := alertCaseCheck.usableUntil[db]
	alertCaseCheck.Unlock()
	if cached && time.Now().Before(until) {
		return true, nil
	}
	exists, err := alertCaseStoreExists(ctx, db)
	if err != nil || !exists {
		return false, err
	}
	complete, expected, current, err := alertCaseTriggerDigests(ctx, db)
	if err != nil {
		return false, err
	}
	noteAlertCaseTriggerState(!complete, expected, current)
	if complete {
		alertCaseCheck.Lock()
		alertCaseCheck.usableUntil[db] = time.Now().Add(alertCaseStoreCheckTTL)
		alertCaseCheck.Unlock()
		return true, nil
	}
	return false, invalidateAlertCaseStore(ctx, db)
}

// AlertCaseStoreStatus 是物化表的诊断状态：能否使用、不能用的原因、触发器摘要（期望与当前）、队列与隔离条目数。
type AlertCaseStoreStatus struct {
	Usable bool `json:"usable"`
	// Reason：disabled（JJD_ALERT_CASE_STORE=off）、not_migrated、trigger_definitions_changed、logic_rebuilding、
	// backfill_pending、quarantined_entries、backlog_over_limit；为空表示可用。
	Reason                string `json:"reason,omitempty"`
	ExpectedTriggerDigest string `json:"expected_trigger_digest,omitempty"`
	CurrentTriggerDigest  string `json:"current_trigger_digest,omitempty"`
	Pending               int    `json:"pending"`
	Quarantined           int    `json:"quarantined"`
	LastQuarantineError   string `json:"last_quarantine_error,omitempty"`
}

// AlertCaseStoreStatus 返回物化表的诊断状态；tenant 为空时只看全局（迁移、触发器、口径指纹）。
func (r *AlertOccurrenceRepository) AlertCaseStoreStatus(ctx context.Context, tenant string) (AlertCaseStoreStatus, error) {
	status := AlertCaseStoreStatus{}
	if r.caseStoreDisabled {
		status.Reason = "disabled"
		return status, nil
	}
	exists, err := alertCaseStoreExists(ctx, r.db)
	if err != nil {
		return status, err
	}
	if !exists {
		status.Reason = "not_migrated"
		return status, nil
	}
	ok, expected, current, err := alertCaseTriggerDigests(ctx, r.db)
	if err != nil {
		return status, err
	}
	status.ExpectedTriggerDigest, status.CurrentTriggerDigest = expected, current
	if !ok {
		status.Reason = "trigger_definitions_changed"
		return status, nil
	}
	useMeta, err := r.useReadMetadata(ctx)
	if err != nil {
		return status, err
	}
	version, err := alertCaseLogicVersion(useMeta)
	if err != nil {
		status.Reason = "logic_rebuilding"
		return status, nil
	}
	var current2, done bool
	if err := r.db.QueryRow(ctx, `SELECT COALESCE((SELECT logic_version FROM alert_case_store_version),'')=`+alertCaseFullVersionSQL("$2::text")+`,
 COALESCE((SELECT done FROM alert_case_backfill WHERE tenant_id=$1),TRUE),
 (SELECT COUNT(*) FROM (SELECT 1 FROM alert_case_dirty WHERE ($1='' OR tenant_id=$1) LIMIT $3) pending),
 (SELECT COUNT(*) FROM alert_case_dirty_quarantine WHERE ($1='' OR tenant_id=$1)),
 COALESCE((SELECT last_error FROM alert_case_dirty_quarantine WHERE ($1='' OR tenant_id=$1) ORDER BY last_failed_at DESC LIMIT 1),'')`,
		tenant, version, alertCaseStaleLimit+1).Scan(&current2, &done, &status.Pending, &status.Quarantined, &status.LastQuarantineError); err != nil {
		return status, err
	}
	switch {
	case !current2:
		status.Reason = "logic_rebuilding"
	case tenant != "" && !done:
		status.Reason = "backfill_pending"
	case tenant != "" && status.Quarantined > 0:
		status.Reason = "quarantined_entries"
	case tenant != "" && status.Pending > alertCaseStaleLimit:
		status.Reason = "backlog_over_limit"
	default:
		status.Usable = true
	}
	return status, nil
}

func alertCaseStoreExists(ctx context.Context, db auditDispositionQueryRower) (bool, error) {
	var exists bool
	err := db.QueryRow(ctx, `SELECT to_regclass('alert_case_backfill') IS NOT NULL AND to_regclass('alert_case_dirty') IS NOT NULL
 AND to_regclass('alert_cases') IS NOT NULL AND to_regclass('alert_case_members') IS NOT NULL AND to_regclass('alert_case_groups') IS NOT NULL
 AND to_regclass('alert_case_store_version') IS NOT NULL AND to_regclass('alert_case_trigger_expected') IS NOT NULL
 AND to_regclass('alert_case_dirty_quarantine') IS NOT NULL`).Scan(&exists)
	return exists, err
}

// alertCaseReadMetadata 与 AlertOccurrenceRepository.useReadMetadata 同一判断（是否有生成列 alert_read_metadata_v1）。
func alertCaseReadMetadata(ctx context.Context, db auditDispositionQueryRower) (bool, error) {
	var available bool
	err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass('security_events') AND attname='alert_read_metadata_v1' AND attgenerated='s' AND NOT attisdropped)`).Scan(&available)
	return available, err
}

// alertCaseLogicVersion 是物化口径的指纹：命中行写入 SQL、案件聚合 SQL、告警组折叠判断，以及是否使用
// 生成列 alert_read_metadata_v1，任何一处变了指纹就变。存下来的指纹不同时（升级改了归并口径），物化结果
// 作废重建，重建完成前读接口实时查询。
func alertCaseLogicVersion(useReadMetadata bool) (string, error) {
	inputs, err := alertCaseLogicInputs(useReadMetadata)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(strings.Join(inputs, "\x00")))
	return hex.EncodeToString(sum[:12]), nil
}

// alertCaseLogicInputs 是口径指纹的全部输入：命中行写入 SQL、物化聚合 SQL 和与之对应的实时聚合 SQL
// （alertCaseRollup、alertCaseLaneRollup，两边任一改了都要重建）、告警组折叠判断、列清单。
func alertCaseLogicInputs(useReadMetadata bool) ([]string, error) {
	insert, _, err := buildAlertCaseMemberInsert(useReadMetadata, "", []string{}, []string{}, []bool{})
	if err != nil {
		return nil, err
	}
	return []string{insert, alertCaseAggregateSQL("SELECT m.* FROM alert_case_members m"), alertCaseRollup, alertCaseLaneRollup,
		alertCaseGroupFoldQuery, strings.Join(alertCaseMemberColumns, ","), strings.Join(alertCaseColumns, ",")}, nil
}

// alertCaseMetadataFingerprintSQL 是读取元数据函数（迁移 850 起，1010 改过）函数体的摘要。生成列按这些函数算，
// 函数变了（新版本只对新写入的行生效）也要重建物化结果，所以函数体并进口径指纹。
const alertCaseMetadataFingerprintSQL = `(SELECT md5(COALESCE(string_agg(p.proname||':'||p.prosrc,'|' ORDER BY p.proname,p.oid),''))
 FROM pg_proc p WHERE p.proname IN ('jjd_alert_finding_metadata_v1','jjd_alert_read_metadata_v1','jjd_alert_read_metadata_v2'))`

// alertCaseFullVersionSQL 是存进 alert_case_store_version 的完整口径指纹：代码指纹（$参数）加函数体摘要。
func alertCaseFullVersionSQL(param string) string {
	return "(" + param + "||':'||" + alertCaseMetadataFingerprintSQL + "||':'||" + alertCaseTriggerDigestSQL + ")"
}

// ensureAlertCaseLogicVersion 发现存下的口径指纹与当前代码不同时，把所有租户的回填重置为未完成并记下新指纹。
func ensureAlertCaseLogicVersion(ctx context.Context, db *pgxpool.Pool, useReadMetadata bool) error {
	want, err := alertCaseLogicVersion(useReadMetadata)
	if err != nil {
		return err
	}
	return pgx.BeginTxFunc(ctx, db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('jjd_alert_cases:logic_version',0))`); err != nil {
			return err
		}
		var current bool
		err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT logic_version FROM alert_case_store_version),'')=`+alertCaseFullVersionSQL("$1::text"), want).Scan(&current)
		if err != nil {
			return err
		}
		if current {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO alert_case_backfill (tenant_id) SELECT id FROM tenants
 ON CONFLICT (tenant_id) DO UPDATE SET done=FALSE,cursor_event_id='',started_at=now(),updated_at=now()`); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO alert_case_store_version (id,logic_version,updated_at) VALUES (TRUE,`+alertCaseFullVersionSQL("$1::text")+`,now())
 ON CONFLICT (id) DO UPDATE SET logic_version=EXCLUDED.logic_version,updated_at=now()`, want)
		return err
	})
}
