package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func alertCaseLimitsDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("ALERT_CASES_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("ALERT_CASES_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db, ctx
}

// holdAlertCaseTenantLock 模拟后台正在消化这个租户：另开一个事务占住租户锁，返回释放函数。
func holdAlertCaseTenantLock(t *testing.T, ctx context.Context, db *pgxpool.Pool, tenant string) func() {
	t.Helper()
	conn, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		conn.Release()
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('jjd_alert_cases:'||$1,0))`, tenant); err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_ = tx.Rollback(context.Background())
			conn.Release()
		}
	}
	t.Cleanup(release)
	return release
}

// 一个只有一个大告警组（count 条事件）的租户；返回租户编号。
func seedAlertCaseGroupTenant(t *testing.T, ctx context.Context, db *pgxpool.Pool, events int) string {
	t.Helper()
	tenant := fmt.Sprintf("t_limits_%d", time.Now().UnixNano())
	t.Cleanup(func() {
		for _, sql := range []string{`DELETE FROM security_events WHERE tenant_id=$1`, `DELETE FROM request_logs WHERE tenant_id=$1`,
			`DELETE FROM projects WHERE tenant_id=$1`, `DELETE FROM alert_case_dirty WHERE tenant_id=$1`, `DELETE FROM alert_case_dirty_quarantine WHERE tenant_id=$1`,
			`DELETE FROM alert_case_members WHERE tenant_id=$1`, `DELETE FROM alert_cases WHERE tenant_id=$1`, `DELETE FROM alert_case_groups WHERE tenant_id=$1`,
			`DELETE FROM alert_case_backfill WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`} {
			_, _ = db.Exec(context.Background(), sql, tenant)
		}
	})
	for _, sql := range []string{
		`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',TRUE)`,
		`INSERT INTO projects(id,tenant_id,name) VALUES($1||'_p',$1,'应用')`,
		`INSERT INTO request_logs(id,request_id,tenant_id,project_id,environment_scope,created_at) VALUES($1||'_r',$1||'_r',$1,$1||'_p','customer',now()-interval '1 hour')`,
	} {
		if _, err := db.Exec(ctx, sql, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary,alert_group_id,created_at)
 SELECT $1||'_e'||g,$1||'_r',$1,$1||'_p','security_check','high','flag',
   jsonb_build_object('findings',jsonb_build_array(jsonb_build_object('type','pii','category','email','severity','high','rule_id','r1','rule_name','邮箱','message_index',0,
     'matched_location','content[0:'||g||']','evidence_identity_sha256',md5(g::text)||md5(g::text)))),'big_group',now()-make_interval(mins=>g)
 FROM generate_series(1,$2::int) g`, tenant, events); err != nil {
		t.Fatal(err)
	}
	return tenant
}

// 处置授权（必须先消化完队列）等租户锁、消化都有上限：后台占着锁时不无限等，超过上限改走实时查询（可串行化事务里
// 实时查询同样正确）。
func TestAlertCaseAuthorizationDrainGivesUpWhenTheTenantIsBusy(t *testing.T) {
	db, ctx := alertCaseLimitsDB(t)
	tenant := seedAlertCaseGroupTenant(t, ctx, db, 3)
	repo := NewAlertOccurrenceRepository(db)
	if err := repo.PrepareAlertCases(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE security_events SET severity='critical' WHERE id=$1`, tenant+"_e1"); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_case_dirty WHERE tenant_id=$1`, tenant).Scan(&pending); err != nil || pending == 0 {
		t.Fatalf("the change must be queued: %d %v", pending, err)
	}
	if status, err := repo.AlertCaseStoreStatus(ctx, tenant); err != nil || !status.Usable {
		t.Fatalf("store must otherwise be usable for this tenant: %+v %v", status, err)
	}
	release := holdAlertCaseTenantLock(t, ctx, db, tenant)
	defer release()
	limited, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	started := time.Now()
	meta, err := repo.useReadMetadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := prepareAlertCaseReads(limited, db, meta, tenant, true)
	if err != nil {
		t.Fatalf("authorization drain must fall back instead of failing: %v", err)
	}
	if materialized {
		t.Fatal("the queue could not be drained; authorization must use the live query")
	}
	if took := time.Since(started); took < alertCaseExactLockWait/2 || took > alertCaseExactLockWait+2*time.Second {
		t.Fatalf("authorization should wait about %v for the tenant lock, waited %v", alertCaseExactLockWait, took)
	}
	release()
	if materialized, err := prepareAlertCaseReads(ctx, db, meta, tenant, true); err != nil || !materialized {
		t.Fatalf("once the lock is free authorization drains the queue and reads the store: %v %v", materialized, err)
	}
}

// 处置后同步消化只处理牵动事件少的条目：大告警组（事件超过 alertCaseReadSmallFanout 条）改状态留给后台。
func TestAlertCaseSyncDrainLeavesLargeGroupsToTheBackground(t *testing.T) {
	db, ctx := alertCaseLimitsDB(t)
	tenant := seedAlertCaseGroupTenant(t, ctx, db, alertCaseReadSmallFanout+1)
	repo := NewAlertOccurrenceRepository(db)
	if err := repo.PrepareAlertCases(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO alert_case_dirty(tenant_id,kind,ref) VALUES($1,'group','big_group')`, tenant); err != nil {
		t.Fatal(err)
	}
	n, err := drainAlertCaseRefs(ctx, db, false, tenant, map[string][]string{"group": {"big_group"}})
	if err != nil || n != 0 {
		t.Fatalf("sync drain must leave the large group: n=%d err=%v", n, err)
	}
	var left int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_case_dirty WHERE tenant_id=$1 AND kind='group'`, tenant).Scan(&left); err != nil || left != 1 {
		t.Fatalf("large group entry must stay queued: %d %v", left, err)
	}
}

// 后台按展开后的事件数切批：一条牵动很多事件的告警组条目分成几个事务处理，每个事务的事件数不超过上限；
// “窄”条目也按条数切批。处理完队列清空，结果与实时一致。
func TestAlertCaseBackgroundDrainSplitsLargeEntries(t *testing.T) {
	db, ctx := alertCaseLimitsDB(t)
	tenant := seedAlertCaseGroupTenant(t, ctx, db, 120)
	repo := NewAlertOccurrenceRepository(db)
	if err := repo.PrepareAlertCases(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	oldEvents, oldNarrow := alertCaseBackgroundEventBatch, alertCaseBackgroundNarrowBatch
	alertCaseBackgroundEventBatch, alertCaseBackgroundNarrowBatch = 50, 40
	var chunks []int
	alertCaseChunkObserver = func(events int) { chunks = append(chunks, events) }
	t.Cleanup(func() {
		alertCaseBackgroundEventBatch, alertCaseBackgroundNarrowBatch = oldEvents, oldNarrow
		alertCaseChunkObserver = nil
	})
	if _, err := db.Exec(ctx, `INSERT INTO alert_case_dirty(tenant_id,kind,ref) SELECT $1::text,'event',$1::text||'_e'||g FROM generate_series(1,100) g`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO alert_case_dirty(tenant_id,kind,ref) VALUES($1,'group','big_group')`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := repo.PrepareAlertCases(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 4 {
		t.Fatalf("expected the narrow entries and the large group to be split, got chunks %v", chunks)
	}
	for _, n := range chunks {
		if n > 50 {
			t.Fatalf("a transaction recomputed %d events; the cap is 50 (chunks %v)", n, chunks)
		}
	}
	live := &AlertOccurrenceRepository{db: db, caseStoreDisabled: true}
	f := AlertOccurrenceFilter{TenantID: tenant, Grouping: "cases", IncludeSuppressed: true, IncludeDevTraffic: true, Limit: 100}
	want, err := live.List(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.List(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, "after split drain", want, got)
}

// 坏条目隔离：一批里有一条怎么都处理不了时，其余条目照常消化，坏条目移进隔离表（记下错误和次数），
// 这个租户的读改走实时查询；故障排除后后台重试隔离条目，成功了就回到物化读法。
func TestAlertCaseBadEntriesAreQuarantinedAndRetried(t *testing.T) {
	db, ctx := alertCaseLimitsDB(t)
	tenant := seedAlertCaseGroupTenant(t, ctx, db, 4)
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DROP TRIGGER IF EXISTS zz_alert_case_member_bad ON alert_case_members; DROP FUNCTION IF EXISTS zz_alert_case_member_bad()`)
	})
	repo := NewAlertOccurrenceRepository(db)
	if err := repo.PrepareAlertCases(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	bad := tenant + "_e2"
	if _, err := db.Exec(ctx, `CREATE FUNCTION zz_alert_case_member_bad() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.event_id = '`+bad+`' THEN RAISE EXCEPTION 'injected bad entry'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER zz_alert_case_member_bad BEFORE INSERT ON alert_case_members FOR EACH ROW EXECUTE FUNCTION zz_alert_case_member_bad();`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE security_events SET severity='critical' WHERE tenant_id=$1 AND id IN ($1||'_e1',$1||'_e2',$1||'_e3')`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.MaintainAlertCases(ctx, 10*time.Second); err == nil {
		t.Fatal("maintenance should report the quarantined entry")
	}
	var pending, quarantined, attempts int
	var lastError string
	if err := db.QueryRow(ctx, `SELECT (SELECT COUNT(*) FROM alert_case_dirty WHERE tenant_id=$1),
 (SELECT COUNT(*) FROM alert_case_dirty_quarantine WHERE tenant_id=$1),
 COALESCE((SELECT MAX(attempts) FROM alert_case_dirty_quarantine WHERE tenant_id=$1 AND ref=$2),0),
 COALESCE((SELECT MAX(last_error) FROM alert_case_dirty_quarantine WHERE tenant_id=$1 AND ref=$2),'')`, tenant, bad).Scan(&pending, &quarantined, &attempts, &lastError); err != nil {
		t.Fatal(err)
	}
	if pending != 0 || quarantined != 1 || attempts != 1 || !strings.Contains(lastError, "injected bad entry") {
		t.Fatalf("pending=%d quarantined=%d attempts=%d error=%q", pending, quarantined, attempts, lastError)
	}
	f := AlertOccurrenceFilter{TenantID: tenant, Grouping: "cases", IncludeSuppressed: true, IncludeDevTraffic: true, Limit: 100}
	if alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("a tenant with quarantined entries must be read with the live query")
	}
	status, err := repo.AlertCaseStoreStatus(ctx, tenant)
	if err != nil || status.Quarantined != 1 || status.Reason != "quarantined_entries" {
		t.Fatalf("status = %+v err=%v", status, err)
	}

	if _, err := db.Exec(ctx, `DROP TRIGGER zz_alert_case_member_bad ON alert_case_members; DROP FUNCTION zz_alert_case_member_bad()`); err != nil {
		t.Fatal(err)
	}
	oldRetry := alertCaseQuarantineRetryAfter
	alertCaseQuarantineRetryAfter = 0
	t.Cleanup(func() { alertCaseQuarantineRetryAfter = oldRetry })
	if _, err := repo.MaintainAlertCases(ctx, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_case_dirty_quarantine WHERE tenant_id=$1`, tenant).Scan(&quarantined); err != nil || quarantined != 0 {
		t.Fatalf("retry must clear the quarantine: %d %v", quarantined, err)
	}
	if !alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("after a successful retry the store should serve reads again")
	}
	live := &AlertOccurrenceRepository{db: db, caseStoreDisabled: true}
	want, err := live.List(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.List(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, "after quarantine retry", want, got)
}

// 触发器摘要不一致时，状态接口能说明原因（带期望与当前摘要），读走实时查询。
func TestAlertCaseStoreStatusExplainsTriggerMismatch(t *testing.T) {
	db, ctx := alertCaseLimitsDB(t)
	repo := NewAlertOccurrenceRepository(db)
	status, err := repo.AlertCaseStoreStatus(ctx, "")
	if err != nil || !status.Usable || status.Reason != "" {
		t.Fatalf("migrated store status = %+v err=%v", status, err)
	}
	var definition string
	if err := db.QueryRow(ctx, `SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgname='trg_alert_case_dirty_key_update'`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `DROP TRIGGER trg_alert_case_dirty_key_update ON internal_keys`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), definition)
		resetAlertCaseStoreCheckCache()
	})
	resetAlertCaseStoreCheckCache()
	status, err = repo.AlertCaseStoreStatus(ctx, "")
	if err != nil || status.Usable || status.Reason != "trigger_definitions_changed" || status.ExpectedTriggerDigest == "" ||
		status.ExpectedTriggerDigest == status.CurrentTriggerDigest {
		t.Fatalf("mismatch status = %+v err=%v", status, err)
	}
}

// 处置授权只在请求路径上消化窄条目：队列里有告警组或凭据条目（哪怕很小）时，窄条目照常消化，宽条目留给后台，
// 这次授权改走实时查询，不在请求路径上分多个事务展开大组（截止时间管不住）。
func TestAlertCaseAuthorizationDrainLeavesWideEntriesAndUsesLiveQuery(t *testing.T) {
	db, ctx := alertCaseLimitsDB(t)
	tenant := seedAlertCaseGroupTenant(t, ctx, db, alertCaseReadSmallFanout+1)
	repo := NewAlertOccurrenceRepository(db)
	if err := repo.PrepareAlertCases(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	meta, err := repo.useReadMetadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var chunks []int
	alertCaseChunkObserver = func(events int) { chunks = append(chunks, events) }
	t.Cleanup(func() { alertCaseChunkObserver = nil })
	for _, kind := range []string{"group", "key"} {
		chunks = nil
		if _, err := db.Exec(ctx, `INSERT INTO alert_case_dirty(tenant_id,kind,ref) VALUES($1,$2,$3),($1,'event',$1||'_e1')`, tenant, kind, "big_group"); err != nil {
			t.Fatal(err)
		}
		materialized, err := prepareAlertCaseReads(ctx, db, meta, tenant, true)
		if err != nil || materialized {
			t.Fatalf("%s entry queued: authorization must use the live query: materialized=%v err=%v", kind, materialized, err)
		}
		// 只重算了那条窄的事件条目，没有展开大组（大组有 alertCaseReadSmallFanout+1 条事件）。
		if len(chunks) != 1 || chunks[0] != 1 {
			t.Fatalf("%s entry must not be expanded on the request path, recomputed chunks %v", kind, chunks)
		}
		var narrow, wide int
		if err := db.QueryRow(ctx, `SELECT COUNT(*) FILTER (WHERE kind='event'), COUNT(*) FILTER (WHERE kind=$2) FROM alert_case_dirty WHERE tenant_id=$1`, tenant, kind).Scan(&narrow, &wide); err != nil {
			t.Fatal(err)
		}
		if narrow != 0 || wide != 1 {
			t.Fatalf("narrow entries drain, the %s entry stays for the background: narrow=%d wide=%d", kind, narrow, wide)
		}
		if _, err := db.Exec(ctx, `DELETE FROM alert_case_dirty WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	if materialized, err := prepareAlertCaseReads(ctx, db, meta, tenant, true); err != nil || !materialized {
		t.Fatalf("with only narrow entries (none) authorization reads the store: %v %v", materialized, err)
	}
}
