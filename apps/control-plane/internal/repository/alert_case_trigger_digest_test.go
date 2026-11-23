package repository

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 按 1003 的回滚说明回滚后再升级，只会重跑 1003：同名触发器和 jjd_alert_case_dirty_access_rows 被降回 1003 的
// 旧定义（1006 改过），触发器都在、都启用，但有些变化不再登记，物化结果会悄悄过期。完整性检查要比对触发器
// 定义与触发器函数体的摘要：与迁移记下的不一致就走实时查询并作废物化结果；定义恢复后才重建。
func TestAlertCaseStoreFallsBackWhenTriggerDefinitionsAreDowngraded(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ALERT_CASES_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("ALERT_CASES_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	fx := seedAlertCaseStoreFixture(t, ctx, db)
	t.Cleanup(func() { fx.cleanup(); db.Close() })
	migration := func(name string) string {
		t.Helper()
		body, err := os.ReadFile("../../../../deploy/migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	apply := func(sql string) {
		t.Helper()
		if _, err := db.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
		resetAlertCaseStoreCheckCache()
	}
	// 测完把 1006 的定义恢复回来，不让共用的测试库停在旧定义上。
	restored := false
	t.Cleanup(func() {
		if !restored {
			_, _ = db.Exec(context.Background(), migration("1006_alert_retention_dirty_triggers.sql"))
			resetAlertCaseStoreCheckCache()
		}
	})
	repo := NewAlertOccurrenceRepository(db)
	repo.caseStoreDisabled = false
	f := AlertOccurrenceFilter{TenantID: fx.tenantA, Grouping: "cases", Limit: 10}
	if err := repo.PrepareAlertCases(ctx, fx.tenantA); err != nil {
		t.Fatal(err)
	}
	if !alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("store with the expected trigger definitions should serve reads")
	}

	apply(migration("1003_alert_case_dirty_triggers.sql"))
	if alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("reads must fall back to the live query while the dirty triggers carry 1003's older definitions")
	}
	var done bool
	if err := db.QueryRow(ctx, `SELECT done FROM alert_case_backfill WHERE tenant_id=$1`, fx.tenantA).Scan(&done); err != nil || done {
		t.Fatalf("downgraded triggers must reset the backfill: done=%v err=%v", done, err)
	}
	if err := repo.PrepareAlertCases(ctx, fx.tenantA); err == nil {
		t.Fatal("rebuilding on downgraded triggers must be refused")
	}

	apply(migration("1006_alert_retention_dirty_triggers.sql"))
	restored = true
	if err := repo.PrepareAlertCases(ctx, fx.tenantA); err != nil {
		t.Fatal(err)
	}
	if !alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("store rebuilt after the definitions came back should serve reads")
	}
}

// 迁移记下的摘要与控制面算的摘要是同一个表达式：刚迁移完的库上两者一致。
func TestAlertCaseTriggerDigestMatchesAfterMigration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ALERT_CASES_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("ALERT_CASES_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ok, err := alertCaseTriggersAsExpected(ctx, db)
	if err != nil || !ok {
		t.Fatalf("freshly migrated database must match the recorded trigger digest: ok=%v err=%v", ok, err)
	}
}

// 迁移 1008 记摘要用的表达式与控制面现算的是同一段 SQL。
func TestAlertCaseTriggerDigestMigrationUsesTheSameExpression(t *testing.T) {
	body, err := os.ReadFile("../../../../deploy/migrations/1008_alert_case_trigger_digest.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), alertCaseTriggerDigestSQL) {
		t.Fatalf("1008 must record the digest with alertCaseTriggerDigestSQL:\n%s", alertCaseTriggerDigestSQL)
	}
}
