package repository

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 物化口径（命中行与案件聚合的 SQL、是否用生成列）一变，存下来的结果就不能再用：读接口先回到实时查询，
// 后台把所有租户的回填重置后重建，重建完才再用物化表。
func TestAlertCaseStoreRebuildsWhenLogicChanges(t *testing.T) {
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
	repo := NewAlertOccurrenceRepository(db)
	repo.caseStoreDisabled = false
	if err := repo.PrepareAlertCases(ctx, fx.tenantA); err != nil {
		t.Fatal(err)
	}
	f := AlertOccurrenceFilter{TenantID: fx.tenantA, Grouping: "cases", Limit: 10}
	if !alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("fresh store should serve reads")
	}
	if _, err := db.Exec(ctx, `UPDATE alert_case_store_version SET logic_version='stale'`); err != nil {
		t.Fatal(err)
	}
	if alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("reads must fall back to the live query while the stored logic is stale")
	}
	if _, err := repo.MaintainAlertCases(ctx, 0); err != nil {
		t.Fatal(err)
	}
	var done bool
	if err := db.QueryRow(ctx, `SELECT done FROM alert_case_backfill WHERE tenant_id=$1`, fx.tenantA).Scan(&done); err != nil || done {
		t.Fatalf("stale logic must reset the tenant backfill: done=%v err=%v", done, err)
	}
	if err := repo.PrepareAlertCases(ctx, fx.tenantA); err != nil {
		t.Fatal(err)
	}
	if !alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("rebuilt store should serve reads again")
	}

	// 读取元数据函数（生成列按它算）改了也算口径变化。
	var definition string
	if err := db.QueryRow(ctx, `SELECT pg_get_functiondef('jjd_alert_finding_metadata_v1'::regproc)`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(definition, "BEGIN", "BEGIN\n  -- logic fingerprint test", 1)
	if changed == definition {
		t.Fatal("cannot alter the metadata function body for the test")
	}
	if _, err := db.Exec(ctx, changed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(context.Background(), definition) })
	if alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("a changed metadata function must invalidate the stored results")
	}
	if _, err := db.Exec(ctx, definition); err != nil {
		t.Fatal(err)
	}
	if err := repo.PrepareAlertCases(ctx, fx.tenantA); err != nil {
		t.Fatal(err)
	}
	if !alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("store rebuilt after the function change should serve reads")
	}
}
