package repository

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 回滚 1003 后再升级、或有人删了任一个登记触发器时，物化结果会悄悄过期：读接口必须改走实时查询，并把回填
// 重置为未完成；触发器补回后由后台重建，重建完才再用物化表。
func TestAlertCaseStoreFallsBackWhenADirtyTriggerIsMissing(t *testing.T) {
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
	f := AlertOccurrenceFilter{TenantID: fx.tenantA, Grouping: "cases", Limit: 10}
	if err := repo.PrepareAlertCases(ctx, fx.tenantA); err != nil {
		t.Fatal(err)
	}
	if !alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("complete store should serve reads")
	}
	var definition string
	if err := db.QueryRow(ctx, `SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgname='trg_alert_case_dirty_group_update'`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `DROP TRIGGER trg_alert_case_dirty_group_update ON alert_groups`); err != nil {
		t.Fatal(err)
	}
	resetAlertCaseStoreCheckCache()
	restored := false
	t.Cleanup(func() {
		if !restored {
			_, _ = db.Exec(context.Background(), definition)
			resetAlertCaseStoreCheckCache()
		}
	})
	if alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("reads must fall back to the live query while a dirty trigger is missing")
	}
	var done bool
	if err := db.QueryRow(ctx, `SELECT done FROM alert_case_backfill WHERE tenant_id=$1`, fx.tenantA).Scan(&done); err != nil || done {
		t.Fatalf("missing trigger must reset the backfill: done=%v err=%v", done, err)
	}
	// 触发器缺着的时候后台不能重建（重建完也会再次过期）。
	if _, err := repo.MaintainAlertCases(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := repo.PrepareAlertCases(ctx, fx.tenantA); err == nil {
		t.Fatal("rebuilding without the dirty triggers must be refused")
	}
	if _, err := db.Exec(ctx, definition); err != nil {
		t.Fatal(err)
	}
	restored = true
	resetAlertCaseStoreCheckCache()
	if err := repo.PrepareAlertCases(ctx, fx.tenantA); err != nil {
		t.Fatal(err)
	}
	if !alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("store rebuilt after the trigger came back should serve reads")
	}
}
