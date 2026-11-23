package repository

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 消化待重算队列失败（这里用测试触发器让某租户写命中行出错）时：读接口回退实时查询，照常返回结果；
// 后台维护跳过这个租户，别的租户照常回填、消化。
func TestAlertCaseDrainFailureFallsBackAndDoesNotStopOtherTenants(t *testing.T) {
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
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DROP TRIGGER IF EXISTS zz_alert_case_member_fail ON alert_case_members; DROP FUNCTION IF EXISTS zz_alert_case_member_fail()`)
		fx.cleanup()
		db.Close()
	})
	repo := NewAlertOccurrenceRepository(db)
	repo.caseStoreDisabled = false
	if err := repo.PrepareAlertCases(ctx, fx.tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `CREATE FUNCTION zz_alert_case_member_fail() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id = '`+fx.tenantA+`' THEN RAISE EXCEPTION 'injected member failure'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER zz_alert_case_member_fail BEFORE INSERT ON alert_case_members FOR EACH ROW EXECUTE FUNCTION zz_alert_case_member_fail();`); err != nil {
		t.Fatal(err)
	}
	// 租户 A 有一条新命中待重算，消化会失败；租户 B 也有待重算的变化。
	if _, err := db.Exec(ctx, `UPDATE security_events SET severity='critical' WHERE id=$1`, "e3_"+fx.suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE security_events SET severity='critical' WHERE id=$1`, "eb1_"+fx.suffix); err != nil {
		t.Fatal(err)
	}
	live := &AlertOccurrenceRepository{db: db, caseStoreDisabled: true}
	f := AlertOccurrenceFilter{TenantID: fx.tenantA, Grouping: "cases", IncludeSuppressed: true, Limit: 100}
	want, err := live.List(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.List(ctx, f)
	if err != nil {
		t.Fatalf("a failed drain must not fail the read: %v", err)
	}
	assertSameJSON(t, "read during drain failure", want, got)
	if alertCaseStoreUsed(t, ctx, repo, f) {
		t.Fatal("tenant A still has unprocessed changes; the read must use the live query")
	}
	if _, err := repo.MaintainAlertCases(ctx, 5*time.Second); err == nil {
		t.Fatal("maintenance should report the failing tenant")
	}
	var pendingB int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM alert_case_dirty WHERE tenant_id=$1`, fx.tenantB).Scan(&pendingB); err != nil || pendingB != 0 {
		t.Fatalf("maintenance must still drain tenant B: pending=%d err=%v", pendingB, err)
	}
}
