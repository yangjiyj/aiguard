package repository

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 用户自己的处置要立刻可见：事件误报、案件处置、告警组改状态在提交后同步消化这次登记的条目再返回。
// 处置之后后台马上占住租户锁（模拟后台正在消化别的积压），读路径拿不到锁就直接读已物化结果、不等：
// 这时各种读法（案件列表、各车道、处置状态、开发作用域、截止时间、命中明细、汇总、按用户/会话）都与实时一致，
// 而且每次读都不会被后台的锁卡住。
func TestAlertCaseDispositionsAreVisibleImmediately(t *testing.T) {
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
	live := &AlertOccurrenceRepository{db: db, caseStoreDisabled: true}
	stored := NewAlertOccurrenceRepository(db)
	stored.caseStoreDisabled = false
	for _, tenant := range []string{fx.tenantA, fx.tenantB} {
		if err := stored.PrepareAlertCases(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	id := func(name string) string { return name + "_" + fx.suffix }
	dispositions := NewAuditDispositionRepository(db)
	groups := NewAlertGroupRepository(db)

	// 事件级误报（连带告警组静默）、案件处置、告警组改状态。
	if _, err := dispositions.UpsertAuthorized(ctx, &AuditDisposition{TenantID: fx.tenantA, SubjectType: "security_event",
		SubjectID: id("e11"), Status: "false_positive", OperatorID: "u", OperatorName: "甲"}, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	page, err := live.List(ctx, AlertOccurrenceFilter{TenantID: fx.tenantA, Grouping: "cases", IncludeSuppressed: true, IncludeDevTraffic: true, Limit: 100})
	if err != nil || len(page.Items) < 3 {
		t.Fatalf("list cases: %v", err)
	}
	seen := time.Now()
	if _, err := dispositions.UpsertAuthorized(ctx, &AuditDisposition{TenantID: fx.tenantA, SubjectType: "alert_case",
		SubjectID: page.Items[2].CaseID, Status: "resolved", OperatorID: "u", OperatorName: "甲", CaseSeenThrough: &seen}, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := groups.UpdateStatus(ctx, fx.tenantA, id("g_open"), AlertGroupStatusFalsePositive, "u", "复核为误报"); err != nil {
		t.Fatal(err)
	}

	// 后台占着租户锁：读前消化拿不到锁，不等。
	conn, err := db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	busy, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Rollback(context.Background())
	for _, tenant := range []string{fx.tenantA, fx.tenantB} {
		if _, err := busy.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('jjd_alert_cases:'||$1,0))`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	// 读前消化拿不到锁时报 errAlertCaseTenantBusy（不等锁），读照常返回已物化结果。
	if _, err := drainAlertCases(ctx, db, stored.mustReadMetadata(t, ctx), fx.tenantA, alertCaseReadDrainChunk, alertCaseDrainBeforeRead); !errors.Is(err, errAlertCaseTenantBusy) {
		t.Fatalf("read-side drain must not wait for the background lock, got %v", err)
	}
	// 各读法逐条比对（读路径若等锁会一直卡住，这里给足上限只为防挂死，不量墙钟）。
	compareCtx, cancelCompare := context.WithTimeout(ctx, 5*time.Minute)
	defer cancelCompare()
	compareAlertCaseStore(t, compareCtx, live, stored, fx, "right after dispositions while the background holds the lock")
}

func (r *AlertOccurrenceRepository) mustReadMetadata(t *testing.T, ctx context.Context) bool {
	t.Helper()
	meta, err := r.useReadMetadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return meta
}
