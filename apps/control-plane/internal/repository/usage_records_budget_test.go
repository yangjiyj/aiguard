package repository

import (
	"fmt"
	"testing"
	"time"
)

// 被预算断流拒绝的请求没有账单行，只在 request_logs.billing_outcome 里留下结果：
// 使用记录必须把它显示成独立的“预算用尽被拒”状态，并且可以按该状态筛选。
func TestListUsageRecordsShowsBudgetRefusalsAsOwnBillingState(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	seed := seedThreeUsageRecords(t, db, ctx, tenantID, userID, projectID)
	now := time.Now().UTC()
	insert := func(requestID, status, outcome string, code int) {
		t.Helper()
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, client_id, endpoint_type, request_status, upstream_status_code, billing_outcome, created_at)
			VALUES ($1, $1, $2, $3, $4, $5, 'chat', $6, $7, $8, $9)
		`, requestID, tenantID, projectID, userID, seed.keyID, status, code, outcome, now); err != nil {
			t.Fatalf("insert %s: %v", requestID, err)
		}
	}
	suffix := time.Now().UnixNano()
	exhausted := fmt.Sprintf("req_budget_exhausted_%d", suffix)
	unpriced := fmt.Sprintf("req_budget_unpriced_%d", suffix)
	unavailable := fmt.Sprintf("req_budget_unavailable_%d", suffix)
	insert(exhausted, "budget_exhausted", "budget_exhausted", 429)
	insert(unpriced, "model_price_missing", "budget_unpriced", 403)
	insert(unavailable, "billing_unavailable", "budget_unavailable", 503)

	start, end := usageRecordRange()
	scope := UsageScope{TenantID: tenantID, UserID: userID, ProjectIDs: []string{projectID}}
	repo := NewUsageDailyRepository(db)
	records, _, err := repo.ListUsageRecords(ctx, scope, UsageRecordFilter{StartDate: start, EndDate: end, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	byID := indexUsageRecordsByRequestID(records)
	for requestID, want := range map[string]string{exhausted: "budget_exhausted", unpriced: "budget_unpriced", unavailable: "budget_unavailable"} {
		if got := byID[requestID].BillingState; got != want {
			t.Fatalf("%s billing_state = %q, want %q", requestID, got, want)
		}
	}
	// 既有记录的计费状态不受影响。
	if got := byID[seed.costedReqID].BillingState; got != "not_billed" {
		t.Fatalf("existing rows must keep their state, got %q", got)
	}

	filtered, total, err := repo.ListUsageRecords(ctx, scope, UsageRecordFilter{StartDate: start, EndDate: end, Limit: 50, BillingState: "budget_exhausted"})
	if err != nil || total != 1 || len(filtered) != 1 || filtered[0].RequestID != exhausted {
		t.Fatalf("filter by budget_exhausted = total %d len %d err %v", total, len(filtered), err)
	}
}
