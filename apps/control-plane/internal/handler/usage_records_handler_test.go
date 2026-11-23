package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func setupUsageRecordsHandlerDB(t *testing.T) (*pgxpool.Pool, context.Context, string, string, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}

	suffix := fmt.Sprint(time.Now().UnixNano())
	tenantID := "tenant_usage_records_handler_" + suffix
	userID := "user_usage_records_handler_" + suffix
	projectID := "project_usage_records_handler_" + suffix
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`, tenantID, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $3, 'tenant_owner', 'active')`, userID, tenantID, userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, owner_user_id, status) VALUES ($1, $2, $3, $4, 'active')`, projectID, tenantID, projectID, userID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, "DELETE FROM tool_call_logs WHERE tenant_id = $1", tenantID)
		_, _ = db.Exec(ctx, "DELETE FROM request_logs WHERE tenant_id = $1", tenantID)
		_, _ = db.Exec(ctx, "DELETE FROM internal_keys WHERE tenant_id = $1", tenantID)
		_, _ = db.Exec(ctx, "DELETE FROM projects WHERE tenant_id = $1", tenantID)
		_, _ = db.Exec(ctx, "DELETE FROM users WHERE tenant_id = $1", tenantID)
		_, _ = db.Exec(ctx, "DELETE FROM tenants WHERE id = $1", tenantID)
		db.Close()
	})
	return db, ctx, tenantID, userID, projectID
}

func withTenantOwner(req *http.Request, tenantID, userID string) *http.Request {
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       userID,
		TenantID: tenantID,
		Role:     "tenant_owner",
		Status:   "active",
	})
	ctx = context.WithValue(ctx, auth.SessionKey, &repository.Session{
		ID:       "session_" + userID,
		UserID:   userID,
		Username: userID,
		Role:     "tenant_owner",
		TenantID: tenantID,
	})
	return req.WithContext(ctx)
}

func TestGetUsageRecordsReturnsBillingStateWithoutLegacyCost(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupUsageRecordsHandlerDB(t)
	now := time.Now().UTC()
	keyID := "key_usage_records_handler_" + fmt.Sprint(now.UnixNano())
	if _, err := db.Exec(ctx, `
		INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, name, status)
		VALUES ($1, $2, $3, $4, $5, 'sk-handler', '客服排障 Key', 'active')
	`, keyID, tenantID, projectID, userID, keyID+"_hash"); err != nil {
		t.Fatalf("insert key: %v", err)
	}
	requestID := "req_usage_records_handler_" + fmt.Sprint(now.UnixNano())
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, project_id, user_id, client_id,
			endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at
		) VALUES ($1, $1, $2, $3, $4, $5, 'chat', 'success', 10, 3, 999, $6)
	`, requestID, tenantID, projectID, userID, keyID, now); err != nil {
		t.Fatalf("insert request log: %v", err)
	}

	url := fmt.Sprintf("/admin/v1/usage/records?start=%s&end=%s&billing_state=not_billed&limit=5", now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
	req := withTenantOwner(httptest.NewRequest(http.MethodGet, url, nil), tenantID, userID)
	rr := httptest.NewRecorder()

	GetUsageRecords(&Dependencies{UsageDailyRepo: repository.NewUsageDailyRepository(db)}).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "total_cost") || strings.Contains(rr.Body.String(), "cost_meta_json") {
		t.Fatalf("legacy cost fields leaked in response: %s", rr.Body.String())
	}
	var resp struct {
		Records []repository.UsageRecord `json:"records"`
		Total   int                      `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Records) != 1 {
		t.Fatalf("expected one record, got total=%d len=%d body=%s", resp.Total, len(resp.Records), rr.Body.String())
	}
	if resp.Records[0].BillingState != "not_billed" || resp.Records[0].BillingAmountMicros != nil {
		t.Fatalf("billing fields = %+v", resp.Records[0])
	}
	if resp.Records[0].KeyName != "客服排障 Key" || resp.Records[0].KeyPrefix != "sk-handler" {
		t.Fatalf("key fields = %+v", resp.Records[0])
	}
}

func TestGetAgentRiskOverviewUsesSessionTenant(t *testing.T) {
	db, ctx, tenantID, userID, _ := setupUsageRecordsHandlerDB(t)
	now := time.Now().UTC()
	otherTenantID := tenantID + "_other"
	if _, err := db.Exec(ctx, `
		INSERT INTO tool_call_logs (id, request_id, session_id, tenant_id, user_id, tool_name, tool_type, risk_level, parameters, result, status, mode, matched_policy_id, matched_policy_name, created_at)
		VALUES
			($1, 'req_risk_handler_1', 'sess-risk-handler', $2, $3, 'bash.exec', 'system', 'high', '{}'::jsonb, '', 'success', 'block', 'pol_block', '阻断策略', $4),
			($5, 'req_risk_handler_2', 'sess-risk-handler-other', $6, $3, 'bash.exec', 'system', 'high', '{}'::jsonb, '', 'success', 'block', 'pol_block', '阻断策略', $4)
	`, "tc_risk_handler_"+fmt.Sprint(now.UnixNano()), tenantID, userID, now, "tc_risk_handler_other_"+fmt.Sprint(now.UnixNano()), otherTenantID); err != nil {
		t.Fatalf("insert tool logs: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, "DELETE FROM tool_call_logs WHERE tenant_id = $1", otherTenantID)
	})

	url := fmt.Sprintf("/admin/v1/agentguard/risk-overview?start=%s&end=%s&tenant_id=%s", now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339), otherTenantID)
	req := withTenantOwner(httptest.NewRequest(http.MethodGet, url, nil), tenantID, userID)
	rr := httptest.NewRecorder()

	GetAgentRiskOverview(&Dependencies{ToolCallLogRepo: repository.NewToolCallLogRepository(db)}).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp repository.AgentRiskOverview
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.TotalToolCalls != 1 || resp.BlockedCalls != 1 {
		t.Fatalf("expected only current tenant counts, got %+v", resp)
	}
}

func TestParseUsageTroubleshootingFilters(t *testing.T) {
	request := httptest.NewRequest("GET", "/?source_ip=192.0.2.8&failure_category=timeout&http_status=504&error_keyword=capacity", nil)
	filter, err := parseUsageRecordFilter(request, true)
	if err != nil || filter.SourceIP != "192.0.2.8" || filter.FailureCategory != "timeout" || filter.HTTPStatus != 504 || filter.ErrorKeyword != "capacity" {
		t.Fatalf("filter=%+v err=%v", filter, err)
	}
	for _, v := range []string{"99", "600", "abc", "504%20OR%201=1"} {
		_, err := parseUsageRecordFilter(httptest.NewRequest("GET", "/?http_status="+v, nil), true)
		if err == nil {
			t.Fatalf("accepted invalid status: %s", v)
		}
	}
}
