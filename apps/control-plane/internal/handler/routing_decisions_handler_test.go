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

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// setupRoutingDecisionsDB creates test DB pool + tenant + user fixture.
func setupRoutingDecisionsDB(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "trd_" + sfx
	userID := "urd_" + sfx
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		 VALUES ($1,$2,$3,$4,'x','platform_admin','active')`,
		userID, tenantID, userID, userID+"@test.com",
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM request_logs WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		pool.Close()
	})
	return pool, tenantID, userID
}

func buildRoutingDecisionsDeps(pool *pgxpool.Pool) *Dependencies {
	requestLogRepo := repository.NewRequestLogRepository(pool)
	return &Dependencies{
		RequestLogRepo: requestLogRepo,
	}
}

func withRoutingDecisionsUserCtx(r *http.Request, tenantID, userID string) *http.Request {
	u := &repository.User{
		ID:       userID,
		TenantID: tenantID,
		Role:     "platform_admin",
		Status:   "active",
	}
	return r.WithContext(context.WithValue(r.Context(), auth.UserKey, u))
}

// TestListRoutingDecisions_Empty verifies empty list returns correct structure.
func TestListRoutingDecisions_Empty(t *testing.T) {
	pool, tenantID, userID := setupRoutingDecisionsDB(t)
	deps := buildRoutingDecisionsDeps(pool)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions?limit=10", nil)
	req = withRoutingDecisionsUserCtx(req, tenantID, userID)
	rr := httptest.NewRecorder()
	ListRoutingDecisions(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp["data"] == nil {
		t.Error("expected data field")
	}
	if resp["total"] == nil {
		t.Error("expected total field")
	}

	data := resp["data"].([]interface{})
	if len(data) != 0 {
		t.Errorf("expected 0 items for empty tenant, got %d", len(data))
	}
	total := int(resp["total"].(float64))
	if total != 0 {
		t.Errorf("expected total=0, got %d", total)
	}
}

// TestListRoutingDecisions_WithData verifies listing with routing_decision_json.
func TestListRoutingDecisions_WithData(t *testing.T) {
	pool, tenantID, userID := setupRoutingDecisionsDB(t)
	deps := buildRoutingDecisionsDeps(pool)
	ctx := context.Background()

	// Insert a request_log with routing_decision_json (model_id/provider_id NULL to avoid FK)
	routingJSON := `{"selected_model": "gpt-4", "reason": "cost_optimized", "alternatives": ["gpt-3.5", "claude"]}`
	_, err := pool.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, request_status, upstream_status_code, created_at, routing_decision_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
	`, "rl_test_1", "req_test_1", tenantID, "completed", 200, time.Now(), routingJSON)
	if err != nil {
		t.Fatalf("insert request_log: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions?limit=10", nil)
	req = withRoutingDecisionsUserCtx(req, tenantID, userID)
	rr := httptest.NewRecorder()
	ListRoutingDecisions(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	data := resp["data"].([]interface{})
	if len(data) != 1 {
		t.Fatalf("expected 1 item, got %d", len(data))
	}

	item := data[0].(map[string]interface{})
	for _, forbidden := range []string{"id", "tenant_id", "provider_id", "model_id", "routing_decision_json"} {
		if _, exists := item[forbidden]; exists {
			t.Fatalf("unsafe internal field %q exposed: %#v", forbidden, item)
		}
	}

	total := int(resp["total"].(float64))
	if total != 1 {
		t.Errorf("expected total=1, got %d", total)
	}
}

func TestRoutingDecisionAPIProvidesFiltersAndSafeDetail(t *testing.T) {
	pool, tenantID, userID := setupRoutingDecisionsDB(t)
	deps := buildRoutingDecisionsDeps(pool)
	v2 := `{"model_route_v2":{"schema_version":2,"requested_model":"logical/model","policy_source":"model_override","policy_version":7,"strategy":"smart","planned_route":{"provider_name":"供应商甲","route_ref":"线路 1"},"actual_route":{"provider_name":"供应商乙","route_ref":"线路 2"},"candidates":[{"provider_name":"供应商甲","route_ref":"线路 1","normalized_scores":{"latency":0.8}}],"attempts":[{"route":{"provider_name":"供应商甲","route_ref":"线路 1"},"result":"failed","status_code_category":"5xx","latency_ms":20,"failure_category":"upstream_5xx"}],"fallback_used":true,"fallback_reason":"primary_route_failed"},"provider_layer":{"selected_provider":"internal-provider-id"}}`
	_, err := pool.Exec(context.Background(), `INSERT INTO request_logs (id,request_id,tenant_id,request_status,latency_ms,created_at,routing_decision_json) VALUES ('safe_detail','req_safe_detail',$1,'completed',432,NOW(),$2::jsonb)`, tenantID, v2)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions?model=logical%2Fmodel&provider=%E4%BE%9B%E5%BA%94%E5%95%86%E4%B9%99&result=completed&fallback=true", nil)
	req = withRoutingDecisionsUserCtx(req, tenantID, userID)
	rr := httptest.NewRecorder()
	ListRoutingDecisions(deps)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "internal-provider-id") || strings.Contains(rr.Body.String(), "tenant_id") {
		t.Fatalf("unsafe list DTO: %s", rr.Body.String())
	}
	var list RoutingDecisionListResponse
	if json.NewDecoder(rr.Body).Decode(&list) != nil || list.Total != 1 || len(list.Data) != 1 || !list.Data[0].FallbackUsed {
		t.Fatalf("bad filtered list: %#v", list)
	}
	if list.Data[0].LatencyMS == nil || *list.Data[0].LatencyMS != 432 {
		t.Fatalf("list latency missing: %#v", list.Data[0].LatencyMS)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions/req_safe_detail", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("request_id", "req_safe_detail")
	detailReq = detailReq.WithContext(context.WithValue(detailReq.Context(), chi.RouteCtxKey, rctx))
	detailReq = withRoutingDecisionsUserCtx(detailReq, tenantID, userID)
	detailRR := httptest.NewRecorder()
	GetRoutingDecision(deps)(detailRR, detailReq)
	if detailRR.Code != http.StatusOK || strings.Contains(detailRR.Body.String(), "internal-provider-id") {
		t.Fatalf("unsafe detail: %d %s", detailRR.Code, detailRR.Body.String())
	}
	var detail RoutingDecisionDetail
	if json.NewDecoder(detailRR.Body).Decode(&detail) != nil || len(detail.Candidates) != 1 || len(detail.Attempts) != 1 {
		t.Fatalf("detail explanation missing: %#v", detail)
	}
	if detail.LatencyMS == nil || *detail.LatencyMS != 432 {
		t.Fatalf("detail latency missing: %#v", detail.LatencyMS)
	}
}

func TestRoutingDecisionDetailIndependentlySanitizesHistoricalV2Values(t *testing.T) {
	pool, tenantID, userID := setupRoutingDecisionsDB(t)
	deps := buildRoutingDecisionsDeps(pool)
	malicious := `{"model_route_v2":{"schema_version":2,"requested_model":"gpt-5.4","policy_source":"Authorization: Bearer policy-token","strategy":"secret=strategy-token","planned_route":{"provider_name":"api_key=provider-token","route_ref":"https://upstream.example/v1?api_key=url-token#raw"},"actual_route":{"provider_name":"正常供应商","route_ref":"credential_id=cred-token"},"candidates":[{"provider_name":"Bearer candidate-token","route_ref":"线路 1","sample_state":"secret: sample-token","dimension_state":{"latency":"Authorization=dimension-token"},"exclusion_reason":"https://bad.example/p?q=query-token"}],"attempts":[{"route":{"provider_name":"api-key=attempt-token","route_ref":"线路 1"},"result":"secret=result-token","status_code_category":"5xx","failure_category":"Bearer failure-token"}],"fallback_used":true,"fallback_reason":"credential=fallback-token"}}`
	_, err := pool.Exec(context.Background(), `INSERT INTO request_logs (id,request_id,tenant_id,request_status,created_at,routing_decision_json) VALUES ('malicious_v2','req_malicious_v2',$1,'completed',NOW(),$2::jsonb)`, tenantID, malicious)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions/req_malicious_v2", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("request_id", "req_malicious_v2")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = withRoutingDecisionsUserCtx(req, tenantID, userID)
	rr := httptest.NewRecorder()
	GetRoutingDecision(deps)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	text := strings.ToLower(rr.Body.String())
	for _, forbidden := range []string{"policy-token", "strategy-token", "provider-token", "url-token", "cred-token", "candidate-token", "sample-token", "dimension-token", "query-token", "attempt-token", "result-token", "failure-token", "fallback-token", "?api_key=", "#raw", "?q="} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("historical v2 value leaked %q: %s", forbidden, rr.Body.String())
		}
	}
	if !strings.Contains(rr.Body.String(), "gpt-5.4") || !strings.Contains(rr.Body.String(), "正常供应商") {
		t.Fatalf("normal values over-redacted: %s", rr.Body.String())
	}
}

func TestRoutingDecisionDetailMarksUnparseablePayloadWithoutEcho(t *testing.T) {
	pool, tenantID, userID := setupRoutingDecisionsDB(t)
	deps := buildRoutingDecisionsDeps(pool)
	_, err := pool.Exec(context.Background(), `INSERT INTO request_logs(id,request_id,tenant_id,request_status,created_at,routing_decision_json) VALUES('bad_shape','req_bad_shape',$1,'completed',NOW(),'"Bearer raw-secret"'::jsonb)`, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions/req_bad_shape", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("request_id", "req_bad_shape")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = withRoutingDecisionsUserCtx(req, tenantID, userID)
	rr := httptest.NewRecorder()
	GetRoutingDecision(deps)(rr, req)
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "raw-secret") || !strings.Contains(rr.Body.String(), "unparseable") {
		t.Fatalf("unsafe parse failure response: %d %s", rr.Code, rr.Body.String())
	}
}

// TestListRoutingDecisions_Filter verifies that logs without routing_decision_json are excluded.
func TestListRoutingDecisions_Filter(t *testing.T) {
	pool, tenantID, userID := setupRoutingDecisionsDB(t)
	deps := buildRoutingDecisionsDeps(pool)
	ctx := context.Background()

	// Insert a request_log WITHOUT routing_decision_json (model_id/provider_id NULL)
	_, err := pool.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, request_status, upstream_status_code, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, "rl_no_routing", "req_no_routing", tenantID, "completed", 200, time.Now())
	if err != nil {
		t.Fatalf("insert request_log: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions?limit=10", nil)
	req = withRoutingDecisionsUserCtx(req, tenantID, userID)
	rr := httptest.NewRecorder()
	ListRoutingDecisions(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	data := resp["data"].([]interface{})
	if len(data) != 0 {
		t.Errorf("expected 0 items (log without routing_decision_json should be filtered), got %d", len(data))
	}
}

// TestListRoutingDecisions_Pagination verifies limit/offset work correctly.
func TestListRoutingDecisions_Pagination(t *testing.T) {
	pool, tenantID, userID := setupRoutingDecisionsDB(t)
	deps := buildRoutingDecisionsDeps(pool)
	ctx := context.Background()

	// Insert 3 request_logs with routing_decision_json
	for i := 1; i <= 3; i++ {
		_, err := pool.Exec(ctx, `
			INSERT INTO request_logs (id, request_id, tenant_id, request_status, upstream_status_code, created_at, routing_decision_json)
			VALUES ($1, $2, $3, $4, $5, NOW() - INTERVAL '1 second' * $6, '{"model": "test"}'::jsonb)
		`, fmt.Sprintf("rl_page_%d", i), fmt.Sprintf("req_page_%d", i), tenantID, "completed", 200, i)
		if err != nil {
			t.Fatalf("insert request_log %d: %v", i, err)
		}
	}

	// Test limit=2
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions?limit=2", nil)
	req = withRoutingDecisionsUserCtx(req, tenantID, userID)
	rr := httptest.NewRecorder()
	ListRoutingDecisions(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	data := resp["data"].([]interface{})
	if len(data) != 2 {
		t.Errorf("expected 2 items with limit=2, got %d", len(data))
	}
	total := int(resp["total"].(float64))
	if total != 3 {
		t.Errorf("expected total=3, got %d", total)
	}

	// Test offset=2 (should get 1 item)
	req2 := httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions?limit=10&offset=2", nil)
	req2 = withRoutingDecisionsUserCtx(req2, tenantID, userID)
	rr2 := httptest.NewRecorder()
	ListRoutingDecisions(deps)(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr2.Code, rr2.Body.String())
	}

	var resp2 map[string]interface{}
	if err := json.NewDecoder(rr2.Body).Decode(&resp2); err != nil {
		t.Fatalf("decode: %v", err)
	}

	data2 := resp2["data"].([]interface{})
	if len(data2) != 1 {
		t.Errorf("expected 1 item with offset=2, got %d", len(data2))
	}
}
