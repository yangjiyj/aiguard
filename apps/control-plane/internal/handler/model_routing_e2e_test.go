package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const crossServiceTenantA = "mr_e2e_tenant_a"
const crossServiceTenantB = "mr_e2e_tenant_b"

func crossServicePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("MODEL_ROUTING_E2E_DATABASE_URL")
	if dsn == "" {
		t.Skip("MODEL_ROUTING_E2E_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func crossServiceRequest(method, target string, body []byte, tenantID string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	user := &repository.User{ID: "mr_e2e_user_a", TenantID: tenantID, Role: "tenant_owner", Status: "active"}
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
}

func TestModelRoutingCrossServiceControlWritePhase(t *testing.T) {
	if os.Getenv("MODEL_ROUTING_E2E_PHASE") != "control-write" {
		t.Skip("not control-write phase")
	}
	pool := crossServicePool(t)
	deps := &Dependencies{ModelRoutingRepo: repository.NewModelRoutingRepository(pool), ProviderRepo: repository.NewProviderRepository(pool), ModelRepo: repository.NewModelRepository(pool)}
	routesRR := httptest.NewRecorder()
	ListModelRoutingRoutes(deps)(routesRR, crossServiceRequest(http.MethodGet, "/admin/v1/model-routing/routes", nil, crossServiceTenantA))
	if routesRR.Code != http.StatusOK {
		t.Fatalf("routes: %d %s", routesRR.Code, routesRR.Body.String())
	}
	var routePayload struct {
		Routes []struct {
			RouteRef    string `json:"route_ref"`
			DisplayName string `json:"display_name"`
		} `json:"routes"`
	}
	if err := json.NewDecoder(routesRR.Body).Decode(&routePayload); err != nil || len(routePayload.Routes) != 2 {
		t.Fatalf("route payload=%+v err=%v", routePayload, err)
	}
	refs := map[string]string{}
	for _, route := range routePayload.Routes {
		refs[route.DisplayName] = route.RouteRef
	}
	body, _ := json.Marshal(map[string]any{"expected_version": 0, "config": map[string]any{"strategy": "priority", "cost_basis": "none", "providers": []map[string]any{{"route_ref": refs["主线路"], "enabled": true, "priority": 1}, {"route_ref": refs["备用线路"], "enabled": true, "priority": 2}}}})
	writeRR := httptest.NewRecorder()
	PutModelRoutingDefault(deps)(writeRR, crossServiceRequest(http.MethodPut, "/admin/v1/model-routing/default", body, crossServiceTenantA))
	if writeRR.Code != http.StatusOK {
		t.Fatalf("write: %d %s", writeRR.Code, writeRR.Body.String())
	}
	for _, forbidden := range []string{"mr_e2e_provider_a", "mr_e2e_provider_b", "provider_id", "fixed_provider_id"} {
		if strings.Contains(writeRR.Body.String(), forbidden) {
			t.Fatalf("write response leaked %q: %s", forbidden, writeRR.Body.String())
		}
	}
}

func TestModelRoutingCrossServiceControlReadPhase(t *testing.T) {
	if os.Getenv("MODEL_ROUTING_E2E_PHASE") != "control-read" {
		t.Skip("not control-read phase")
	}
	pool := crossServicePool(t)
	deps := buildRoutingDecisionsDeps(pool)
	var requestID string
	if err := pool.QueryRow(context.Background(), `SELECT request_id FROM request_logs WHERE tenant_id=$1 AND routing_decision_json IS NOT NULL ORDER BY created_at DESC LIMIT 1`, crossServiceTenantA).Scan(&requestID); err != nil {
		t.Fatal(err)
	}
	listRR := httptest.NewRecorder()
	ListRoutingDecisions(deps)(listRR, withRoutingDecisionsUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions", nil), crossServiceTenantA, "mr_e2e_user_a"))
	if listRR.Code != 200 || !strings.Contains(listRR.Body.String(), requestID) || !strings.Contains(listRR.Body.String(), `"fallback_used":true`) {
		t.Fatalf("tenant A list: %d %s", listRR.Code, listRR.Body.String())
	}
	otherRR := httptest.NewRecorder()
	ListRoutingDecisions(deps)(otherRR, withRoutingDecisionsUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions", nil), crossServiceTenantB, "mr_e2e_user_b"))
	if otherRR.Code != 200 || strings.Contains(otherRR.Body.String(), requestID) {
		t.Fatalf("tenant B list: %d %s", otherRR.Code, otherRR.Body.String())
	}
	detailReq := httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions/"+requestID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("request_id", requestID)
	detailReq = detailReq.WithContext(context.WithValue(detailReq.Context(), chi.RouteCtxKey, rctx))
	detailReq = withRoutingDecisionsUserCtx(detailReq, crossServiceTenantB, "mr_e2e_user_b")
	detailRR := httptest.NewRecorder()
	GetRoutingDecision(deps)(detailRR, detailReq)
	if detailRR.Code != http.StatusNotFound {
		t.Fatalf("cross tenant detail=%d %s", detailRR.Code, detailRR.Body.String())
	}
}

func TestModelRoutingV2DecisionAppearsInControlPlane(t *testing.T) {
	pool, tenantA, userA := setupRoutingDecisionsDB(t)
	_, tenantB, userB := setupRoutingDecisionsDB(t)
	decision := `{"model_route_v2":{"schema_version":2,"requested_model":"logical/model","policy_source":"tenant_default","policy_version":3,"strategy":"priority","planned_route":{"provider_name":"供应商甲","route_ref":"线路 1"},"actual_route":{"provider_name":"供应商乙","route_ref":"线路 2"},"attempts":[{"route":{"provider_name":"供应商甲","route_ref":"线路 1"},"result":"failed","status_code_category":"429","latency_ms":12,"failure_category":"rate_limited"},{"route":{"provider_name":"供应商乙","route_ref":"线路 2"},"result":"success","status_code_category":"2xx","latency_ms":20}],"fallback_used":true,"fallback_reason":"primary_route_failed"}}`
	if _, err := pool.Exec(context.Background(), `INSERT INTO request_logs(id,request_id,tenant_id,request_status,created_at,routing_decision_json) VALUES('e2e_route_log','req_route_e2e',$1,'completed',NOW(),$2::jsonb)`, tenantA, decision); err != nil {
		t.Fatal(err)
	}
	deps := buildRoutingDecisionsDeps(pool)

	listReq := withRoutingDecisionsUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions?model=logical%2Fmodel", nil), tenantA, userA)
	listRR := httptest.NewRecorder()
	ListRoutingDecisions(deps)(listRR, listReq)
	var list RoutingDecisionListResponse
	if listRR.Code != http.StatusOK || json.NewDecoder(listRR.Body).Decode(&list) != nil || list.Total != 1 || len(list.Data) != 1 || !list.Data[0].FallbackUsed {
		t.Fatalf("gateway decision not visible: status=%d response=%#v body=%s", listRR.Code, list, listRR.Body.String())
	}
	for _, forbidden := range []string{"tenant_id", "provider_id", "routing_decision_json"} {
		if strings.Contains(listRR.Body.String(), forbidden) {
			t.Fatalf("internal field %q leaked: %s", forbidden, listRR.Body.String())
		}
	}

	otherListReq := withRoutingDecisionsUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions?model=logical%2Fmodel", nil), tenantB, userB)
	otherListRR := httptest.NewRecorder()
	ListRoutingDecisions(deps)(otherListRR, otherListReq)
	var otherList RoutingDecisionListResponse
	if otherListRR.Code != http.StatusOK || json.NewDecoder(otherListRR.Body).Decode(&otherList) != nil || otherList.Total != 0 || len(otherList.Data) != 0 {
		t.Fatalf("cross-tenant decision visible: status=%d response=%#v body=%s", otherListRR.Code, otherList, otherListRR.Body.String())
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions/req_route_e2e", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("request_id", "req_route_e2e")
	detailReq = detailReq.WithContext(context.WithValue(detailReq.Context(), chi.RouteCtxKey, rctx))
	detailReq = withRoutingDecisionsUserCtx(detailReq, tenantB, userB)
	detailRR := httptest.NewRecorder()
	GetRoutingDecision(deps)(detailRR, detailReq)
	if detailRR.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant detail must be hidden: status=%d body=%s", detailRR.Code, detailRR.Body.String())
	}
}
