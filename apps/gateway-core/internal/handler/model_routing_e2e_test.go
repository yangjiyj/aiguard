package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestModelRoutingCrossServiceGatewayPhase(t *testing.T) {
	if os.Getenv("MODEL_ROUTING_E2E_PHASE") != "gateway" {
		t.Skip("not gateway phase")
	}
	dsn := os.Getenv("MODEL_ROUTING_E2E_DATABASE_URL")
	if dsn == "" {
		t.Fatal("MODEL_ROUTING_E2E_DATABASE_URL is required")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var primaryCalls, fallbackCalls int
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls++
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"limited"}}`))
	}))
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalls++
		if r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != "fallback-secret" {
			t.Errorf("fallback endpoint/auth path=%s key=%s", r.URL.Path, r.Header.Get("x-api-key"))
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["model"] != "fallback-upstream" {
			t.Errorf("fallback model=%v", body["model"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg-e2e","type":"message","role":"assistant","model":"fallback-upstream","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer fallback.Close()
	if _, err := pool.Exec(context.Background(), `UPDATE providers SET base_url=CASE id WHEN 'mr_e2e_provider_a' THEN $1 WHEN 'mr_e2e_provider_b' THEN $2 END WHERE id IN ('mr_e2e_provider_a','mr_e2e_provider_b')`, primary.URL+"/v1", fallback.URL+"/v1"); err != nil {
		t.Fatal(err)
	}
	router := modelrouter.NewModelRouter(pool)
	cache := modelrouter.NewPolicyCache(pool, time.Minute)
	engine := modelrouter.NewModelRouteEngine(router, cache)
	audit := NewRealAuditWriter(pool, nil)
	h := NewChatCompletionsHandler(&config.Config{}, router, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, &RealProviderAdapterFactory{}, nil, nil)
	h.SetRouting(nil, nil, cache, engine)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"logical/model","messages":[{"role":"user","content":"hello"}]}`))
	req = req.WithContext(setAuthInfo(req.Context(), "mr_e2e_tenant_a", "mr_e2e_project_a", "", "mr_e2e_key", ""))
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || primaryCalls != 1 || fallbackCalls != 1 {
		t.Fatalf("fallback closure status=%d primary=%d fallback=%d body=%s", rr.Code, primaryCalls, fallbackCalls, rr.Body.String())
	}
	var stored int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM request_logs WHERE tenant_id='mr_e2e_tenant_a' AND routing_decision_json IS NOT NULL AND routing_decision_json->'model_route_v2'->>'fallback_used'='true'`).Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("persisted decisions=%d err=%v", stored, err)
	}

	writer := &acceptanceAlertWriter{}
	sink := modelrouter.NewAlertSink(writer, time.Minute)
	alertEngine := modelrouter.NewModelRouteEngineWithAlertSink(router, cache, sink)
	plan, applied, planErr := alertEngine.Plan(context.Background(), modelrouter.RequestEnvelope{TenantID: "mr_e2e_tenant_a", Model: "unknown/model", RequestID: "zero-candidate"})
	if planErr == nil || !applied || plan.Decision == nil || plan.Decision.ModelRouteV2.FallbackReason != "no_enabled_route" {
		t.Fatalf("zero candidate plan=%+v applied=%v err=%v", plan, applied, planErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sink.Close(ctx); err != nil {
		t.Fatal(err)
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	// 目录里没有的模型名是客户端写错名字，不是线路故障：不再产生「模型无可用线路」告警。
	if len(writer.alerts) != 0 {
		t.Fatalf("engine alerts=%+v", writer.alerts)
	}
}

func serveV2Chat(t *testing.T, tenant string, engine modelrouter.Engine, factory ProviderAdapterFactory) *httptest.ResponseRecorder {
	t.Helper()
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, factory, nil, nil)
	h.SetRouting(nil, nil, nil, engine)
	body := []byte(`{"model":"logical/model","messages":[{"role":"user","content":"hello"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req = req.WithContext(setAuthInfo(req.Context(), tenant, "project-a", "user-a", "key-a", ""))
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	return rr
}

func TestModelRoutingV2GlobalDefaultSameModel(t *testing.T) {
	r := route("p1", "openai", "https://one.invalid", "vendor-one")
	d := &modelrouter.RoutingDecision{ModelRouteV2: &modelrouter.ModelRouteDecisionV2{SchemaVersion: 2, RequestedModel: "logical/model", PolicySource: "tenant_default"}}
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: r, Decision: d}}
	caller := &MockProviderCaller{}
	rr := serveV2Chat(t, "tenant-a", engine, &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": caller}})
	if rr.Code != http.StatusOK || engine.planCalls != 1 || len(caller.CallEnvelopes) != 1 {
		t.Fatalf("default route not executed: status=%d plans=%d calls=%d body=%s", rr.Code, engine.planCalls, len(caller.CallEnvelopes), rr.Body.String())
	}
	if got := caller.CallEnvelopes[0]; got.Model != "logical/model" || got.UpstreamModelID != "vendor-one" {
		t.Fatalf("default route changed logical model or lost mapping: %+v", got)
	}
}

func TestModelRoutingV2ModelExceptionOverridesDefault(t *testing.T) {
	r := route("p2", "anthropic", "https://two.invalid", "vendor-two")
	d := &modelrouter.RoutingDecision{ModelRouteV2: &modelrouter.ModelRouteDecisionV2{SchemaVersion: 2, RequestedModel: "logical/model", PolicySource: "model_override"}}
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: r, Decision: d}}
	caller := &MockProviderCaller{}
	rr := serveV2Chat(t, "tenant-a", engine, &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p2": caller}})
	if rr.Code != http.StatusOK || rr.Header().Get("X-JJDGuard-Provider-ID") != "p2" || len(caller.CallEnvelopes) != 1 {
		t.Fatalf("model override not selected: status=%d provider=%q body=%s", rr.Code, rr.Header().Get("X-JJDGuard-Provider-ID"), rr.Body.String())
	}
	if d.ModelRouteV2.PolicySource != "model_override" || caller.CallEnvelopes[0].Model != "logical/model" {
		t.Fatalf("override explanation/model mismatch: decision=%+v envelope=%+v", d.ModelRouteV2, caller.CallEnvelopes[0])
	}
}

func TestModelRoutingV2FallbackUsesSecondProvidersOwnEndpoint(t *testing.T) {
	var primaryCalls, fallbackCalls int
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls++
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer primary-secret" {
			t.Errorf("primary endpoint or auth mismatch")
		}
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"limited"}}`))
	}))
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalls++
		if r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != "fallback-secret" || r.Header.Get("anthropic-version") == "" {
			t.Errorf("fallback endpoint, protocol, or auth mismatch")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["model"] != "claude-upstream" {
			t.Errorf("fallback upstream model mismatch body=%v err=%v", body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg-2","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer fallback.Close()

	routes := []modelrouter.ModelRecord{
		route("p1", "openai", primary.URL+"/v1", "openai-upstream"),
		route("p2", "anthropic", fallback.URL+"/v1", "claude-upstream"),
	}
	engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: routes[0], Fallbacks: routes[1:]}}
	env := &modelrouter.RequestEnvelope{RequestID: "e2e-fallback", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}
	result, err := executeModelRoutePlan(context.Background(), modelRouteExecutionInput{
		Engine: engine, CredentialResolver: executionCredentialResolver{"p1": "primary-secret", "p2": "fallback-secret"},
		Factory: &RealProviderAdapterFactory{}, Envelope: env,
		SecuredBody: []byte(`{"model":"logical/model","messages":[{"role":"user","content":"hello"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if primaryCalls != 1 || fallbackCalls != 1 || result.Envelope.ProviderID != "p2" || result.Envelope.Model != "logical/model" || result.Envelope.UpstreamModelID != "claude-upstream" {
		t.Fatalf("fallback did not use second route truth: primary=%d fallback=%d envelope=%+v", primaryCalls, fallbackCalls, result.Envelope)
	}
}

type acceptanceAlertWriter struct {
	mu     sync.Mutex
	alerts []modelrouter.RouteAlert
}

func (w *acceptanceAlertWriter) WriteRouteAlert(_ context.Context, alert modelrouter.RouteAlert, _ time.Duration) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.alerts = append(w.alerts, alert)
	return true, nil
}

func TestModelRoutingV2NoCandidateReturnsUnavailableAndAlert(t *testing.T) {
	engine := &executionTestEngine{hasPolicy: true, applied: true, planErr: errors.New("no eligible route")}
	rr := serveV2Chat(t, "tenant-a", engine, &MockProviderAdapterFactory{})
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "model_route_unavailable") || strings.Contains(rr.Body.String(), "no eligible route") {
		t.Fatalf("unsafe unavailable response: status=%d body=%s", rr.Code, rr.Body.String())
	}
	writer := &acceptanceAlertWriter{}
	sink := modelrouter.NewAlertSink(writer, 5*time.Minute)
	sink.Emit(context.Background(), modelrouter.RouteAlert{TenantID: "tenant-a", ModelName: "logical/model", ProviderRef: "all-routes", Type: modelrouter.AlertRouteUnavailable})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sink.Close(ctx); err != nil {
		t.Fatal(err)
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if len(writer.alerts) != 1 || writer.alerts[0].Type != modelrouter.AlertRouteUnavailable {
		t.Fatalf("unavailable alert not persisted: %+v", writer.alerts)
	}
}

type tenantCaptureEngine struct {
	*executionTestEngine
	wantTenant string
}

func (e *tenantCaptureEngine) Plan(_ context.Context, env modelrouter.RequestEnvelope) (modelrouter.RoutePlan, bool, error) {
	if env.TenantID != e.wantTenant {
		return modelrouter.RoutePlan{}, true, fmt.Errorf("cross-tenant plan: %s", env.TenantID)
	}
	e.planCalls++
	return e.plan, e.applied, e.planErr
}

func TestModelRoutingV2TenantIsolation(t *testing.T) {
	r := route("p1", "openai", "https://one.invalid", "vendor-one")
	base := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: r}}
	engine := &tenantCaptureEngine{executionTestEngine: base, wantTenant: "tenant-a"}
	rr := serveV2Chat(t, "tenant-a", engine, &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": &MockProviderCaller{}}})
	if rr.Code != http.StatusOK || base.planCalls != 1 {
		t.Fatalf("tenant-scoped route failed: status=%d plans=%d body=%s", rr.Code, base.planCalls, rr.Body.String())
	}
}

func TestModelRoutingV2KillSwitchRestoresLegacyPath(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	engine := &executionTestEngine{hasPolicy: true, applied: true}
	legacyCalls := 0
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{}}, nil, nil)
	h.modelRouteEngine = engine
	h.legacyModelResolver = func(_ context.Context, env *modelrouter.RequestEnvelope) *modelrouter.ModelDecision {
		legacyCalls++
		return &modelrouter.ModelDecision{TargetModel: env.Model, Strategy: "legacy"}
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(`{"model":"logical/model","messages":[{"role":"user","content":"hello"}]}`)))
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || legacyCalls != 1 || len(engine.hasRefs) != 0 || engine.planCalls != 0 {
		t.Fatalf("kill switch did not restore legacy: status=%d legacy=%d lookups=%v plans=%d body=%s", rr.Code, legacyCalls, engine.hasRefs, engine.planCalls, rr.Body.String())
	}
}
