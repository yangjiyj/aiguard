package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProxyIngressBypassesMoneyButKeepsAuditForPricedKeys(t *testing.T) {
	var requests, quotaLookups int
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":{"code":"monthly_allowance_exhausted"}}`))
	}))
	defer cp.Close()
	client := NewBillingClientWithMode(cp.URL, "test-secret", "default", "metering")
	client.AllowanceRequired = func(context.Context, string, string) (bool, error) { quotaLookups++; return true, nil }
	for _, ingress := range []string{"forward_proxy", "reverse_proxy"} {
		e := &modelrouter.RequestEnvelope{BillingIngress: ingress, TenantID: "t", UserID: "u", ClientID: "filled-key", Model: "priced-model", RequestID: ingress}
		if err := client.ReserveUsage(context.Background(), e, BillingUsage{PromptTokens: 1}); err != nil {
			t.Fatalf("proxy monetary admission: %v", err)
		}
		client.reserved.Store(e.RequestID, billingTrackingState{Admitted: true, PriceID: "priced-model", AdmittedAt: time.Now()})
		audit := &MockAuditWriter{}
		NewBillingAuditWriter(audit, client).FinalizeRequestLog(context.Background(), e, []byte(`{"usage":{"prompt_tokens":2,"completion_tokens":3}}`), "success", 200, 1, nil)
		if len(audit.RequestLogFinalizes) != 1 || e.BillingOutcome != "" {
			t.Fatalf("audit=%d monetaryoutcome=%s", len(audit.RequestLogFinalizes), e.BillingOutcome)
		}
	}
	if requests != 0 || quotaLookups != 0 {
		t.Fatalf("proxy financial calls=%d quota lookups=%d", requests, quotaLookups)
	}
	direct := &modelrouter.RequestEnvelope{BillingIngress: "model_api", TenantID: "t", UserID: "u", ClientID: "filled-key", Model: "priced-model", RequestID: "direct"}
	if err := client.ReserveUsage(context.Background(), direct, BillingUsage{PromptTokens: 1}); err == nil {
		t.Fatal("direct exhausted model API must still refuse")
	}
	if requests != 1 {
		t.Fatalf("direct calls=%d", requests)
	}
}

func TestSecurityOnlyReverseProxyForwardsPricedModel(t *testing.T) {
	hits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"usage":{"prompt_tokens":2,"completion_tokens":3}}`))
	}))
	defer upstream.Close()
	h := &ReverseProxyHandler{tenantID: "tenant", client: upstream.Client(), resolveEgressTarget: testEgressResolver(upstream.URL), routes: []ReverseProxyRoute{{ID: "security-only", PathPrefix: "/proxy/owned", TargetURL: upstream.URL, TargetPathPrefix: "/v1", Status: "active"}}}
	req := httptest.NewRequest(http.MethodPost, "http://gateway/proxy/owned/chat/completions", strings.NewReader(`{"model":"priced-model"}`))
	req.Header.Set("Authorization", "Bearer client-owned-upstream-key")
	recorder := httptest.NewRecorder()
	if !h.ServeHTTP(recorder, req) || recorder.Code != 200 || hits != 1 {
		t.Fatalf("status=%d hits=%d", recorder.Code, hits)
	}
}

func TestNoTokenModelProxyHandlerDoesNotTouchPricedBilling(t *testing.T) {
	requests := 0
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":{"code":"monthly_allowance_exhausted"}}`))
	}))
	defer cp.Close()
	client := NewBillingClientWithMode(cp.URL, "test-secret", "default", "metering")
	client.AllowanceRequired = func(context.Context, string, string) (bool, error) {
		t.Fatal("proxy looked up money quotas")
		return true, nil
	}
	audit := &MockAuditWriter{}
	security := &MockSecurityChecker{}
	provider := &MockProviderCaller{}
	h := NewChatCompletionsHandler(&config.Config{ProxyDefaultTenantID: "tenant-123", ProxyDefaultProjectID: "project-123", ProxyDefaultUserID: "user-123"}, newProxyEnabledResolver(), &MockRateLimitChecker{}, security, NewBillingAuditWriter(audit, client), &MockProviderAdapterFactory{MockProviderCaller: provider}, nil, nil)
	h.SetBillingPreflight(client)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, proxyChatRequest(""))
	if w.Code != 200 || requests != 0 {
		t.Fatalf("status=%d moneycalls=%d body=%s", w.Code, requests, w.Body.String())
	}
	if len(provider.CallCalls) != 1 || len(security.InputCheckCalls) != 1 || len(security.OutputCheckCalls) != 1 || len(audit.RequestLogFinalizes) != 1 {
		t.Fatalf("upstream=%d security=%d/%d audit=%d", len(provider.CallCalls), len(security.InputCheckCalls), len(security.OutputCheckCalls), len(audit.RequestLogFinalizes))
	}
	e := audit.RequestLogFinalizes[0].Envelope
	if e.BillingIngress != "reverse_proxy" || e.ClientID == "" || e.UserID == "" || e.BillingOutcome != "" {
		t.Fatalf("proxy envelope=%+v", e)
	}
}

func TestTrustedProxyContextOverridesForgedKeyAndIngress(t *testing.T) {
	hits := 0
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(429) }))
	defer cp.Close()
	c := NewBillingClientWithMode(cp.URL, "test-secret", "default", "metering")
	ctx := context.WithValue(context.Background(), auth.ProxyRequestKey, true)
	e := &modelrouter.RequestEnvelope{BillingIngress: "model_api", TenantID: "tenant", UserID: "user", ClientID: "key", Model: "priced", RequestID: "forged"}
	if err := c.ReserveUsage(ctx, e, BillingUsage{PromptTokens: 10}); err != nil {
		t.Fatal(err)
	}
	if e.BillingIngress != "reverse_proxy" {
		t.Fatalf("ingress=%s", e.BillingIngress)
	}
	e.BillingIngress = "model_api"
	if outcome := c.Finalize(ctx, e, []byte(`{"usage":{"prompt_tokens":2,"completion_tokens":3}}`), "success"); outcome != "" {
		t.Fatalf("outcome=%s", outcome)
	}
	if hits != 0 {
		t.Fatalf("moneycalls=%d", hits)
	}
	var clientEnvelope modelrouter.RequestEnvelope
	if err := json.Unmarshal([]byte(`{"billing_ingress":"reverse_proxy","BillingIngress":"reverse_proxy"}`), &clientEnvelope); err != nil {
		t.Fatal(err)
	}
	if clientEnvelope.BillingIngress != "" || !directModelBilling(&clientEnvelope) {
		t.Fatal("client JSON forged trusted billing ingress")
	}
}

func TestDirectModelAPIHandlerRetainsPricedRefusal(t *testing.T) {
	hits := 0
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":{"code":"monthly_allowance_exhausted"}}`))
	}))
	defer cp.Close()
	c := NewBillingClientWithMode(cp.URL, "test-secret", "default", "metering")
	c.AllowanceRequired = func(context.Context, string, string) (bool, error) { return true, nil }
	audit := &MockAuditWriter{}
	provider := &MockProviderCaller{}
	h := NewChatCompletionsHandler(&config.Config{}, newProxyEnabledResolver(), &MockRateLimitChecker{}, &MockSecurityChecker{}, NewBillingAuditWriter(audit, c), &MockProviderAdapterFactory{MockProviderCaller: provider}, nil, nil)
	h.SetBillingPreflight(c)
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"safe"}],"billing_ingress":"reverse_proxy"}`))
	request = request.WithContext(setAuthInfo(request.Context(), "tenant-123", "project-123", "user-123", "key-123", ""))
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, request)
	if w.Code != 429 || hits == 0 || len(provider.CallCalls) != 0 {
		t.Fatalf("status=%d moneycalls=%d upstream=%d", w.Code, hits, len(provider.CallCalls))
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Envelope.BillingIngress != "model_api" {
		t.Fatal("direct billing/audit classification changed")
	}
}

func TestProxyBillingIngressPersistsThroughSyncAndAsyncAuditWithPostgres(t *testing.T) {
	for _, async := range []bool{false, true} {
		t.Run(map[bool]string{false: "sync", true: "async"}[async], func(t *testing.T) {
			db, ctx, tenant, project, provider, model := setupAuditWriterNullUserFixture(t)
			hits := 0
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(429) }))
			defer cp.Close()
			c := NewBillingClientWithMode(cp.URL, "test-secret", "default", "metering")
			var writer AuditWriter = &RealAuditWriter{db: &realDBExecutor{pool: db}}
			if async {
				writer = NewAsyncAuditWriter(writer, &fakeOutboxEnqueuer{})
			}
			writer = NewBillingAuditWriter(writer, c)
			e := &modelrouter.RequestEnvelope{BillingIngress: "model_api", RequestID: tenant + "-proxy", TenantID: tenant, ProjectID: project, ProviderID: provider, ModelID: model, EndpointType: "chat", Model: "priced", ClientID: "forged-key"}
			ctx = context.WithValue(ctx, auth.ProxyRequestKey, true)
			writer.EnsureRequestLog(ctx, e)
			writer.FinalizeRequestLog(ctx, e, []byte(`{"usage":{"prompt_tokens":2,"completion_tokens":3}}`), "success", 200, 1, nil)
			var ingress, status string
			if err := db.QueryRow(ctx, `SELECT output_audit_result->'response_metadata'->>'billing_ingress',request_status FROM request_logs WHERE tenant_id=$1 AND request_id=$2`, tenant, e.RequestID).Scan(&ingress, &status); err != nil {
				t.Fatal(err)
			}
			if ingress != "reverse_proxy" || status != "success" || hits != 0 {
				t.Fatalf("ingress=%s status=%s money=%d", ingress, status, hits)
			}
			var facts, wallets, ledger int64
			if err := db.QueryRow(ctx, `SELECT (SELECT COUNT(*) FROM billing_usage_facts WHERE tenant_id=$1),(SELECT COUNT(*) FROM billing_wallets WHERE tenant_id=$1),(SELECT COUNT(*) FROM billing_ledger_entries WHERE tenant_id=$1)`, tenant).Scan(&facts, &wallets, &ledger); err != nil {
				t.Fatal(err)
			}
			if facts != 0 || wallets != 0 || ledger != 0 {
				t.Fatalf("finance=%d/%d/%d", facts, wallets, ledger)
			}
		})
	}
}

func TestTrustedProxyContextSkipsMoneyForEmbeddingAndImageHandlers(t *testing.T) {
	for _, kind := range []string{"embeddings", "images"} {
		t.Run(kind, func(t *testing.T) {
			t.Setenv("UAG_ROUTING_DISABLED", "true")
			hits := 0
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(429) }))
			defer cp.Close()
			client := NewBillingClientWithMode(cp.URL, "test-secret", "default", "metering")
			audit := &MockAuditWriter{}
			security := &MockSecurityChecker{}
			provider := &MockProviderCaller{}
			factory := &MockProviderAdapterFactory{MockProviderCaller: provider}
			var handler http.HandlerFunc
			var request *http.Request
			if kind == "embeddings" {
				h := NewEmbeddingsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, security, NewBillingAuditWriter(audit, client), factory)
				h.SetBillingPreflight(client)
				handler = h.Handler()
				request = httptest.NewRequest(http.MethodPost, "/v1/embeddings", strings.NewReader(`{"model":"priced-embedding","input":"safe input"}`))
			} else {
				provider.CallResponse = []byte(testImageResponse)
				h := NewImagesHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, security, NewBillingAuditWriter(audit, client), factory, nil)
				h.SetBillingPreflight(client)
				handler = h.Handler()
				request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-2","prompt":"safe drawing","n":1}`))
			}
			ctx := setAuthInfo(request.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
			request = request.WithContext(context.WithValue(ctx, auth.ProxyRequestKey, true))
			w := httptest.NewRecorder()
			handler(w, request)
			if w.Code != 200 || hits != 0 || len(provider.CallCalls) != 1 || len(security.InputCheckCalls) != 1 || len(audit.RequestLogFinalizes) != 1 {
				t.Fatalf("status=%d money=%d provider=%d security=%d audit=%d body=%s", w.Code, hits, len(provider.CallCalls), len(security.InputCheckCalls), len(audit.RequestLogFinalizes), w.Body.String())
			}
			e := audit.RequestLogFinalizes[0].Envelope
			if e.BillingIngress != "reverse_proxy" || e.ClientID != "key-123" || e.UserID != "user-123" {
				t.Fatalf("envelope=%+v", e)
			}
		})
	}
}
