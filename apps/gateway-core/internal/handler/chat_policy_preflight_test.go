package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type recordingBillingPreflight struct {
	reserveCalls         int
	reserveEnvelope      *modelrouter.RequestEnvelope
	reserveRequest       *ChatCompletionRequest
	reserveErr           error
	reserveUsageCalls    int
	reserveUsageEnvelope *modelrouter.RequestEnvelope
	reserveUsage         BillingUsage
	reserveUsageErr      error
}

func (f *recordingBillingPreflight) Reserve(_ context.Context, envelope *modelrouter.RequestEnvelope, request *ChatCompletionRequest) error {
	f.reserveCalls++
	f.reserveEnvelope = envelope
	f.reserveRequest = request
	return f.reserveErr
}

func (f *recordingBillingPreflight) ReserveUsage(_ context.Context, envelope *modelrouter.RequestEnvelope, usage BillingUsage) error {
	f.reserveUsageCalls++
	f.reserveUsageEnvelope = envelope
	f.reserveUsage = usage
	return f.reserveUsageErr
}

func TestProcessSharedRequestPathReservesBillingBeforeProvider(t *testing.T) {
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID:           "model-1",
		ModelName:    "gpt-4",
		ProviderID:   "provider-1",
		ProviderType: "openai",
	}}
	providerCaller := &MockProviderCaller{}
	billing := &recordingBillingPreflight{}
	handler := NewChatCompletionsHandler(
		&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{},
		&MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: providerCaller}, nil, nil,
	)
	handler.SetBillingPreflight(billing)

	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
	authInfo := &auth.AuthInfo{TenantID: "tenant-1", ProjectID: "project-1", UserID: "user-1", KeyID: "key-1"}
	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	w := httptest.NewRecorder()

	result, err := handler.processSharedRequestPath(httpReq.Context(), w, httpReq, "req-billing", authInfo, time.Now(), req, nil)
	if err != nil {
		t.Fatalf("expected shared request path to pass, got %v: %s", err, w.Body.String())
	}
	if result == nil || result.Envelope == nil {
		t.Fatal("expected processed request result")
	}
	if billing.reserveCalls != 1 {
		t.Fatalf("expected one billing reservation, got %d", billing.reserveCalls)
	}
	if billing.reserveEnvelope != result.Envelope || billing.reserveEnvelope.RequestID != "req-billing" {
		t.Fatalf("billing reservation used the wrong envelope: %+v", billing.reserveEnvelope)
	}
	if billing.reserveRequest != req {
		t.Fatal("billing reservation did not receive the chat request")
	}
	if len(providerCaller.CallCalls) != 0 {
		t.Fatalf("provider must not be called while preparing the shared path, got %d calls", len(providerCaller.CallCalls))
	}
}

func TestProcessSharedRequestPathPreservesBillingAdmissionHTTPStatus(t *testing.T) {
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID:           "model-1",
		ModelName:    "gpt-4",
		ProviderID:   "provider-1",
		ProviderType: "openai",
	}}
	providerCaller := &MockProviderCaller{}
	billing := &recordingBillingPreflight{reserveErr: &BillingAdmissionError{
		Code:       "billing_http_429",
		HTTPStatus: http.StatusTooManyRequests,
		Message:    "billing admission denied",
	}}
	handler := NewChatCompletionsHandler(
		&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{},
		&MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: providerCaller}, nil, nil,
	)
	handler.SetBillingPreflight(billing)

	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
	authInfo := &auth.AuthInfo{TenantID: "tenant-1", ProjectID: "project-1", UserID: "user-1", KeyID: "key-1"}
	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	w := httptest.NewRecorder()

	_, err := handler.processSharedRequestPath(httpReq.Context(), w, httpReq, "req-billing-limit", authInfo, time.Now(), req, nil)
	if err == nil {
		t.Fatal("expected billing admission rejection")
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", w.Code, w.Body.String())
	}
	if len(providerCaller.CallCalls) != 0 {
		t.Fatalf("provider must not be called after billing rejection, got %d calls", len(providerCaller.CallCalls))
	}
}

func TestProcessSharedRequestPathPreservesBillingLimitCodeAndRetryAfter(t *testing.T) {
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"rpm_limit_exceeded","message":"customer requests per minute limit exceeded"}}`))
	}))
	defer controlPlane.Close()

	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-1", ModelName: "gpt-4", ProviderID: "provider-1", ProviderType: "openai",
	}}
	providerCaller := &MockProviderCaller{}
	handler := NewChatCompletionsHandler(
		&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{},
		&MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: providerCaller}, nil, nil,
	)
	handler.SetBillingPreflight(NewBillingClient(controlPlane.URL, "internal-secret", "default"))

	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
	authInfo := &auth.AuthInfo{TenantID: "tenant-1", ProjectID: "project-1", UserID: "user-1", KeyID: "key-1"}
	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	w := httptest.NewRecorder()

	_, err := handler.processSharedRequestPath(httpReq.Context(), w, httpReq, "req-billing-rpm", authInfo, time.Now(), req, nil)
	if err == nil {
		t.Fatal("expected billing admission rejection")
	}
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("status=%d retry-after=%q body=%s", w.Code, w.Header().Get("Retry-After"), w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "rpm_limit_exceeded") {
		t.Fatalf("specific billing code was lost: %s", w.Body.String())
	}
	if len(providerCaller.CallCalls) != 0 {
		t.Fatalf("provider must not be called after billing rejection, got %d calls", len(providerCaller.CallCalls))
	}
}

func TestRunChatPolicyPreflightRejectsForbiddenModel(t *testing.T) {
	mockResolver := &MockModelResolver{ModelPolicy: &modelrouter.ModelPolicy{DenyList: []string{"gpt-4"}}}
	mockRateLimiter := &MockRateLimitChecker{}
	mockAudit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{modelResolver: mockResolver, rateLimiter: mockRateLimiter, auditWriter: mockAudit}
	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
	authInfo := &auth.AuthInfo{TenantID: "tenant-1", ProjectID: "project-1", UserID: "user-1", KeyID: "key-1"}
	partialEnvelope := buildChatPartialEnvelope("req-1", authInfo, req.Model, "chat")
	w := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", nil)

	result, err := handler.runChatPolicyPreflight(chatPolicyPreflightInput{
		ctx:             httpReq.Context(),
		w:               w,
		r:               httpReq,
		requestID:       "req-1",
		authInfo:        authInfo,
		startedAt:       time.Now(),
		request:         req,
		modelRecord:     &modelrouter.ModelRecord{ID: "model-1"},
		partialEnvelope: partialEnvelope,
	})

	if err == nil {
		t.Fatal("expected forbidden model error")
	}
	if result.concurrencyAcquired {
		t.Fatal("model policy rejection must not acquire concurrency")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Fatalf("expected one request log ensure, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 || mockAudit.RequestLogFinalizes[0].Status != "forbidden_model" {
		t.Fatalf("expected forbidden_model finalize, got %+v", mockAudit.RequestLogFinalizes)
	}
	if len(mockRateLimiter.ReleaseConcurrencyCalls) != 0 {
		t.Fatalf("did not expect concurrency release when slot was never acquired, got %+v", mockRateLimiter.ReleaseConcurrencyCalls)
	}
}

func TestRunChatPolicyPreflightReleasesConcurrencyOnQuotaRejection(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{ConcurrencyLimit: 5, DailyTokenLimit: 100}}
	mockRateLimiter := &MockRateLimitChecker{ConcurrencyAllowed: true, DailyAllowed: false}
	mockAudit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{modelResolver: mockResolver, rateLimiter: mockRateLimiter, auditWriter: mockAudit}
	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
	authInfo := &auth.AuthInfo{TenantID: "tenant-1", ProjectID: "project-1", UserID: "user-1", KeyID: "key-1"}
	partialEnvelope := buildChatPartialEnvelope("req-1", authInfo, req.Model, "chat")
	w := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", nil)

	result, err := handler.runChatPolicyPreflight(chatPolicyPreflightInput{
		ctx:             httpReq.Context(),
		w:               w,
		r:               httpReq,
		requestID:       "req-1",
		authInfo:        authInfo,
		startedAt:       time.Now(),
		request:         req,
		modelRecord:     &modelrouter.ModelRecord{ID: "model-1"},
		partialEnvelope: partialEnvelope,
	})

	if err == nil {
		t.Fatal("expected quota rejection")
	}
	if !result.concurrencyAcquired {
		t.Fatal("expected concurrency to be acquired before quota rejection")
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", w.Code, w.Body.String())
	}
	if len(mockRateLimiter.ReleaseConcurrencyCalls) != 1 || mockRateLimiter.ReleaseConcurrencyCalls[0] != "project-1" {
		t.Fatalf("expected concurrency release for project-1, got %+v", mockRateLimiter.ReleaseConcurrencyCalls)
	}
	if len(mockAudit.RequestLogFinalizes) != 1 || mockAudit.RequestLogFinalizes[0].Status != "quota_exceeded" {
		t.Fatalf("expected quota_exceeded finalize, got %+v", mockAudit.RequestLogFinalizes)
	}
}

func TestRunChatPolicyPreflightSoftQuotaNeverHardRejects(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{
		RPMLimit: 1, ConcurrencyLimit: 1, DailyTokenLimit: 1, MonthlyTokenLimit: 1,
		EnforcementMode: "soft",
	}}
	mockRateLimiter := &MockRateLimitChecker{}
	handler := &ChatCompletionsHandler{
		modelResolver: mockResolver,
		rateLimiter:   mockRateLimiter,
		auditWriter:   &MockAuditWriter{},
	}
	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
	authInfo := &auth.AuthInfo{TenantID: "tenant-1", ProjectID: "project-1", UserID: "user-1", KeyID: "key-1"}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	w := httptest.NewRecorder()

	result, err := handler.runChatPolicyPreflight(chatPolicyPreflightInput{
		ctx: httpReq.Context(), w: w, r: httpReq, requestID: "req-soft",
		authInfo: authInfo, startedAt: time.Now(), request: req,
		modelRecord:     &modelrouter.ModelRecord{ID: "model-1"},
		partialEnvelope: buildChatPartialEnvelope("req-soft", authInfo, req.Model, "chat"),
	})

	if err != nil || result.concurrencyAcquired || w.Code != http.StatusOK {
		t.Fatalf("soft quota must remain observational: result=%+v status=%d err=%v body=%s", result, w.Code, err, w.Body.String())
	}
}

func TestRunChatPolicyPreflightProxySwitchesRuntimeIdentity(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockAudit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{
		cfg:           &config.Config{ProxyDefaultTenantID: "tenant_default", ProxyDefaultProjectID: "project_default", ProxyDefaultUserID: "system_proxy"},
		modelResolver: mockResolver,
		rateLimiter:   &MockRateLimitChecker{},
		auditWriter:   mockAudit,
		proxyKeyVerifier: &fakeProxyKeyVerifier{
			info: &ProxyKeyInfo{KeyID: "proxy-key-1"},
		},
	}
	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
	authInfo := &auth.AuthInfo{TenantID: "tenant-user", ProjectID: "project-user", UserID: "user-1", KeyID: "key-1"}
	partialEnvelope := buildChatPartialEnvelope("req-1", authInfo, req.Model, "chat")
	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	httpReq.Header.Set("X-Proxy-Key", "proxy-good")
	ctx := context.WithValue(httpReq.Context(), auth.ProxyRequestKey, true)
	ctx = context.WithValue(ctx, auth.ClientIPKey, "1.2.3.4")
	httpReq = httpReq.WithContext(ctx)
	w := httptest.NewRecorder()

	result, err := handler.runChatPolicyPreflight(chatPolicyPreflightInput{
		ctx:       httpReq.Context(),
		w:         w,
		r:         httpReq,
		requestID: "req-1",
		authInfo:  authInfo,
		startedAt: time.Now(),
		request:   req,
		modelRecord: &modelrouter.ModelRecord{
			ID:          "model-1",
			ProxyConfig: `{"enabled":true}`,
		},
		partialEnvelope: partialEnvelope,
	})

	if err != nil {
		t.Fatalf("expected proxy preflight to pass, got %v", err)
	}
	if result.concurrencyAcquired {
		t.Fatal("proxy preflight should not acquire tenant concurrency")
	}
	if authInfo.TenantID != "tenant_default" || authInfo.ProjectID != "project_default" || authInfo.UserID != "system_proxy:1.2.3.4" {
		t.Fatalf("expected proxy identity switch, got %+v", authInfo)
	}
	if len(mockAudit.RequestLogFinalizes) != 0 {
		t.Fatalf("did not expect rejection finalize on passing proxy preflight, got %+v", mockAudit.RequestLogFinalizes)
	}
}
