package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

// === Embeddings Tests ===

func TestEmbeddingsSuccess(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello world"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp EmbeddingsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.Object != "list" {
		t.Errorf("Expected object='list', got '%s'", resp.Object)
	}
	if len(resp.Data) != 1 {
		t.Errorf("Expected 1 embedding data")
	}
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog call")
	}
	if mockAudit.RequestLogFinalizes[0].Status != "success" {
		t.Errorf("Expected final status='success'")
	}
}

func TestEmbeddingsPreservesBillingAdmissionHTTPStatus(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	providerCaller := &MockProviderCaller{}
	mockProviderFactory := &MockProviderAdapterFactory{MockProviderCaller: providerCaller}
	handler := NewEmbeddingsHandler(&config.Config{}, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)
	handler.SetBillingPreflight(&recordingBillingPreflight{reserveUsageErr: &BillingAdmissionError{
		Code:       "billing_http_429",
		HTTPStatus: http.StatusTooManyRequests,
		Message:    "billing admission denied",
	}})

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello world"}
	body, _ := json.Marshal(reqBody)
	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = httpReq.WithContext(setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", ""))

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", w.Code, w.Body.String())
	}
	if len(providerCaller.CallCalls) != 0 {
		t.Fatalf("provider must not be called after billing rejection, got %d calls", len(providerCaller.CallCalls))
	}
}

func TestEmbeddingsInvalidJSON(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader([]byte("invalid json")))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// Audit contract: request log for invalid JSON rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for invalid JSON, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for invalid JSON, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "invalid_request" {
		t.Errorf("Expected final status='invalid_request', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestEmbeddingsMissingModel(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Input: "Hello world"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing model, got %d", w.Code)
	}

	// Audit contract: request log for invalid_request rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for missing model, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for missing model, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "invalid_request" {
		t.Errorf("Expected final status='invalid_request', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestEmbeddingsEmptyInput(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: ""}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for empty input, got %d", w.Code)
	}

	// Audit contract: request log for invalid_request rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for empty input, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for empty input, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "invalid_request" {
		t.Errorf("Expected final status='invalid_request', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestEmbeddingsArrayInput(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderCaller := &MockProviderCaller{}
	mockProviderFactory := &MockProviderAdapterFactory{MockProviderCaller: mockProviderCaller}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	// Array input with 2 strings
	reqBody := EmbeddingsRequest{
		Model: "text-embedding-ada-002",
		Input: []interface{}{"Hello", "World"},
	}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify TransformRequest was called
	if len(mockProviderCaller.TransformRequestCalls) != 1 {
		t.Errorf("Expected 1 TransformRequest call, got %d", len(mockProviderCaller.TransformRequestCalls))
	}
}

func TestEmbeddingsSecurityBlocked(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{
		InputAction:   "block",
		InputFindings: []SecurityFinding{{Type: "pii", Severity: "high"}},
	}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "sensitive data"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for security blocked, got %d", w.Code)
	}
	if len(mockAudit.SecurityEventWrites) == 0 {
		t.Error("Expected security event write")
	}
}

func TestEmbeddingsProviderCallFailure(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderCaller := &MockProviderCaller{CallError: fmt.Errorf("provider unavailable")}
	mockProviderFactory := &MockProviderAdapterFactory{MockProviderCaller: mockProviderCaller}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502 for provider failure, got %d", w.Code)
	}
	if mockAudit.RequestLogFinalizes[0].Status != "provider_unavailable" {
		t.Errorf("Expected final status='provider_unavailable'")
	}
}

func TestEmbeddingsConcurrencyRelease(t *testing.T) {
	mockResolver := &MockModelResolver{
		QuotaPolicy: &modelrouter.QuotaPolicy{ConcurrencyLimit: 10},
	}
	mockRateLimiter := &MockRateLimitChecker{ConcurrencyAllowed: true}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify concurrency was released
	if len(mockRateLimiter.ReleaseConcurrencyCalls) != 1 {
		t.Errorf("Expected 1 release concurrency call, got %d", len(mockRateLimiter.ReleaseConcurrencyCalls))
	}
}

func TestEmbeddingsRateLimited(t *testing.T) {
	mockResolver := &MockModelResolver{
		QuotaPolicy: &modelrouter.QuotaPolicy{RPMLimit: 100},
	}
	mockRateLimiter := &MockRateLimitChecker{RPMAllowed: false}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 for rate limited, got %d", w.Code)
	}

	// Request log MUST be recorded for rate_limited rejection (audit contract)
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for rate_limited, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for rate_limited, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "rate_limited" {
		t.Errorf("Expected final status='rate_limited', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

// TestEmbeddingsProviderUnsupportedEndpoint verifies provider_unsupported error when provider doesn't support embeddings
func TestEmbeddingsProviderUnsupportedEndpoint(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	// Simulate provider returning endpoint not supported error
	mockProviderCaller := &MockProviderCaller{
		CallError: fmt.Errorf("%w: anthropic provider only supports chat", provider.ErrEndpointNotSupported),
	}
	mockProviderFactory := &MockProviderAdapterFactory{MockProviderCaller: mockProviderCaller}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "claude-3", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// Should return 400 Bad Request, NOT 502 Bad Gateway
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for provider_unsupported, got %d", w.Code)
	}

	// Should return provider_unsupported error code, NOT provider_unavailable
	respBody := w.Body.String()
	if !strings.Contains(respBody, "provider_unsupported") {
		t.Errorf("Expected error code 'provider_unsupported', got: %s", respBody)
	}
	if strings.Contains(respBody, "provider_unavailable") {
		t.Errorf("Should NOT contain 'provider_unavailable', got: %s", respBody)
	}

	// Audit final status should be provider_unsupported
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog call")
	}
	if mockAudit.RequestLogFinalizes[0].Status != "provider_unsupported" {
		t.Errorf("Expected final status='provider_unsupported', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

// TestEmbeddingsSessionUpsert verifies session upsert when session ID is present
func TestEmbeddingsSessionUpsert(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	// Include session ID in auth context
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-456")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify UpsertAgentSession was called
	if len(mockAudit.AgentSessionUpserts) != 1 {
		t.Errorf("Expected 1 UpsertAgentSession call, got %d", len(mockAudit.AgentSessionUpserts))
	}
	if mockAudit.AgentSessionUpserts[0].SessionID != "session-456" {
		t.Errorf("Expected SessionID='session-456', got '%s'", mockAudit.AgentSessionUpserts[0].SessionID)
	}
}

// TestEmbeddingsNoSessionUpsert verifies no session upsert when session ID is absent
func TestEmbeddingsNoSessionUpsert(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	// No session ID
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify UpsertAgentSession was NOT called
	if len(mockAudit.AgentSessionUpserts) != 0 {
		t.Errorf("Expected 0 UpsertAgentSession calls when no session ID, got %d", len(mockAudit.AgentSessionUpserts))
	}
}

// TestEmbeddingsUpstreamHTTPError500 verifies upstream 500 error is passed through to client
func TestEmbeddingsUpstreamHTTPError500(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	upstreamErrBody := []byte(`{"error": {"message": "internal server error", "type": "server_error"}}`)
	mockProviderCaller := &MockProviderCaller{
		CallError: &provider.UpstreamHTTPError{
			StatusCode: http.StatusInternalServerError,
			Body:       upstreamErrBody,
			Message:    "internal server error",
		},
	}
	mockProviderFactory := &MockProviderAdapterFactory{MockProviderCaller: mockProviderCaller}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// Should return 500 from upstream, NOT 502 Bad Gateway
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500 (upstream), got %d", w.Code)
	}

	if !strings.Contains(w.Body.String(), "upstream_error") || strings.Contains(w.Body.String(), "internal server error") {
		t.Errorf("Expected sanitized gateway error body, got: %s", w.Body.String())
	}

	// Audit final status should be provider_error, NOT provider_unavailable
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog call")
	}
	if mockAudit.RequestLogFinalizes[0].Status != "provider_error" {
		t.Errorf("Expected final status='provider_error', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

// TestEmbeddingsUpstreamHTTPError400 verifies upstream 400 error is passed through
func TestEmbeddingsUpstreamHTTPError400(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	upstreamErrBody := []byte(`{"error": {"message": "invalid model: model not found", "type": "invalid_request_error"}}`)
	mockProviderCaller := &MockProviderCaller{
		CallError: &provider.UpstreamHTTPError{
			StatusCode: http.StatusBadRequest,
			Body:       upstreamErrBody,
			Message:    "invalid model: model not found",
		},
	}
	mockProviderFactory := &MockProviderAdapterFactory{MockProviderCaller: mockProviderCaller}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "invalid-model", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// Should return 400 from upstream
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 (upstream), got %d", w.Code)
	}

	if !strings.Contains(w.Body.String(), "upstream_error") || !strings.Contains(w.Body.String(), "invalid model: model not found") {
		t.Errorf("Expected upstream 4xx message passed through, got: %s", w.Body.String())
	}

	// Audit final status should be provider_error
	if mockAudit.RequestLogFinalizes[0].Status != "provider_error" {
		t.Errorf("Expected final status='provider_error', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
	if mockAudit.RequestLogFinalizes[0].StatusCode != http.StatusBadRequest {
		t.Errorf("Expected StatusCode=400 in audit, got %d", mockAudit.RequestLogFinalizes[0].StatusCode)
	}
}

// TestEmbeddingsProviderUnavailableNotUpstreamHTTP verifies network errors are still provider_unavailable
func TestEmbeddingsProviderUnavailableNotUpstreamHTTP(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	// Regular error (network, timeout, etc.) - NOT UpstreamHTTPError
	mockProviderCaller := &MockProviderCaller{
		CallError: fmt.Errorf("connection refused"),
	}
	mockProviderFactory := &MockProviderAdapterFactory{MockProviderCaller: mockProviderCaller}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	// Should return 502 Bad Gateway for network errors
	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502 for network error, got %d", w.Code)
	}

	// Should contain provider_unavailable error code
	if !strings.Contains(w.Body.String(), "provider_unavailable") {
		t.Errorf("Expected error code 'provider_unavailable', got: %s", w.Body.String())
	}

	// Audit final status should be provider_unavailable (NOT provider_error)
	if mockAudit.RequestLogFinalizes[0].Status != "provider_unavailable" {
		t.Errorf("Expected final status='provider_unavailable', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

// ===== Embeddings Audit Contract Regression Tests =====
// These tests verify that embeddings early-failure branches record request logs.
// Contract: authenticated request must have request log, even if rejected early.

func TestEmbeddingsAuditContractModelNotConfigured(t *testing.T) {
	mockResolver := &MockModelResolver{ResolveError: fmt.Errorf("model not found")}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "unknown-model", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}

	// Request log MUST be recorded for model_not_configured rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for model_not_configured, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for model_not_configured, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "model_not_configured" {
		t.Errorf("Expected final status='model_not_configured', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestEmbeddingsAuditContractForbiddenModel(t *testing.T) {
	mockResolver := &MockModelResolver{ModelPolicy: &modelrouter.ModelPolicy{DenyList: []string{"text-embedding-ada-002"}}}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}

	// Request log MUST be recorded for forbidden_model rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for forbidden_model, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for forbidden_model, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "forbidden_model" {
		t.Errorf("Expected final status='forbidden_model', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestEmbeddingsAuditContractRateLimited(t *testing.T) {
	mockResolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{RPMLimit: 10}}
	mockRateLimiter := &MockRateLimitChecker{RPMAllowed: false}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}

	// Request log MUST be recorded for rate_limited rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for rate_limited, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for rate_limited, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "rate_limited" {
		t.Errorf("Expected final status='rate_limited', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

func TestEmbeddingsAuditContractProviderNotConfigured(t *testing.T) {
	mockResolver := &MockModelResolver{ReturnEmptyKey: true} // No API key
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	reqBody := EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}

	// Request log MUST be recorded for provider_not_configured rejection
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog for provider_not_configured, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog for provider_not_configured, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "provider_not_configured" {
		t.Errorf("Expected final status='provider_not_configured', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}

// REGRESSION TEST: TestEmbeddingsPreParseSessionUpsertOnInvalidJSON verifies session is upserted
// even when JSON parsing fails (pre-parse failure). Contract: authenticated request with session
// header should always create/update session record, regardless of pre-parse/pre-process errors.
func TestEmbeddingsPreParseSessionUpsertOnInvalidJSON(t *testing.T) {
	mockResolver := &MockModelResolver{}
	mockRateLimiter := &MockRateLimitChecker{}
	mockSecurity := &MockSecurityChecker{}
	mockAudit := &MockAuditWriter{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	cfg := &config.Config{}
	handler := NewEmbeddingsHandler(cfg, mockResolver, mockRateLimiter, mockSecurity, mockAudit, mockProviderFactory)

	httpReq := httptest.NewRequest("POST", "/v1/embeddings", bytes.NewReader([]byte("invalid json")))
	httpReq.Header.Set("Content-Type", "application/json")
	// Key: authenticated request with session header
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-embeddings-pre")
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// Session MUST be upserted even on pre-parse invalid JSON
	if len(mockAudit.AgentSessionUpserts) != 1 {
		t.Errorf("Expected 1 AgentSessionUpsert on pre-parse failure, got %d", len(mockAudit.AgentSessionUpserts))
	}
	if mockAudit.AgentSessionUpserts[0].SessionID != "session-embeddings-pre" {
		t.Errorf("Expected session_id='session-embeddings-pre', got '%s'", mockAudit.AgentSessionUpserts[0].SessionID)
	}

	// Request log also recorded
	if len(mockAudit.RequestLogEnsures) != 1 {
		t.Errorf("Expected 1 EnsureRequestLog, got %d", len(mockAudit.RequestLogEnsures))
	}
	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Errorf("Expected 1 FinalizeRequestLog, got %d", len(mockAudit.RequestLogFinalizes))
	}
	if mockAudit.RequestLogFinalizes[0].Status != "invalid_request" {
		t.Errorf("Expected final status='invalid_request', got '%s'", mockAudit.RequestLogFinalizes[0].Status)
	}
}
