package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

func TestFinalizeChatJSONSuccessWritesAuditAndHeadersOnce(t *testing.T) {
	mockAudit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{auditWriter: mockAudit}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1", ProjectID: "project-1", ModelID: "model-1", Model: "gpt-4", ProviderID: "provider-1", Provider: "openai"}
	respBody := []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1716399600,"model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`)
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })

	handler.finalizeChatJSONSuccess(context.Background(), w, chatJSONSuccessFinalizerInput{
		envelope:     envelope,
		respBody:     respBody,
		startedAt:    time.Now(),
		auditResult:  &AuditResult{InputAction: "allow", OutputAction: "allow"},
		fallbackUsed: true,
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-JJDGuard-Provider-ID"); got != "provider-1" {
		t.Fatalf("expected provider header, got %q", got)
	}
	if got := w.Header().Get("X-JJDGuard-Fallback-Used"); got != "true" {
		t.Fatalf("expected fallback header true, got %q", got)
	}
	if len(mockAudit.RequestLogFinalizes) != 1 || mockAudit.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("expected one success finalize, got %+v", mockAudit.RequestLogFinalizes)
	}
	if len(mockAudit.ContentLogWrites) != 1 || mockAudit.ContentLogWrites[0].Role != "assistant" || mockAudit.ContentLogWrites[0].Tokens != 2 {
		t.Fatalf("expected one assistant content log with completion tokens, got %+v", mockAudit.ContentLogWrites)
	}
}

func TestFinalizeChatJSONSuccessBindsProposedToolBeforeRequestFinalize(t *testing.T) {
	mockAudit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{auditWriter: mockAudit}
	envelope := chatToolTestEnvelope()
	envelope.EvidenceRunID = "run_weak"
	envelope.EvidenceRunSource = "responses_prompt_cache_key_candidate"
	envelope.EvidenceRunPrefixHash = "prefix-a"
	respBody := []byte(`{"id":"chatcmpl-tool","choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_0123456789abcdef_response","type":"function","function":{"name":"read","arguments":"{}"}}]}}]}`)

	handler.finalizeChatJSONSuccess(context.Background(), httptest.NewRecorder(), chatJSONSuccessFinalizerInput{
		envelope: envelope, respBody: respBody, startedAt: time.Now(),
	})

	if len(mockAudit.RequestLogFinalizes) != 1 {
		t.Fatalf("finalize calls=%d, want 1", len(mockAudit.RequestLogFinalizes))
	}
	finalized := mockAudit.RequestLogFinalizes[0].Envelope
	if finalized.EvidenceRunID == "" || finalized.EvidenceRunID == "run_weak" || finalized.EvidenceRunSource != chatToolCallEvidenceSource {
		t.Fatalf("proposed tool evidence was not bound before finalize: %+v", finalized)
	}
}

func TestFinalizeChatProviderErrorPassesThroughUpstreamHTTP(t *testing.T) {
	mockAudit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{auditWriter: mockAudit}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1", ProjectID: "project-1", UpstreamProtocol: "responses"}
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })
	upstreamErr := &provider.UpstreamHTTPError{StatusCode: http.StatusBadRequest, Body: []byte(`{"error":{"message":"bad request"}}`), Message: "bad request"}

	handled := handler.finalizeChatProviderError(context.Background(), w, chatProviderErrorFinalizerInput{
		envelope:  envelope,
		requestID: "req-1",
		startedAt: time.Now(),
		err:       upstreamErr,
	})

	if !handled {
		t.Fatal("expected provider error to be handled")
	}
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "upstream_error") || !strings.Contains(w.Body.String(), "bad request") || !strings.Contains(w.Body.String(), `"stage":"upstream_response"`) {
		t.Fatalf("expected diagnosable 400 body, got status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Request-ID") != "req-1" || w.Header().Get("X-JJDGuard-Error-Stage") != "upstream_response" || w.Header().Get("X-JJDGuard-Upstream-Protocol") != "responses" {
		t.Fatalf("missing correlation headers: %#v", w.Header())
	}
	if len(mockAudit.RequestLogFinalizes) != 1 || mockAudit.RequestLogFinalizes[0].Status != "provider_error" || mockAudit.RequestLogFinalizes[0].StatusCode != http.StatusBadRequest {
		t.Fatalf("expected provider_error finalize, got %+v", mockAudit.RequestLogFinalizes)
	}
}

func TestFinalizeChatProviderErrorUsesGatewayErrorForNetwork(t *testing.T) {
	mockAudit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{auditWriter: mockAudit}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1", ProjectID: "project-1"}
	w := httptest.NewRecorder()
	t.Cleanup(func() { assertLegacyRoutingHeadersAbsent(t, w) })

	handled := handler.finalizeChatProviderError(context.Background(), w, chatProviderErrorFinalizerInput{
		envelope:  envelope,
		requestID: "req-1",
		startedAt: time.Now(),
		err:       errors.New("connection refused"),
	})

	if !handled {
		t.Fatal("expected provider error to be handled")
	}
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "provider_unavailable") {
		t.Fatalf("expected gateway provider_unavailable, got status=%d body=%s", w.Code, w.Body.String())
	}
	if len(mockAudit.RequestLogFinalizes) != 1 || mockAudit.RequestLogFinalizes[0].Status != "provider_unavailable" || mockAudit.RequestLogFinalizes[0].StatusCode != http.StatusBadGateway {
		t.Fatalf("expected provider_unavailable finalize, got %+v", mockAudit.RequestLogFinalizes)
	}
}

func assertLegacyRoutingHeadersAbsent(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Header().Get("X-NewAPI-Provider-ID"); got != "" {
		t.Fatalf("legacy provider header=%q", got)
	}
	if got := w.Header().Get("X-NewAPI-Fallback-Used"); got != "" {
		t.Fatalf("legacy fallback header=%q", got)
	}
}
