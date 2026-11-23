package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestNativeMessagesLiveStreamPreservesAnthropicEventsAndFinalizesEvidence(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "provider-key" {
			t.Fatalf("upstream api key=%q", r.Header.Get("X-Api-Key"))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-live\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-live\",\"content\":[],\"usage\":{\"input_tokens\":3,\"cache_read_input_tokens\":2,\"output_tokens\":0}}}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n")
		_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	resolver := &MockModelResolver{
		ProviderAPIKey: "provider-key",
		ModelRecord: &modelrouter.ModelRecord{
			ID: "model-live", ProviderID: "provider-live", ModelName: "claude-live",
			UpstreamModelID: "claude-live", ProviderType: "anthropic",
			ProviderBaseURL: upstream.URL, Status: "active",
		},
	}
	security := &streamRegressionSecurity{}
	audit := &MockAuditWriter{}
	handler := NewMessagesHandler(
		&config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_audit"},
		resolver, &MockRateLimitChecker{}, security, audit, &RealProviderAdapterFactory{}, nil, nil,
	)

	request := httptest.NewRequest(http.MethodPost, "/v1/messages",
		strings.NewReader("{\"model\":\"claude-live\",\"max_tokens\":16,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"inspect\"}]}"))
	request = request.WithContext(setAuthInfo(request.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-123"))
	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, request)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "event: content_block_delta") || !strings.Contains(body, "\"text\":\"hello\"") ||
		!strings.Contains(body, "event: message_stop") {
		t.Fatalf("Messages SSE body=%q", body)
	}
	if len(security.calls()) != 2 || security.calls()[0] != "hello" || security.calls()[1] != "hello" {
		t.Fatalf("live and final output scans=%#v", security.calls())
	}
	foundAssistantEvidence := false
	for _, log := range audit.ContentLogWrites {
		if log.Role == "assistant" && log.Content == "hello" {
			foundAssistantEvidence = true
			break
		}
	}
	if !foundAssistantEvidence {
		t.Fatalf("content evidence=%#v", audit.ContentLogWrites)
	}
	if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != "success" {
		t.Fatalf("request finalization=%#v", audit.RequestLogFinalizes)
	}
	if !strings.Contains(string(audit.RequestLogFinalizes[0].RespBody), "\"prompt_tokens\":5") {
		t.Fatalf("Anthropic cache-read tokens were not normalized into the audit usage: %s", audit.RequestLogFinalizes[0].RespBody)
	}
	final := audit.RequestLogFinalizes[0]
	assertRequestTimingPersisted(t, final.Envelope, final.AuditResult, "input_security_ms", "output_security_ms", "pre_upstream_ms", "generation_ms")
}
