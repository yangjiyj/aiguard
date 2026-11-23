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

func TestNativeResponsesLiveStreamPreservesSSEAndFinalizesSecurityEvidence(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-live\"}}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-live\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"gpt-live\",\"output\":[{\"id\":\"msg-live\",\"type\":\"message\",\"status\":\"completed\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"hello\"}]}],\"usage\":{\"input_tokens\":3,\"output_tokens\":1,\"total_tokens\":4}}}\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	resolver := &MockModelResolver{
		ProviderAPIKey: "provider-key",
		ModelRecord: &modelrouter.ModelRecord{
			ID: "model-live", ProviderID: "provider-live", ModelName: "gpt-live",
			UpstreamModelID: "gpt-live", ProviderType: "openai",
			ProviderBaseURL: upstream.URL, ProviderAuthMode: "bearer",
			Status: "active", ResponsesNative: true,
		},
	}
	security := &streamRegressionSecurity{}
	audit := &MockAuditWriter{}
	handler := NewResponsesHandler(
		&config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_audit"},
		resolver, &MockRateLimitChecker{}, security, audit, &RealProviderAdapterFactory{}, nil, nil,
	)

	request := nativeResponsesRequest(t, []byte("{\"model\":\"gpt-live\",\"input\":\"inspect\",\"stream\":true}"))
	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, request)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "response.output_text.delta") || !strings.Contains(body, "response.completed") {
		t.Fatalf("native SSE body=%q", body)
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
	final := audit.RequestLogFinalizes[0]
	assertRequestTimingPersisted(t, final.Envelope, final.AuditResult, "input_security_ms", "output_security_ms", "pre_upstream_ms", "generation_ms")
}
