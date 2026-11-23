package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaptureGatewayResponsesDiagnosticIsExplicitAndScoped(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GATEWAY_RAW_DUMP_DIR", dir)
	t.Setenv("GATEWAY_RAW_DUMP_MAX_SAMPLES", "1")

	captured, err := captureGatewayResponsesDiagnostic("req-sample", "api.example-gateway.com", "/v1/responses", "application/json", []byte(`{"output":"expected final answer"}`))
	if err != nil {
		t.Fatalf("capture diagnostic: %v", err)
	}
	if !captured {
		t.Fatal("expected the explicitly enabled Codex Responses sample to be captured")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read diagnostic dir: %v", err)
	}
	if len(entries) != 1 || filepath.Ext(entries[0].Name()) != ".response" {
		t.Fatalf("expected one response-only diagnostic file, got %#v", entries)
	}
	stored, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read captured response: %v", err)
	}
	if string(stored) != `{"output":"expected final answer"}` {
		t.Fatalf("unexpected captured body: %q", stored)
	}

	if captured, err := captureGatewayResponsesDiagnostic("req-other", "api.example-gateway.com", "/v1/chat/completions", "application/json", []byte(`{"choices":[]}`)); err != nil || captured {
		t.Fatalf("non-Responses traffic must never be captured: captured=%v err=%v", captured, err)
	}
}

func TestCaptureGatewayResponsesDiagnosticHonorsOneSampleLimit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GATEWAY_RAW_DUMP_DIR", dir)
	t.Setenv("GATEWAY_RAW_DUMP_MAX_SAMPLES", "1")

	if captured, err := captureGatewayResponsesDiagnostic("req-first", "api.example-gateway.com", "/v1/responses", "application/json", []byte("first")); err != nil || !captured {
		t.Fatalf("first sample: captured=%v err=%v", captured, err)
	}
	if captured, err := captureGatewayResponsesDiagnostic("req-second", "api.example-gateway.com", "/v1/responses", "application/json", []byte("second")); err != nil || captured {
		t.Fatalf("second sample must be rejected by the cap: captured=%v err=%v", captured, err)
	}
}

func TestReverseProxyStreamsCaptureTheSingleResponsesDiagnostic(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GATEWAY_RAW_DUMP_DIR", dir)
	t.Setenv("GATEWAY_RAW_DUMP_MAX_SAMPLES", "1")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\\\"type\\\":\\\"response.output_text.delta\\\",\\\"delta\\\":\\\"final answer\\\"}\\n\\n"))
		_, _ = w.Write([]byte("data: [DONE]\\n\\n"))
	}))
	defer upstream.Close()

	handler := &ReverseProxyHandler{
		tenantID:            "tenant_default",
		client:              upstream.Client(),
		resolveEgressTarget: testEgressResolver(upstream.URL),
		auditRecorder:       &fakeReverseProxyAuditRecorder{},
		routes: []ReverseProxyRoute{{
			ID: "rpr_examplegw", PathPrefix: "/examplegw", TargetURL: "http://api.example-gateway.com",
			SecurityEnabled: false, Status: "active",
		}},
	}
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/examplegw/v1/responses", strings.NewReader(`{"stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	if !handler.ServeHTTP(w, req) || w.Code != http.StatusOK {
		t.Fatalf("expected streamed Responses request to succeed, got %d", w.Code)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read diagnostic dir: %v", err)
	}
	if len(entries) != 1 || filepath.Ext(entries[0].Name()) != ".response" {
		t.Fatalf("expected one streamed response capture, got %#v", entries)
	}
}

func TestExtractReverseProxyResponsesSSEOutputUsesFinalTextOnly(t *testing.T) {
	body := []byte(`event: response.created
data: {"type":"response.created","response":{"instructions":"Codex runtime prompt that must not be displayed as the answer"}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":"actual "}

event: response.output_text.done
data: {"type":"response.output_text.done","text":"actual final answer"}

event: response.completed
data: {"type":"response.completed","response":{"output":[]}}
`)
	if got := extractReverseProxyResponsesSSEOutput(body); got != "actual final answer" {
		t.Fatalf("expected final output text only, got %q", got)
	}
}
