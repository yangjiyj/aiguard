package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func sseJSON(v any) string { b, _ := json.Marshal(v); return "data: " + string(b) + "\r\n\r\n" }
func TestStreamingInspectionDoesNotUseRetentionHeadTail(t *testing.T) {
	metadata := sseJSON(map[string]any{"type": "response.created", "response": map[string]any{"instructions": strings.Repeat("x", 300*1024)}})
	secret := "password=MiddleSynthetic79!qR"
	stream := metadata + sseJSON(map[string]any{"type": "response.output_text.delta", "delta": "开头 " + secret + " 结尾"}) + metadata + "data: [DONE]\n\n"
	captured := &headTailReverseProxyCapture{limit: maxReverseProxyRetainedBodyBytes}
	projection := &streamInspectionCapture{path: "/v1/responses"}
	relay := httptest.NewRecorder()
	n, err := copySSEWithFlush(relay, io.MultiWriter(captured, projection), strings.NewReader(stream))
	if err != nil || n != int64(len(stream)) || relay.Body.String() != stream {
		t.Fatal("relay changed")
	}
	if !captured.Truncated() || bytes.Contains(captured.Bytes(), []byte(secret)) {
		t.Fatal("fixture must place secret in omitted retention middle")
	}
	text, reason := projection.Finish(false)
	if reason != "" || !strings.Contains(text, secret) || strings.Contains(text, "xxxx") {
		t.Fatalf("text=%q reason=%s", text, reason)
	}
	scanned := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		_ = json.NewDecoder(r.Body).Decode(&p)
		scanned = strings.Contains(p["content"].(string), secret)
		fmt.Fprint(w, `{"action":"block","inspection_status":"completed","engine_build":"test","findings":[{"type":"secret","category":"plain_password","severity":"critical","matched_location":"content[3:20]"}]}`)
	}))
	defer server.Close()
	h := &ReverseProxyHandler{client: server.Client(), securityURL: server.URL}
	d, err := h.checkStreamInspection(context.Background(), "r", text, reason, "example.invalid", "/v1/responses")
	if err != nil || !scanned || len(d.Findings) != 1 || d.Allowed || d.Action != "block" {
		t.Fatalf("output scan=%+v %v", d, err)
	}
}
func TestStreamingInspectionParsesFragmentedProtocols(t *testing.T) {
	cases := []struct{ path, stream, want string }{
		{"/v1/chat/completions", sseJSON(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": "你好"}}}}) + "data: [DONE]\n\n", "你好"},
		{"/v1/messages", sseJSON(map[string]any{"type": "content_block_delta", "delta": map[string]any{"type": "text_delta", "text": "你好"}}) + sseJSON(map[string]any{"type": "message_stop"}), "你好"},
		{"/v1/responses", sseJSON(map[string]any{"type": "response.output_text.delta", "delta": "你好"}) + sseJSON(map[string]any{"type": "response.output_text.done", "text": "你好"}) + "data: [DONE]\n\n", "你好"},
	}
	for _, tc := range cases {
		c := &streamInspectionCapture{path: tc.path}
		for _, b := range []byte(tc.stream) {
			_, _ = c.Write([]byte{b})
		}
		text, reason := c.Finish(false)
		if text != tc.want || reason != "" {
			t.Fatalf("%s text=%q reason=%s", tc.path, text, reason)
		}
	}
}
func TestStreamingInspectionDoesNotReplaceExposedTextWithBenignFinal(t *testing.T) {
	c := &streamInspectionCapture{path: "/v1/responses"}
	c.Write([]byte(sseJSON(map[string]any{"type": "response.output_text.delta", "delta": "secret already sent"}) + sseJSON(map[string]any{"type": "response.output_text.done", "text": "safe"}) + "data: [DONE]\n\n"))
	text, reason := c.Finish(false)
	if reason != "" || !strings.Contains(text, "secret already sent") || !strings.Contains(text, "safe") {
		t.Fatalf("%q %s", text, reason)
	}
}
func TestStreamingInspectionLimitsAndInterruptedStreamsStayIncomplete(t *testing.T) {
	for _, body := range []string{"data: {bad}\n\n", "data: " + strings.Repeat("x", maxInspectionSSEEvent+1), sseJSON(map[string]any{"type": "response.output_text.delta", "delta": "partial"}), sseJSON(map[string]any{"type": "response.output_text.done", "text": "one part is done, not the response"})} {
		c := &streamInspectionCapture{path: "/v1/responses"}
		if n, e := c.Write([]byte(body)); e != nil || n != len(body) {
			t.Fatal("capture affected relay")
		}
		_, reason := c.Finish(false)
		if reason == "" {
			t.Fatal("incomplete stream reported complete")
		}
	}
	c := &streamInspectionCapture{path: "/v1/responses"}
	c.Write([]byte("data: [DONE]\n\n"))
	_, reason := c.Finish(true)
	if reason == "" {
		t.Fatal("transport error lost")
	}
}
func TestStreamingInspectionWindowsCoverMiddleAndKeepOffsets(t *testing.T) {
	seen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Content string `json:"content"`
		}
		json.NewDecoder(r.Body).Decode(&p)
		findings := []any{}
		if i := strings.Index(p.Content, "MIDDLE_SECRET"); i >= 0 {
			seen = true
			findings = append(findings, map[string]any{"type": "secret", "category": "test", "severity": "high", "matched_location": fmt.Sprintf("content[%d:%d]", i, i+13)})
		}
		json.NewEncoder(w).Encode(map[string]any{"action": "audit", "inspection_status": "completed", "findings": findings})
	}))
	defer server.Close()
	text := strings.Repeat("a", 50000) + "MIDDLE_SECRET" + strings.Repeat("z", 50000)
	h := &ReverseProxyHandler{client: server.Client(), securityURL: server.URL}
	d, e := h.checkStreamInspection(context.Background(), "windows", text, "", "example.invalid", "/v1/responses")
	if e != nil || !seen || d.SemanticStatus == "incomplete" {
		t.Fatalf("%+v %v", d, e)
	}
	for _, f := range d.Findings {
		if f.MatchedLocation != "content[50000:50013]" {
			t.Fatalf("wrong original offset: %s", f.MatchedLocation)
		}
	}
}

// Optional deployment acceptance: actual running engine, synthetic local upstream,
// in-memory audit sink. Never inserts attack fixtures into the customer database.
func TestStreamingInspectionLiveEngine(t *testing.T) {
	endpoint := os.Getenv("COVERAGE_ENGINE_URL")
	if endpoint == "" {
		t.Skip("live engine acceptance not configured")
	}
	secret := "password=MiddleAcceptance48!qZ"
	metadata := sseJSON(map[string]any{"type": "response.reasoning.delta", "delta": strings.Repeat("x", 300*1024)})
	body := metadata + sseJSON(map[string]any{"type": "response.output_text.delta", "delta": "检查结果：" + secret}) + metadata + "data: [DONE]\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, body)
	}))
	defer upstream.Close()
	audit := &fakeReverseProxyAuditRecorder{}
	h := &ReverseProxyHandler{tenantID: "tenant_default", securityURL: endpoint, internalSecret: os.Getenv("COVERAGE_ENGINE_TOKEN"), client: &http.Client{Timeout: 60 * time.Second}, securityAuditOnlyFallback: true, resolveEgressTarget: testEgressResolver(upstream.URL), auditRecorder: audit, routes: []ReverseProxyRoute{{ID: "test", PathPrefix: "/test", TargetURL: upstream.URL, SecurityEnabled: true, Status: "active"}}}
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/test/v1/responses", strings.NewReader(`{"model":"test","input":"你好"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if !h.ServeHTTP(rec, req) || rec.Code != 200 || rec.Body.String() != body {
		t.Fatal("relay was altered")
	}
	found := false
	for _, event := range audit.securityEvents {
		if event.stage == "output" {
			if event.record.OutputSemanticStatus == "incomplete" {
				t.Fatalf("full projection reported incomplete: %s", event.record.OutputSemanticReason)
			}
			for _, f := range event.findings {
				if f.Category == "plain_password" || f.Category == "code_leak_password_in_code" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("actual engine missed middle credential")
	}
	t.Logf("live engine: %d response bytes relayed exactly; middle credential detected; no capture gap", len(body))
}
