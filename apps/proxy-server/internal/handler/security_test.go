package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestParseResponse_ExtractsAction(t *testing.T) {
	s := &SecurityClient{}

	tests := []struct {
		resp map[string]interface{}
		want string
	}{
		{map[string]interface{}{"action": "audit"}, "audit"},
		{map[string]interface{}{"action": "block"}, "block"},
		{map[string]interface{}{"action": "pass"}, "pass"},
		{map[string]interface{}{}, "audit"},              // default
		{map[string]interface{}{"action": nil}, "audit"}, // nil action
	}

	for _, tt := range tests {
		action, _ := s.parseResponse(tt.resp)
		if action != tt.want {
			t.Errorf("parseResponse action = %s, want %s", action, tt.want)
		}
	}
}

func TestParseResponse_ExtractsFindings(t *testing.T) {
	s := &SecurityClient{}

	resp := map[string]interface{}{
		"action": "audit",
		"findings": []interface{}{
			map[string]interface{}{"type": "pii", "severity": "high"},
			map[string]interface{}{"type": "sensitive", "severity": "medium"},
		},
	}

	action, findings := s.parseResponse(resp)
	if action != "audit" {
		t.Errorf("action = %s, want audit", action)
	}
	if len(findings) != 2 {
		t.Errorf("findings count = %d, want 2", len(findings))
	}
	if findings[0]["type"] != "pii" {
		t.Errorf("first finding type = %v, want pii", findings[0]["type"])
	}
}

func TestParseResponse_EmptyFindings(t *testing.T) {
	s := &SecurityClient{}

	resp := map[string]interface{}{
		"action": "pass",
	}

	action, findings := s.parseResponse(resp)
	if action != "pass" {
		t.Errorf("action = %s, want pass", action)
	}
	if len(findings) != 0 {
		t.Errorf("findings count = %d, want 0", len(findings))
	}
}

func TestParseResponse_MalformedFindings(t *testing.T) {
	s := &SecurityClient{}

	resp := map[string]interface{}{
		"action": "audit",
		"findings": []interface{}{
			"not a map", // malformed
			map[string]interface{}{"type": "valid"},
		},
	}

	action, findings := s.parseResponse(resp)
	if action != "audit" {
		t.Errorf("action = %s, want audit", action)
	}
	// Should only have the valid finding
	if len(findings) != 1 {
		t.Errorf("findings count = %d, want 1 (malformed filtered)", len(findings))
	}
}

func TestPostJSON_SerializesPayload(t *testing.T) {
	// This is a unit test for the serialization logic
	// We can't test the actual HTTP call without mocking

	payload := map[string]interface{}{
		"tenant_id": "tenant_001",
		"text":      "test content",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Verify it's valid JSON
	var decoded map[string]interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded["tenant_id"] != "tenant_001" {
		t.Errorf("tenant_id = %v, want tenant_001", decoded["tenant_id"])
	}
	if decoded["text"] != "test content" {
		t.Errorf("text = %v, want test content", decoded["text"])
	}
}

func TestCheckInputUsesSecurityEngineDashPath(t *testing.T) {
	seenPath := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		if seenPath != "/check-input/" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"action":"block","findings":[{"type":"secret"}]}`))
	}))
	defer server.Close()

	s := NewSecurityClient(server.URL)
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", strings.NewReader(`{"messages":[{"content":"sk-test"}]}`))

	action, findings, _ := s.CheckInput(req.Context(), "tenant_default", "test-req", req)
	if action != "block" {
		t.Fatalf("action = %s, want block; path seen %s", action, seenPath)
	}
	if len(findings) != 1 {
		t.Fatalf("findings len = %d, want 1", len(findings))
	}
}

// capturePayloadSecuritySrv 起一个恒返回 audit 的 security-engine 桩,并把收到的
// 请求载荷解析进 payload,供断言 context 字段。
func capturePayloadSecuritySrv(t *testing.T, payload *map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read engine payload: %v", err)
		}
		if err := json.Unmarshal(body, payload); err != nil {
			t.Errorf("unmarshal engine payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"action":"audit","findings":[]}`))
	}))
}

func payloadContext(t *testing.T, payload map[string]interface{}) map[string]interface{} {
	t.Helper()
	ctxMap, ok := payload["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("payload context missing or not object: %v", payload["context"])
	}
	return ctxMap
}

func TestCheckInputContextCarriesAccessTypeAndProduct(t *testing.T) {
	var payload map[string]interface{}
	server := capturePayloadSecuritySrv(t, &payload)
	defer server.Close()

	s := NewSecurityClient(server.URL)
	req := httptest.NewRequest(http.MethodPost, "https://api.individual.githubcopilot.com/responses", strings.NewReader(`{"input":"hello"}`))

	action, _, _ := s.CheckInput(req.Context(), "tenant_default", "test-req", req)
	if action != "audit" {
		t.Fatalf("action = %s, want audit", action)
	}

	ctxMap := payloadContext(t, payload)
	if ctxMap["access_type"] != "ai_ide" {
		t.Fatalf("context access_type = %v, want ai_ide", ctxMap["access_type"])
	}
	if ctxMap["product"] != "github_copilot" {
		t.Fatalf("context product = %v, want github_copilot", ctxMap["product"])
	}
	if ctxMap["endpoint_kind"] != "chat" {
		t.Fatalf("context endpoint_kind = %v, want chat", ctxMap["endpoint_kind"])
	}
	if ctxMap["provider"] != "github" {
		t.Fatalf("context provider = %v, want github", ctxMap["provider"])
	}
}

func TestForwardProxyPrincipalIgnoresSpoofedIdentityHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", nil)
	req.Header.Set("X-User-ID", "attacker")
	req.Header.Set("X-Department-ID", "dept-attacker")
	ctx := forwardProxyPrincipal("tenant-a", LLMProviderMatch{Provider: "openai"})
	if ctx == nil {
		t.Fatal("forward proxy principal missing")
	}
	if ctx.TrustLevel != "unknown" || ctx.ActorUserID != "" || ctx.KeyOwnerUserID != "" {
		t.Fatalf("untrusted headers influenced principal: %+v", ctx)
	}
	if ctx.TenantID != "tenant-a" || ctx.Protocol != "openai" || ctx.EntryPoint != "forward_proxy" {
		t.Fatalf("trusted proxy context missing: %+v", ctx)
	}
}

func TestCheckOutputContextCarriesEndpointContext(t *testing.T) {
	var payload map[string]interface{}
	server := capturePayloadSecuritySrv(t, &payload)
	defer server.Close()

	s := NewSecurityClient(server.URL)
	match := detectLLMProvider("api.individual.githubcopilot.com", "/responses")

	action, _ := s.CheckOutput(context.Background(), "tenant_default", match, []byte(`{"output":"hi"}`), "application/json")
	if action != "audit" {
		t.Fatalf("action = %s, want audit", action)
	}

	ctxMap := payloadContext(t, payload)
	if ctxMap["tenant_id"] != "tenant_default" {
		t.Fatalf("context tenant_id = %v, want tenant_default", ctxMap["tenant_id"])
	}
	if ctxMap["source"] != "forward_proxy" {
		t.Fatalf("context source = %v, want forward_proxy", ctxMap["source"])
	}
	if ctxMap["endpoint_kind"] != "chat" {
		t.Fatalf("context endpoint_kind = %v, want chat", ctxMap["endpoint_kind"])
	}
	if ctxMap["access_type"] != "ai_ide" {
		t.Fatalf("context access_type = %v, want ai_ide", ctxMap["access_type"])
	}
	if ctxMap["product"] != "github_copilot" {
		t.Fatalf("context product = %v, want github_copilot", ctxMap["product"])
	}
	if ctxMap["provider"] != "github" {
		t.Fatalf("context provider = %v, want github", ctxMap["provider"])
	}
}

func TestCheckOutputAuditOnlyDowngradesEnforcementActions(t *testing.T) {
	for _, engineAction := range []string{"block", "reply"} {
		t.Run(engineAction, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", "true")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"action":"` + engineAction + `","findings":[{"type":"pii","action":"` + engineAction + `"}]}`))
			}))
			defer server.Close()

			action, findings := NewSecurityClient(server.URL).CheckOutput(
				context.Background(), "tenant_default", detectLLMProvider("api.openai.com", "/v1/chat/completions"), []byte(`{"output":"secret"}`), "application/json",
			)

			if action != "audit" {
				t.Fatalf("audit-only output %s must be recorded as audit, got %q", engineAction, action)
			}
			if len(findings) != 1 || findings[0]["type"] != "pii" {
				t.Fatalf("audit-only output must retain engine findings, got %+v", findings)
			}
		})
	}
}

func TestSecurityClientSendsInternalSecretHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := (func() string {
			if legacy := r.Header.Get("X-NewAPI-Internal-Token"); legacy != "" {
				t.Errorf("legacy internal token header must be absent")
			}
			return r.Header.Get("X-JJDGuard-Internal-Token")
		})(); got != "secret-token" {
			t.Fatalf("internal token header = %q, want secret-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"action":"audit","findings":[]}`))
	}))
	defer server.Close()

	s := NewSecurityClientWithSecret(server.URL, "secret-token")
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", strings.NewReader(`{"messages":[{"content":"hello"}]}`))

	action, _, _ := s.CheckInput(req.Context(), "tenant_default", "test-req", req)
	if action != "audit" {
		t.Fatalf("action = %s, want audit", action)
	}
}

func TestCheckInputUsesCatalogDecoderForAnthropicMessages(t *testing.T) {
	captured := make(chan map[string]interface{}, 32)
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		_ = json.Unmarshal(raw, &payload)
		captured <- payload
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"audit","findings":[]}`))
	}))
	defer engine.Close()

	body, err := os.ReadFile("testdata/claude-code-v1-messages.req")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	s := NewSecurityClient(engine.URL).WithInspectionScope(fullInspectionPolicy())
	action, _, _ := s.CheckInput(req.Context(), "tenant_default", "test-req", req)
	if action != "audit" {
		t.Fatalf("action = %q", action)
	}
	close(captured)
	sources := map[string]string{}
	for payload := range captured {
		source, _ := payload["content_source"].(string)
		content, _ := payload["content"].(string)
		sources[source] += content
	}
	if !strings.Contains(sources["user"], "GWTEST-P1C-0705-CC-02") || sources["system_prompt"] == "" || sources["tool_result"] == "" {
		t.Fatalf("protocol sources lost: %#v", sources)
	}
	if strings.Contains(sources["user"], "You are Claude Code") {
		t.Fatal("source projections mixed")
	}

}

func TestCheckInputSecurityProjectionSkipsSystemAndToolDefinitions(t *testing.T) {
	var payload map[string]interface{}
	server := capturePayloadSecuritySrv(t, &payload)
	defer server.Close()

	body := `{"model":"claude-sonnet-4-5","system":"平台密钥 sk-platform-example-1234567890 不应触发客户 DLP","tools":[{"name":"Bash","description":"内置示例 AKIAIOSFODNN7EXAMPLE"}],"messages":[{"role":"user","content":"请检查这份配置"}]}`
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	if action, _, _ := NewSecurityClient(server.URL).CheckInput(req.Context(), "tenant_default", "req-source-aware", req); action != "audit" {
		t.Fatalf("unexpected action: %q", action)
	}
	content, _ := payload["content"].(string)
	if content != "请检查这份配置" {
		t.Fatalf("security projection = %q, want only user message", content)
	}
}
