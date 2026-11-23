package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mcpAuditLogByEventType(t *testing.T, logs []map[string]any, id, eventType string) map[string]any {
	t.Helper()
	for _, log := range logs {
		if log["tool_call_id"] == id && log["event_type"] == eventType {
			return log
		}
	}
	t.Fatalf("missing MCP audit for call id %q and event type %q: %#v", id, eventType, logs)
	return nil
}

func mcpExecutionAuditLogByCallID(t *testing.T, logs []map[string]any, id string) map[string]any {
	t.Helper()
	return mcpAuditLogByEventType(t, logs, id, "tool_execution_risk")
}

func TestMCPSingleResultCorrelatesByIDAndRedactsExcerpt(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})
	secret := "sk-" + strings.Repeat("a", 16)
	response, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      9,
		"result":  map[string]any{"text": secret + " " + strings.Repeat("x", 3000)},
	})
	if err != nil {
		t.Fatal(err)
	}
	*env.upstreamBody = string(response)

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))

	log := mcpExecutionAuditLogByCallID(t, *env.toolLogs, "number:9")
	if log["execution_observed"] != true || log["result_observed"] != true {
		t.Fatalf("matching result facts=%#v", log)
	}
	if result, _ := log["result"].(string); result != "" {
		t.Fatalf("destructive lifecycle must not persist tool result: %q", result)
	}
}

func TestMCPResultExcerptRedactsNestedSecretsTokensAndPII(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})
	githubToken := "ghp_" + strings.Repeat("a", 36)
	jwt := strings.Join([]string{
		"eyJhbGciOiJIUzI1NiJ9",
		"eyJzdWIiOiJ1c2VyLTEifQ",
		"dGhpcy1pcy1hLXNpZ25hdHVyZQ",
	}, ".")
	password := "plain-password-must-not-survive"
	response, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      9,
		"result": map[string]any{
			"nested": map[string]any{
				"password":      password,
				"client_secret": "plain-client-secret",
				"safe":          githubToken + " " + jwt,
			},
			"email": "alice@example.com",
			"phone": "13800138000",
			"id":    "11010519491231002X",
			"bank":  "6222021234567890123",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	*env.upstreamBody = string(response)

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))

	log := mcpExecutionAuditLogByCallID(t, *env.toolLogs, "number:9")
	excerpt, _ := log["result"].(string)
	for _, leaked := range []string{password, "plain-client-secret", githubToken, jwt, "alice@example.com", "13800138000", "11010519491231002X", "6222021234567890123"} {
		if strings.Contains(excerpt, leaked) {
			t.Fatalf("result excerpt leaked %q: %s", leaked, excerpt)
		}
	}
	if excerpt != "" {
		t.Fatalf("destructive lifecycle must not persist sanitized tool result: %q", excerpt)
	}
}

func TestMCPErrorResponseDoesNotCountAsResult(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})
	*env.upstreamBody = `{"jsonrpc":"2.0","id":9,"error":{"code":-32001,"message":"failed"}}`
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))
	log := mcpExecutionAuditLogByCallID(t, *env.toolLogs, "number:9")
	if log["execution_observed"] != true || log["result_observed"] != false {
		t.Fatalf("JSON-RPC error facts=%#v", log)
	}
}

func TestMCPWrongResponseIDDoesNotCountAsResult(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})
	*env.upstreamBody = `{"jsonrpc":"2.0","id":10,"result":{"text":"wrong"}}`
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))
	if log := mcpExecutionAuditLogByCallID(t, *env.toolLogs, "number:9"); log["result_observed"] != false {
		t.Fatalf("wrong-id response facts=%#v", log)
	}
}

func TestMCPResponseIDTypeMustMatch(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})
	*env.upstreamBody = `{"jsonrpc":"2.0","id":"9","result":{"text":"wrong type"}}`
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))
	if log := mcpExecutionAuditLogByCallID(t, *env.toolLogs, "number:9"); log["result_observed"] != false {
		t.Fatalf("wrong-type response facts=%#v", log)
	}
}

func TestMCPNonJSONResponseDoesNotCountAsResult(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})
	*env.upstreamContentType = "text/plain"
	*env.upstreamBody = "upstream accepted"
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))
	if log := mcpExecutionAuditLogByCallID(t, *env.toolLogs, "number:9"); log["result_observed"] != false {
		t.Fatalf("non-JSON response facts=%#v", log)
	}
}

func TestMCPSSEDataResultCorrelatesByID(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})
	*env.upstreamContentType = "text/event-stream"
	*env.upstreamBody = ": keepalive\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"text\":\"streamed\"}}\n\n"
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))
	log := mcpExecutionAuditLogByCallID(t, *env.toolLogs, "number:9")
	if log["execution_observed"] != true || log["result_observed"] != true {
		t.Fatalf("SSE result facts=%#v", log)
	}
	if result, _ := log["result"].(string); result != "" {
		t.Fatalf("destructive lifecycle must not persist SSE tool result: %q", result)
	}
}

func TestMCPSSEKeepaliveDoesNotCountAsResult(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})
	*env.upstreamContentType = "text/event-stream"
	*env.upstreamBody = ": keepalive\n\nevent: ping\ndata: {}\n\n"
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if log := mcpExecutionAuditLogByCallID(t, *env.toolLogs, "number:9"); log["result_observed"] != false {
		t.Fatalf("SSE keepalive facts=%#v", log)
	}
}

func TestMCPBatchResponseIsRejected(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})
	*env.upstreamBody = `[
		{"jsonrpc":"2.0","id":9,"result":{"text":"first"}},
		{"jsonrpc":"2.0","id":9,"result":{"text":"second"}}
	]`
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("现代 MCP batch 响应必须拒绝: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMCPRequestShapedPayloadAndNullIDStayUnattributed(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})
	*env.upstreamBody = `{"jsonrpc":"2.0","id":9,"method":"tools/list","result":{"text":"not a response"}}`
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(mcpToolsCallBody))
	if log := mcpExecutionAuditLogByCallID(t, *env.toolLogs, "number:9"); log["result_observed"] != false {
		t.Fatalf("request-shaped payload facts=%#v", log)
	}
	if key, ok := mcpRPCIDKey(json.RawMessage("null")); ok || key != "" {
		t.Fatalf("null id key=(%q,%v), want unattributed", key, ok)
	}
}
