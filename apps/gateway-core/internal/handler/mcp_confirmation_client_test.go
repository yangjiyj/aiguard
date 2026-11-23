package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestCreateMCPConfirmationKeepsArgumentsInsideReplayContext(t *testing.T) {
	var captured map[string]json.RawMessage
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/agentguard/confirmations" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"confirmation_id":"agcf-test","invocation_id":"mcpinv-test","status":"pending","execution_status":"pending"}`))
	}))
	defer cp.Close()

	client := NewToolRiskClient(cp.URL, "internal")
	envelope := &modelrouter.RequestEnvelope{
		TenantID: "tenant-a", ProjectID: "project-a", UserID: "user-a",
		ClientID: "key-a", KeyPrefix: "sk-a", AgentType: "claude-code",
		SessionID: "agent-session-a", RequestID: "req-a", TraceID: "trace-a",
		SourceIP: "203.0.113.8",
	}
	decision := agentguard.Decision{RawDecision: agentguard.DecisionConfirm, EffectiveDecision: agentguard.DecisionConfirm, OperationID: "op-client-original"}
	body := []byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"write","arguments":{"secret":"never-plain"}}}`)
	if _, err := client.CreateMCPConfirmation(context.Background(), envelope, decision,
		"server-a", "demo__write", "write", "number:9", "tool-a", "revision-a", strings.Repeat("a", 64), strings.Repeat("b", 64), body, mcpProtocolVersionLatest, "mcp-session-a"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, ok := captured["tool_call_arguments"]; ok {
		t.Fatal("plaintext tool_call_arguments was sent")
	}
	var replay struct {
		TenantID     string          `json:"tenant_id"`
		ServerID     string          `json:"server_id"`
		ToolName     string          `json:"tool_name"`
		RequestBody  json.RawMessage `json:"request_body"`
		OperationID  string          `json:"operation_id"`
		MCPSessionID string          `json:"mcp_session_id"`
	}
	if err := json.Unmarshal(captured["mcp_replay_context"], &replay); err != nil {
		t.Fatal(err)
	}
	if replay.TenantID != "tenant-a" || replay.ServerID != "server-a" || replay.ToolName != "write" ||
		replay.MCPSessionID != "mcp-session-a" || replay.OperationID != "op-client-original" ||
		string(replay.RequestBody) != string(body) {
		t.Fatalf("replay=%+v body=%s", replay, replay.RequestBody)
	}
}
