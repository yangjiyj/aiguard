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

func TestCheckToolRiskWritesDefinitionExposureFact(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/tools/config":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
				t.Fatalf("decode log: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	h := &ChatCompletionsHandler{toolRiskClient: NewToolRiskClient(server.URL, "secret")}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-def", TenantID: "tenant-1"}
	req := &ChatCompletionRequest{Tools: []ToolDef{{
		Type:     "function",
		Function: ToolFunc{Name: "Read", Description: "read a file", Parameters: json.RawMessage(`{"type":"object"}`)},
	}}}
	if err := h.checkToolRisk(context.Background(), envelope, req); err != nil {
		t.Fatalf("check tool risk: %v", err)
	}
	assertJSONField(t, received, "event_kind", "definition_exposed")
	if observed, ok := received["execution_observed"].(bool); !ok || observed {
		t.Fatalf("definition exposure execution_observed = %#v", received["execution_observed"])
	}
	if hash, _ := received["definition_hash"].(string); hash == "" {
		t.Fatalf("definition_hash missing: %#v", received)
	}
}

func TestAgentGuardPayloadWritesInvocationProposalFact(t *testing.T) {
	payload := buildAgentGuardToolAuditPayload(ToolCall{
		ID:       "call-42",
		Type:     "function",
		Function: ToolCallFunc{Name: "WebSearch", Arguments: `{}`},
	}, agentguard.Decision{
		RawDecision:       agentguard.DecisionAllow,
		EffectiveDecision: agentguard.DecisionAllow,
	}, map[string]any{})

	if payload.EventKind != "invocation_proposed" || payload.ExecutionObserved || payload.ResultObserved {
		t.Fatalf("proposal payload = %#v", payload)
	}
	if payload.ToolCallID != "call-42" {
		t.Fatalf("tool_call_id = %q", payload.ToolCallID)
	}
}

func TestMCPAuditPayloadRequiresExplicitForwardEvidence(t *testing.T) {
	blocked := buildMCPToolAuditPayload(&mcpToolCallDecision{
		Message:   mcpRPCMessage{ID: json.RawMessage(`"rpc-block"`)},
		Qualified: "demo__write",
		Decision: agentguard.Decision{
			RawDecision:       agentguard.DecisionConfirm,
			EffectiveDecision: agentguard.DecisionConfirm,
		},
		MCPServerID: "server-1",
	})
	if blocked.ExecutionObserved || blocked.ResultObserved {
		t.Fatalf("blocked/confirm decision must not invent execution or result: %#v", blocked)
	}
	if blocked.EventKind != "invocation_proposed" {
		t.Fatalf("blocked event kind = %q", blocked.EventKind)
	}

	forwarded := buildMCPToolAuditPayload(&mcpToolCallDecision{
		Message:   mcpRPCMessage{ID: json.RawMessage(`"rpc-forward"`)},
		Qualified: "demo__write",
		Decision: agentguard.Decision{
			RawDecision:       agentguard.DecisionAllow,
			EffectiveDecision: agentguard.DecisionAllow,
		},
		MCPServerID:        "server-1",
		ExecutionForwarded: true,
		ResultObserved:     true,
		OutcomeStatus:      "success",
	})
	if forwarded.EventKind != "execution_forwarded" || !forwarded.ExecutionObserved || !forwarded.ResultObserved {
		t.Fatalf("forwarded payload = %#v", forwarded)
	}
	if forwarded.ToolCallID != "string:rpc-forward" || forwarded.MCPServerID != "server-1" {
		t.Fatalf("forwarded correlation = %#v", forwarded)
	}
}

func TestToolResultMessageWritesResultObservationWithoutExecutionClaim(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/tools/logs" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode log: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	h := &ChatCompletionsHandler{toolRiskClient: NewToolRiskClient(server.URL, "secret")}
	h.logToolResultObservations(context.Background(), &modelrouter.RequestEnvelope{
		RequestID: "req-result", TenantID: "tenant-1",
	}, []Message{{Role: "tool", ToolCallID: "call-result-1", Content: json.RawMessage(`"secret body not persisted"`)}})

	assertJSONField(t, received, "event_kind", "result_observed")
	assertJSONField(t, received, "tool_call_id", "call-result-1")
	if observed, ok := received["result_observed"].(bool); !ok || !observed {
		t.Fatalf("result_observed = %#v", received["result_observed"])
	}
	if executed, ok := received["execution_observed"].(bool); !ok || executed {
		t.Fatalf("client result must not claim execution: %#v", received["execution_observed"])
	}
	if result, _ := received["result"].(string); result == "secret body not persisted" {
		t.Fatal("raw tool result must not be copied into lifecycle audit")
	}
}
