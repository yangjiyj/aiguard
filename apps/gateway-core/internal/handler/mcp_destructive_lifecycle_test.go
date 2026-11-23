package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

func TestBuildMCPDestructiveLifecyclePayloadsOnlyClaimsForwardAfterSuccess(t *testing.T) {
	decision := agentguard.Decision{
		RawDecision:          agentguard.DecisionBlock,
		EffectiveDecision:    agentguard.DecisionAudit,
		Mode:                 agentguard.ModeLight,
		OperationID:          "op-mcp",
		RiskLevel:            "high",
		Confidence:           1,
		EffectiveReason:      "destructive_alert_allow",
		ModeDefaultAction:    agentguard.DestructiveActionAlertAllow,
		CustomAction:         agentguard.DestructiveActionAlertAllow,
		FinalAction:          agentguard.DestructiveActionAlertAllow,
		NotificationRequired: true,
		RiskCategory:         agentguard.DestructiveRiskCategory,
		RiskSubcategory:      "filesystem_delete",
		ReasonSummary:        "deterministic_destructive_operation",
		NormalizedTarget:     "filesystem_delete:1-targets",
	}
	payloads := buildMCPToolAuditPayloads(&mcpToolCallDecision{
		Message:            mcpRPCMessage{ID: json.RawMessage(`9`)},
		Qualified:          "demo__run_shell",
		ArgsJSON:           `{"command":"rm -rf /srv/fixture","token":"top-secret"}`,
		Decision:           decision,
		ExecutionForwarded: true,
		ResultObserved:     true,
		ResultExcerpt:      `{"content":"top-secret full tool result"}`,
		OutcomeStatus:      "success",
	})
	if len(payloads) != 2 {
		t.Fatalf("payload count = %d, want intent and execution risk", len(payloads))
	}
	if payloads[0].EventType != "tool_destructive_intent" || payloads[1].EventType != "tool_execution_risk" {
		t.Fatalf("event types = %q, %q", payloads[0].EventType, payloads[1].EventType)
	}
	if payloads[0].ExecutionForwarded || payloads[0].ResultObserved {
		t.Fatalf("intent asserted later facts: %+v", payloads[0])
	}
	if !payloads[1].ExecutionForwarded || !payloads[1].ExecutionObserved || !payloads[1].ResultObserved {
		t.Fatalf("execution facts missing: %+v", payloads[1])
	}
	for i, payload := range payloads {
		if payload.OperationID != "op-mcp" || payload.Parameters != nil || payload.Result != "" {
			t.Fatalf("payload[%d] correlation/redaction = %+v", i, payload)
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(encoded))
		for _, forbidden := range []string{"top-secret", "/srv/fixture", "full tool result"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("payload[%d] leaked %q: %s", i, forbidden, encoded)
			}
		}
	}
}

func TestBuildMCPDestructiveLifecyclePayloadsBlockedNeverClaimsForward(t *testing.T) {
	decision := agentguard.Decision{
		RawDecision:       agentguard.DecisionBlock,
		EffectiveDecision: agentguard.DecisionBlock,
		Mode:              agentguard.ModeStrict,
		OperationID:       "op-mcp-block",
		FinalAction:       agentguard.DestructiveActionBlock,
		RiskCategory:      agentguard.DestructiveRiskCategory,
		RiskSubcategory:   "filesystem_delete",
	}
	payloads := buildMCPToolAuditPayloads(&mcpToolCallDecision{
		Qualified:     "demo__run_shell",
		Decision:      decision,
		OutcomeStatus: "blocked",
	})
	if len(payloads) != 2 || payloads[1].EventType != "tool_attempt_blocked" {
		t.Fatalf("blocked lifecycle payloads = %+v", payloads)
	}
	for _, payload := range payloads {
		if payload.ExecutionForwarded || payload.ExecutionObserved || payload.ResultObserved {
			t.Fatalf("blocked lifecycle claimed execution: %+v", payload)
		}
	}
}
func TestBuildMCPDestructiveLifecyclePayloadsConfirmIsIntentOnly(t *testing.T) {
	decision := agentguard.Decision{
		RawDecision:          agentguard.DecisionBlock,
		EffectiveDecision:    agentguard.DecisionConfirm,
		Mode:                 agentguard.ModeLight,
		OperationID:          "op-mcp-confirm",
		FinalAction:          agentguard.DestructiveActionConfirm,
		NotificationRequired: true,
		RiskCategory:         agentguard.DestructiveRiskCategory,
		RiskSubcategory:      "filesystem_delete",
	}
	payloads := buildMCPToolAuditPayloads(&mcpToolCallDecision{
		Qualified:     "demo__run_shell",
		Decision:      decision,
		OutcomeStatus: "proposed",
	})
	if len(payloads) != 1 || payloads[0].EventType != "tool_destructive_intent" ||
		payloads[0].FinalAction != "confirm" || payloads[0].Status != "waiting_confirmation" {
		t.Fatalf("confirm must remain a waiting intent: %+v", payloads)
	}
}

func TestBuildMCPDestructiveLifecyclePayloadsTransportFailureKeepsIntentWithoutExecutionFacts(t *testing.T) {
	payloads := buildMCPToolAuditPayloads(&mcpToolCallDecision{
		Qualified: "demo__run_shell",
		Decision: agentguard.Decision{
			EffectiveDecision: agentguard.DecisionAudit,
			FinalAction:       agentguard.DestructiveActionRecord,
			RiskCategory:      agentguard.DestructiveRiskCategory,
		},
		OutcomeStatus: "failed",
	})
	if len(payloads) != 1 || payloads[0].EventType != "tool_destructive_intent" {
		t.Fatalf("transport failure lifecycle = %+v", payloads)
	}
	intent := payloads[0]
	if intent.Status != "failed" || intent.ExecutionForwarded || intent.ExecutionObserved || intent.ResultObserved {
		t.Fatalf("transport failure intent facts = %+v", intent)
	}
}

func TestMCPReconnectKeepsStableOperationAndSeparateRealCalls(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"})
	setMCPDestructivePolicy(env, agentguard.ModeStrict, agentguard.DestructiveActionBlock, "mcp-session-stable")

	call := func(body string) {
		req := newMCPTestRequest(body)
		req.Header.Set("Mcp-Session-Id", "mcp-session-stable")
		req.Header.Set("MCP-Protocol-Version", mcpProtocolVersionLatest)
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, req)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"error"`) {
			t.Fatalf("blocked MCP response status=%d body=%s", w.Code, w.Body.String())
		}
	}
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"rm -rf /srv/isolated-fixture"}}}`
	call(body)
	call(body)
	if len(*env.toolLogs) != 4 {
		t.Fatalf("MCP reconnect lifecycle logs = %#v", *env.toolLogs)
	}
	firstOperation := (*env.toolLogs)[0]["operation_id"]
	for i := 1; i < 4; i++ {
		if (*env.toolLogs)[i]["operation_id"] != firstOperation {
			t.Fatalf("MCP reconnect changed operation id: %#v", *env.toolLogs)
		}
	}
	other := strings.Replace(body, `"id":9`, `"id":10`, 1)
	call(other)
	if len(*env.toolLogs) != 6 || (*env.toolLogs)[4]["operation_id"] == firstOperation ||
		(*env.toolLogs)[4]["operation_id"] != (*env.toolLogs)[5]["operation_id"] {
		t.Fatalf("different MCP call identity collision: %#v", *env.toolLogs)
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("blocked MCP reconnect reached upstream: hits=%d", atomic.LoadInt32(env.upstreamHits))
	}
}
