package handler

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestMCPPolicyFailModeEnforcesAndRecordsGap(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"status","arguments":{"value":"hello"}}}`
	for _, tc := range []struct {
		name, mode           string
		auditOnly, wantBlock bool
	}{
		{"closed", "closed", false, true},
		{"open", "open", false, false},
		{"closed audit lock", "closed", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MCP_POLICY_FAIL_MODE", tc.mode)
			env := newWS1Env(t, tc.auditOnly, blockTool("__none__"))
			env.handler.toolRiskClient.SetMCPPolicyFailMode(tc.mode)
			env.policyStatus = http.StatusServiceUnavailable
			w := env.post(t, body)
			blocked := rpcErrorCode(t, w.Body.String()) == -32000
			if blocked != tc.wantBlock {
				t.Fatalf("mode=%s audit=%v got=%s wantBlock=%v", tc.mode, tc.auditOnly, w.Body.String(), tc.wantBlock)
			}
			wantHits := int32(1)
			if tc.wantBlock {
				wantHits = 0
			}
			if got := atomic.LoadInt32(env.upstreamHits); got != wantHits {
				t.Fatalf("upstream hits=%d want=%d", got, wantHits)
			}
			if !ws1LogsContain(env, "mcp_policy_unavailable") {
				t.Fatalf("policy failure must record coverage gap: %+v", env.logs())
			}
		})
	}
}

func TestMCPPolicyClosedRejectsStaleApproval(t *testing.T) {
	env := newWS1Env(t, false, blockTool("__none__"))
	client := env.handler.toolRiskClient
	client.SetMCPPolicyFailMode("closed")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant_a"}
	key := mcpTargetPolicyCacheKey(envelope, "mcp_srv1", mcpTargetTool, "status")
	client.mcpPolicyCache.rememberLastKnownGood(key, &MCPEffectivePolicy{Mode: "strict", Action: "allow"})
	env.policyStatus = http.StatusServiceUnavailable
	policy := client.GetMCPEffectivePolicy(context.Background(), envelope, "mcp_srv1", "status")
	decision := synthesizeMCPDecision(policy, "status", `{}`, agentguard.ModeStrict)
	if decision.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("closed must reject failed refresh even with stale approval: %+v", decision)
	}
	if !strings.Contains(decision.Reason, "mcp_policy_unavailable") {
		t.Fatalf("failed policy reason missing: %+v", decision)
	}
}

func TestMCPPolicyFailurePreservesLastKnownBlockWhenOpen(t *testing.T) {
	policy := &MCPEffectivePolicy{policyUnavailable: true, policyFailClosed: false}
	decision := applyMCPPolicyFailureDecision(policy, agentguard.Decision{
		RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionBlock,
		ConfiguredEnforcement: true, Reason: "administrator_block",
	}, agentguard.ModeStrict)
	if decision.EffectiveDecision != agentguard.DecisionBlock || decision.Reason != "administrator_block" {
		t.Fatalf("fail-open must retain administrator block: %+v", decision)
	}
	if len(decision.Evidence) != 1 || decision.Evidence[0].Category != "coverage_gap" {
		t.Fatalf("failed refresh must retain coverage evidence: %+v", decision)
	}
}
