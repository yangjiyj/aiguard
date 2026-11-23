package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpadmission"
)

// 租户没有匹配的 MCP 策略（Mode=audit、Action=audit）时，管理员隔离、撤销仍要拦，只受全局观察留痕约束。
func unmatchedStructural(status string, reasons ...string) *MCPEffectivePolicy {
	return &MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit", SupplyChainStatus: status,
		SupplyChainReasons: reasons, SupplyChainRevision: "mcpsc_u", StructuralBlock: true}
}

func TestMCPAdministratorAdmissionBlocksWithoutMatchedPolicy(t *testing.T) {
	for _, policy := range []*MCPEffectivePolicy{
		unmatchedStructural("quarantined", "mcp_tool_quarantined", "manual_quarantine"),
		unmatchedStructural("revoked", "mcp_tool_revoked"),
		unmatchedStructural("quarantined", "mcp_server_quarantined", "manual_quarantine"),
	} {
		d := synthesizeMCPDecisionForTenant(policy, "read", "{}", agentguard.ModeStrict, true, nil, tenantWith(nil))
		if d.EffectiveDecision != agentguard.DecisionBlock || !d.ConfiguredEnforcement {
			t.Fatalf("%v with unmatched policy must block: %+v", policy.SupplyChainReasons, d)
		}
		recorded := synthesizeMCPDecisionForTenant(policy, "read", "{}", agentguard.ModeAudit, true, nil, tenantWith(nil))
		if recorded.EffectiveDecision == agentguard.DecisionBlock {
			t.Fatalf("record mode must not block: %+v", recorded)
		}
	}
}

func TestMCPNonToolTargetServerAdmissionFollowsAdministratorOrItem(t *testing.T) {
	admin := mcpNonToolStructuralPolicy(unmatchedStructural("quarantined", "mcp_server_quarantined", "manual_quarantine", "mcp_tool_unknown"))
	if d := synthesizeMCPDecisionForTenant(admin, "resources/read", "{}", agentguard.ModeStrict, false, nil, tenantWith(nil)); d.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("administrator server quarantine must block non-tool targets: %+v", d)
	}
	// 审查 1：系统隔离以来源为准（原来只看原因码 rug_pull_manifest_changed），这里显式带上 system 来源。
	systemPolicy := unmatchedStructural("quarantined", "mcp_server_quarantined", "rug_pull_manifest_changed", "mcp_tool_unknown")
	systemPolicy.ServerAdmissionSource = mcpadmission.SourceSystem
	system := mcpNonToolStructuralPolicy(systemPolicy)
	if d := synthesizeMCPDecisionForTenant(system, "resources/read", "{}", agentguard.ModeStrict, false, nil, tenantWith(nil)); d.EffectiveDecision == agentguard.DecisionBlock || d.ProtectionItem != "mcp.drift" {
		t.Fatalf("legacy system server quarantine must follow mcp.drift (alert): %+v", d)
	}
}

// 管理员带参数条件的 MCP 策略对未准入、地址/Schema 变化的工具照样生效（2.9.21 由结构阻断兜住）。
func TestMCPArgChainAppliesToStructuralFindings(t *testing.T) {
	chain := []mcpArgChainEntry{{PolicyID: "cond-block", Mode: "strict", Action: "block",
		ArgConditions: []MCPArgCondition{{Path: "$.mode", Op: "eq", Value: []byte(`"rw"`)}}}}
	for _, reasons := range [][]string{{"mcp_server_unverified", "mcp_tool_unverified"}, {"route_binding_mismatch"}} {
		policy := applyMCPArgChain(unmatchedStructural("unverified", reasons...), chain, `{"mode":"rw"}`)
		if policy.Action != "block" || !policy.StructuralBlock {
			t.Fatalf("arg chain must apply to structural findings: %+v", policy)
		}
		if d := synthesizeMCPDecisionForTenant(policy, "write", `{"mode":"rw"}`, agentguard.ModeStrict, true, nil, tenantWith(nil)); d.EffectiveDecision != agentguard.DecisionBlock {
			t.Fatalf("conditional block policy must block an unadmitted tool: %+v", d)
		}
	}
}

// 命中的 MCP 策略为放行时，配成阻断的防护项照拦（两者取严）。
func TestMCPMatchedAllowPolicyDoesNotLoosenBlockedItem(t *testing.T) {
	policy := &MCPEffectivePolicy{Matched: true, PolicyID: "allow", Mode: "strict", Action: "allow",
		SupplyChainStatus: "unverified", SupplyChainReasons: []string{"mcp_tool_unverified"}, StructuralBlock: true}
	if d := synthesizeMCPDecisionForTenant(policy, "read", "{}", agentguard.ModeStrict, true, nil, tenantWith(blockItem("mcp.unadmitted"))); d.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("explicit allow must not loosen mcp.unadmitted=block: %+v", d)
	}
	if d := synthesizeMCPDecisionForTenant(policy, "read", "{}", agentguard.ModeStrict, true, nil, tenantWith(nil)); d.EffectiveDecision == agentguard.DecisionBlock || !mcpDecisionNeedsSecurityEvent(&mcpToolCallDecision{Decision: d}, false) {
		t.Fatalf("explicit allow with default item must alert and allow: %+v", d)
	}
}

// 批准后重放：fallback 只处置“环境变化/策略拉不到”这一项，别的阻断结论照拦。
func TestMCPReplayFallbackNeverLoosensOtherBlocks(t *testing.T) {
	blocked := agentguard.Decision{RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionBlock, ConfiguredEnforcement: true}
	if got, _ := mcpProtectionFallback(blocked, "policy_runtime_unavailable", tenantWith(nil), "read", false); got.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("fallback downgraded an AgentGuard block: %+v", got)
	}
	if mcpReplayDriftTolerable(unmatchedStructural("revoked", "mcp_tool_revoked"), agentguard.Decision{EffectiveDecision: agentguard.DecisionAudit}) {
		t.Fatal("administrator revoke is not an environment change")
	}
	if mcpReplayDriftTolerable(unmatchedStructural("quarantined", "mcp_server_quarantined", "manual_quarantine"), agentguard.Decision{EffectiveDecision: agentguard.DecisionAudit}) {
		t.Fatal("administrator quarantine is not an environment change")
	}
	if mcpReplayDriftTolerable(approvedPolicyForReplay(), blocked) {
		t.Fatal("a configured block conclusion must keep blocking")
	}
	if !mcpReplayDriftTolerable(unmatchedStructural("quarantined", "route_binding_mismatch"), agentguard.Decision{EffectiveDecision: agentguard.DecisionAudit}) {
		t.Fatal("a pure environment change is left to mcp.replay_changed")
	}
}

func approvedPolicyForReplay() *MCPEffectivePolicy {
	return &MCPEffectivePolicy{Matched: true, Mode: "strict", Action: "confirm", SupplyChainStatus: "approved"}
}
