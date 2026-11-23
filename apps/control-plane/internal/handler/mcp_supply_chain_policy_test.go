package handler

import (
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 2.9.22：控制面不再把供应链发现强改成 strict/block（原期望 action=block、mode=strict），
// 只下发 structural_block 与原因，网关按 mcp.* 防护项和管理员隔离/撤销定动作。
func TestMCPSupplyChainFindingKeepsPolicyAndCarriesReasons(t *testing.T) {
	policy := &repository.MCPPolicy{ID: "allow-all", Mode: "strict", DefaultAction: "allow", ScopeType: "tenant"}
	response := buildMCPEffectivePolicyResponse(policy, repository.MCPSupplyChainResolution{
		Status: "quarantined", Reasons: []string{"mcp_tool_quarantined", "description_poison"},
		Revision: "mcpsc_1", StructuralBlock: true, ToolID: "tool-a",
		ServerStatus: "approved", ToolStatus: "quarantined",
	})
	if response["action"] != "allow" || response["mode"] != "strict" || response["structural_block"] != true {
		t.Fatalf("supply-chain finding must keep the policy action and stay structural: %#v", response)
	}
	if response["policy_id"] != "allow-all" || response["supply_chain_status"] != "quarantined" {
		t.Fatalf("policy/supply evidence lost: %#v", response)
	}
}

func TestMCPApprovedSupplyChainPreservesPolicy(t *testing.T) {
	policy := &repository.MCPPolicy{ID: "allow-one", Mode: "strict", DefaultAction: "allow"}
	response := buildMCPEffectivePolicyResponse(policy, repository.MCPSupplyChainResolution{
		Status: "approved", Revision: "mcpsc_2", ToolID: "tool-a",
		ServerStatus: "approved", ToolStatus: "approved",
	})
	if response["action"] != "allow" || response["structural_block"] != false {
		t.Fatalf("approved snapshot changed policy: %#v", response)
	}
}

func TestMCPPoisonScanBudgetReadsProtectionParam(t *testing.T) {
	if got := mcpPoisonScanBudgetFor(nil); got != mcpPoisonScanBudget {
		t.Fatalf("default budget = %v", got)
	}
	settings := protection.Settings{protection.KeyMCPScanUnavailable: {Action: protection.ActionAlertAllow, Params: map[string]any{"timeout_seconds": 30}}}
	if got := mcpPoisonScanBudgetFor(settings); got != 30*time.Second {
		t.Fatalf("configured budget = %v", got)
	}
}
