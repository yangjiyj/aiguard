package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpadmission"
)

// 契约（网关一侧）：管理员隔离、撤销按来源照拦，不看原因文字；系统隔离按 mcp.* 防护项（默认告警放行）。
func TestMCPAdministratorAdmissionFollowsSourceContract(t *testing.T) {
	for _, s := range mcpadmission.ContractSamples {
		policy := unmatchedStructural(s.Status, "mcp_tool_"+s.Status, s.Reason)
		policy.ToolAdmissionSource = mcpadmission.Source(s.ReviewedBy)
		d := synthesizeMCPDecisionForTenant(policy, "read", "{}", agentguard.ModeStrict, true, nil, tenantWith(nil))
		if blocked := d.EffectiveDecision == agentguard.DecisionBlock; blocked != s.WantAdministrator {
			t.Errorf("%s: blocked=%v want %v", s.Name, blocked, s.WantAdministrator)
		}
		set := &mcpApprovedToolSet{ServerApproved: true, ServerStatus: "approved", Tools: map[string]mcpApprovedTool{
			"read": {Status: s.Status, Reason: s.Reason, Source: mcpadmission.Source(s.ReviewedBy)},
		}}
		_, reasons := judgeMCPListedTool([]byte(`{"name":"read","description":"r","inputSchema":{"type":"object"}}`), set)
		if admin := len(reasons) == 1 && reasons[0] == mcpToolsListDropAdministrator; admin != s.WantAdministrator {
			t.Errorf("%s tools/list: reasons=%v want administrator=%v", s.Name, reasons, s.WantAdministrator)
		}
	}
	server := unmatchedStructural("quarantined", "mcp_server_quarantined", "route_binding_changed")
	server.ServerAdmissionSource = mcpadmission.SourceAdministrator
	if d := synthesizeMCPDecisionForTenant(mcpNonToolStructuralPolicy(server), "resources/read", "{}", agentguard.ModeStrict, false, nil, tenantWith(nil)); d.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("administrator server quarantine with a system-looking reason must block non-tool targets: %+v", d)
	}
}
