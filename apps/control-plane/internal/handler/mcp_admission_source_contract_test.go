package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpadmission"
)

// 契约（控制面一侧）：准入来源按 admission_reviewed_by 折算后随有效策略下发，与网关一侧用同一组样例。
func TestMCPEffectivePolicyCarriesAdmissionSourceContract(t *testing.T) {
	for _, s := range mcpadmission.ContractSamples {
		supply := repository.WithMCPAdmissionSources(repository.MCPSupplyChainResolution{
			Status: s.Status, StructuralBlock: true, ServerStatus: "approved", ToolStatus: s.Status,
			Reasons: []string{"mcp_tool_" + s.Status, s.Reason},
		}, "user_admin", s.ReviewedBy)
		response := buildMCPEffectivePolicyResponse(nil, supply)
		if response["tool_admission_source"] != mcpadmission.Source(s.ReviewedBy) || response["server_admission_source"] != mcpadmission.SourceAdministrator {
			t.Errorf("%s: sources = %v / %v", s.Name, response["tool_admission_source"], response["server_admission_source"])
		}
	}
}
