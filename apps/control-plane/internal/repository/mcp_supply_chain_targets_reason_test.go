package repository

import "testing"

// 非工具目标继承服务级结论时，要带上服务自己的隔离原因：网关据此区分管理员隔离和系统发现。
func TestMCPServerLevelSupplyChainCarriesServerReason(t *testing.T) {
	got := MCPServerLevelSupplyChain(MCPSupplyChainResolution{
		Status: "unknown", StructuralBlock: true, Reasons: []string{"mcp_tool_unknown"},
		ServerStatus: "quarantined", ServerReason: "rug_pull_manifest_changed",
	})
	if !got.StructuralBlock || len(got.Reasons) != 2 || got.Reasons[0] != "mcp_server_quarantined" || got.Reasons[1] != "rug_pull_manifest_changed" {
		t.Fatalf("server-level resolution = %+v", got)
	}
	revoked := MCPServerLevelSupplyChain(MCPSupplyChainResolution{ServerStatus: "revoked", ServerReason: "manual_revoked", Reasons: []string{"mcp_server_revoked", "manual_revoked"}, StructuralBlock: true})
	if len(revoked.Reasons) != 2 || revoked.Reasons[0] != "mcp_server_revoked" {
		t.Fatalf("revoked = %+v", revoked)
	}
}
