package repository

import (
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 已批准工具出现同名不一致：默认保持批准、打标记交给网关按 mcp.shadow_divergence 告警；设为阻断时隔离。
func TestApprovedToolShadowDivergenceIsFlagged(t *testing.T) {
	previous := &mcpToolAdmissionRecord{Status: "approved", SchemaHash: "v1"}
	got := decideMCPToolAdmission(previous, &MCPTool{SchemaHash: "v1"}, true, nil)
	if got.Status != "approved" || got.Reason != "shadow_schema_diverges" {
		t.Fatalf("approved shadow = %+v", got)
	}
	blocked := decideMCPToolAdmission(previous, &MCPTool{SchemaHash: "v1"}, true, protection.Settings{protection.KeyMCPShadowDivergence: {Action: protection.ActionBlock}})
	if blocked.Status != "quarantined" || blocked.Reason != "shadow_schema_diverges" {
		t.Fatalf("shadow_divergence=block = %+v", blocked)
	}
	resolved := resolveMCPSupplyChainState("approved", "", 1, "approved", "shadow_schema_diverges", 2, false, true, "tool-1")
	if !resolved.StructuralBlock || resolved.Status != "approved" || len(resolved.Reasons) != 1 || resolved.Reasons[0] != "shadow_schema_diverges" {
		t.Fatalf("approved finding must reach the gateway: %+v", resolved)
	}
}
