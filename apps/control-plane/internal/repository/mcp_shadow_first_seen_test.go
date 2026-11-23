package repository

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 同名不一致只对首次出现的工具比对：B 服务新增同名不同 Schema 的工具时，A 服务上已批准、
// 自身没变的同名工具重同步不被标记。
func TestShadowDivergenceOnlyFlagsFirstSeenToolOnRealPostgres(t *testing.T) {
	pool, tenant, _ := setupMCPSupplyChainTestDB(t)
	ctx := context.Background()
	serverRepo := NewMCPServersRepository(pool)
	repo := NewMCPToolsRepository(pool)
	hashA, hashB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	manifest := strings.Repeat("1", 64)
	syncA := func() {
		if _, err := repo.ApplySupplyChainSync(ctx, MCPSupplyChainSyncInput{
			TenantID: tenant, ServerID: "server-a", ManifestHash: manifest, DescriptionScanComplete: true,
			Tools: []*MCPTool{{ToolName: "read", Description: "read", SchemaHash: hashA}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	createSupplyChainServer(t, serverRepo, tenant, "server-a", "https://a.example/mcp")
	syncA()
	if approved := approveMCPTestSnapshot(t, repo, tenant, "server-a", "read", manifest, "admin"); approved.StructuralBlock {
		t.Fatalf("approved precondition: %+v", approved)
	}
	createSupplyChainServer(t, serverRepo, tenant, "server-b", "https://b.example/mcp")
	shadow, err := repo.ApplySupplyChainSync(ctx, MCPSupplyChainSyncInput{
		TenantID: tenant, ServerID: "server-b", ManifestHash: manifest, DescriptionScanComplete: true,
		Tools: []*MCPTool{{ToolName: "read", Description: "different", SchemaHash: hashB}},
	})
	if err != nil || !containsMCPString(shadow.Reasons, "shadow_schema_diverges") {
		t.Fatalf("the newly seen tool on B must be flagged: %+v err=%v", shadow, err)
	}
	syncA()
	resolved, err := repo.ResolveMCPSupplyChain(ctx, tenant, "server-a", "read")
	if err != nil || resolved.StructuralBlock || containsMCPString(resolved.Reasons, "shadow_schema_diverges") {
		t.Fatalf("A's approved, unchanged tool must not be flagged: %+v err=%v", resolved, err)
	}
}

// 首次出现时被标记同名不一致、仍未准入且 Schema 没变的工具，重同步保留 shadow_schema_diverges；
// 之后把 mcp.shadow_divergence 改成阻断，下次同步对它生效（隔离）。
func TestShadowDivergenceKeptForUnverifiedUnchangedToolOnRealPostgres(t *testing.T) {
	pool, tenant, _ := setupMCPSupplyChainTestDB(t)
	ctx := context.Background()
	serverRepo := NewMCPServersRepository(pool)
	repo := NewMCPToolsRepository(pool)
	hashA, hashB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	manifest := strings.Repeat("1", 64)
	createSupplyChainServer(t, serverRepo, tenant, "server-a", "https://a.example/mcp")
	if _, err := repo.ApplySupplyChainSync(ctx, MCPSupplyChainSyncInput{TenantID: tenant, ServerID: "server-a", ManifestHash: manifest, DescriptionScanComplete: true,
		Tools: []*MCPTool{{ToolName: "read", Description: "read", SchemaHash: hashA}}}); err != nil {
		t.Fatal(err)
	}
	createSupplyChainServer(t, serverRepo, tenant, "server-b", "https://b.example/mcp")
	syncB := func(settings protection.Settings) *MCPSupplyChainSyncResult {
		result, err := repo.ApplySupplyChainSync(ctx, MCPSupplyChainSyncInput{TenantID: tenant, ServerID: "server-b", ManifestHash: manifest, DescriptionScanComplete: true,
			Tools: []*MCPTool{{ToolName: "read", Description: "different", SchemaHash: hashB}}, Protections: settings})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	syncB(nil)
	if again := syncB(nil); again.QuarantinedCount != 0 || !containsMCPString(again.Reasons, "shadow_schema_diverges") {
		t.Fatalf("resync must keep the shadow finding: %+v", again)
	}
	if resolved, _ := repo.ResolveMCPSupplyChain(ctx, tenant, "server-b", "read"); !containsMCPString(resolved.Reasons, "shadow_schema_diverges") {
		t.Fatalf("shadow reason lost after resync: %+v", resolved)
	}
	blocked := syncB(protection.Settings{protection.KeyMCPShadowDivergence: {Action: protection.ActionBlock}})
	if blocked.QuarantinedCount != 1 || !containsMCPString(blocked.Reasons, "shadow_schema_diverges") {
		t.Fatalf("switching mcp.shadow_divergence to block must quarantine it: %+v", blocked)
	}
}
