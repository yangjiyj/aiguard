package repository

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpadmission"
)

// 审查 1：处置来源按 admission_reviewed_by 读出。管理员手动隔离时原因写成系统发现的文字，仍是管理员；
// reviewed_by='system'（同步、旧触发器写入）是系统。
func TestResolveMCPSupplyChainCarriesAdmissionSourceOnRealPostgres(t *testing.T) {
	pool, tenantA, _ := setupMCPSupplyChainTestDB(t)
	ctx := context.Background()
	serverRepo := NewMCPServersRepository(pool)
	repo := NewMCPToolsRepository(pool)
	hash := strings.Repeat("c", 64)
	createSupplyChainServer(t, serverRepo, tenantA, "server-src", "https://src.example/mcp")
	if _, err := repo.ApplySupplyChainSync(ctx, MCPSupplyChainSyncInput{
		TenantID: tenantA, ServerID: "server-src", ManifestHash: strings.Repeat("3", 64),
		ManifestSnapshot: []byte(`[{"name":"read"}]`), DescriptionScanComplete: true,
		Tools: []*MCPTool{{ToolName: "read", Description: "read metadata", InputSchema: map[string]any{"type": "object"}, SchemaHash: hash}},
	}); err != nil {
		t.Fatal(err)
	}
	resolved, err := repo.ResolveMCPSupplyChain(ctx, tenantA, "server-src", "read")
	if err != nil || resolved.ToolID == "" {
		t.Fatalf("resolve: %+v err=%v", resolved, err)
	}
	if _, err := repo.SetMCPToolAdmission(ctx, tenantA, resolved.ToolID, "quarantined", hash, "route_binding_changed", "admin-a"); err != nil {
		t.Fatal(err)
	}
	admin, err := repo.ResolveMCPSupplyChain(ctx, tenantA, "server-src", "read")
	if err != nil || admin.ToolStatus != "quarantined" || admin.ToolAdmissionSource != mcpadmission.SourceAdministrator {
		t.Fatalf("administrator quarantine with a system-looking reason: %+v err=%v", admin, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE mcp_tools SET quarantine_reason='description_poison', admission_reviewed_by='system' WHERE tenant_id=$1 AND id=$2`, tenantA, resolved.ToolID); err != nil {
		t.Fatal(err)
	}
	system, err := repo.ResolveMCPSupplyChain(ctx, tenantA, "server-src", "read")
	if err != nil || system.ToolAdmissionSource != mcpadmission.SourceSystem {
		t.Fatalf("system quarantine: %+v err=%v", system, err)
	}
	if server := MCPServerLevelSupplyChain(system); server.ToolAdmissionSource != "" {
		t.Fatalf("server-level resolution must not carry the tool source: %+v", server)
	}
}
