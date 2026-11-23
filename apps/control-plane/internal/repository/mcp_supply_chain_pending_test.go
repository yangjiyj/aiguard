package repository

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestMCPSupplyChainHardeningFirstSyncAwaitsAdministrator(t *testing.T) {
	if os.Getenv("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL") == "" {
		t.Fatal("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL is required; use disposable PostgreSQL")
	}
	pool, tenant, _ := setupMCPSupplyChainTestDB(t)
	repo := NewMCPToolsRepository(pool)
	createSupplyChainServer(t, NewMCPServersRepository(pool), tenant, "pending-server", "https://mcp.example/rpc")
	ctx := context.Background()
	input := MCPSupplyChainSyncInput{TenantID: tenant, ServerID: "pending-server", ManifestHash: strings.Repeat("a", 64), DescriptionScanComplete: true, Tools: []*MCPTool{{ToolName: "read", SchemaHash: strings.Repeat("b", 64), InputSchema: map[string]interface{}{"type": "object"}}}}
	for i := 0; i < 2; i++ {
		result, err := repo.ApplySupplyChainSync(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if result.ServerStatus != "unverified" || result.ApprovedCount != 0 {
			t.Fatalf("sync %d auto-approved: %+v", i, result)
		}
		var serverStatus, serverReason, manifest, route, reviewer, toolStatus, toolHash, toolReviewer string
		if err := pool.QueryRow(ctx, `SELECT s.admission_status,s.quarantine_reason,s.approved_manifest_hash,s.approved_route_hash,s.admission_reviewed_by,t.admission_status,t.approved_schema_hash,t.admission_reviewed_by FROM mcp_servers s JOIN mcp_tools t ON t.server_id=s.id WHERE s.id='pending-server'`).Scan(&serverStatus, &serverReason, &manifest, &route, &reviewer, &toolStatus, &toolHash, &toolReviewer); err != nil {
			t.Fatal(err)
		}
		if serverStatus != "unverified" || toolStatus != "unverified" || serverReason != "pending_administrator_review" || manifest != "" || route != "" || reviewer != "" || toolHash != "" || toolReviewer != "" {
			t.Fatalf("sync approved identities before review: server=%s/%s manifest=%s route=%s reviewer=%s tool=%s hash=%s reviewer=%s", serverStatus, serverReason, manifest, route, reviewer, toolStatus, toolHash, toolReviewer)
		}
		resolution, err := repo.ResolveMCPSupplyChain(ctx, tenant, "pending-server", "read")
		if err != nil || !resolution.StructuralBlock {
			t.Fatalf("pending tool callable: %+v %v", resolution, err)
		}
	}
}
