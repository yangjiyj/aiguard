package repository

// W1 1.2 真库测试：迁移 860 target_kind 列 + 按类别解析。需要全量迁移后的库。

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func ws1MigratedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	var present bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name='mcp_policies' AND column_name='target_kind')`).Scan(&present); err != nil || !present {
		t.Fatalf("迁移 860 未生效：mcp_policies.target_kind 不存在 (err=%v)", err)
	}
	return pool
}

func TestWS1MCPPolicyTargetKindOnRealPostgres(t *testing.T) {
	pool := ws1MigratedPool(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("ws1t%d", time.Now().UnixNano()%1_000_000_000)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, tenant); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM mcp_policies WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant)
	})
	repo := NewMCPPoliciesRepository(pool)

	legacy := &MCPPolicy{TenantID: tenant, ToolPattern: "*", Mode: "strict", DefaultAction: "block", Enabled: true}
	if err := repo.Create(ctx, legacy); err != nil {
		t.Fatalf("create legacy: %v", err)
	}
	if legacy.TargetKind != "tool" {
		t.Fatalf("缺省类别应为 tool: %q", legacy.TargetKind)
	}
	resource := &MCPPolicy{TenantID: tenant, TargetKind: "resource", ToolPattern: "file:///etc/shadow", Mode: "strict", DefaultAction: "block", Enabled: true}
	if err := repo.Create(ctx, resource); err != nil {
		t.Fatalf("create resource: %v", err)
	}
	if err := repo.Create(ctx, &MCPPolicy{TenantID: tenant, TargetKind: "bogus", Enabled: true}); err == nil {
		t.Fatal("非法 target_kind 应拒绝")
	}
	// 绕过仓储直写非法值，应被 CHECK 约束拒绝。
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_policies(id,tenant_id,target_kind) VALUES ('ws1bad',$1,'Tool')`, tenant); err == nil {
		t.Fatal("CHECK 约束应拒绝大小写变体 'Tool'")
	}

	policies, err := repo.ListByTenant(ctx, tenant, "")
	if err != nil || len(policies) != 2 {
		t.Fatalf("list: %v %d", err, len(policies))
	}
	// 通配工具 block 不影响 resources/read（既有策略行为不变）。
	if got := ResolveMCPPolicy(policies, MCPPolicyScope{TenantID: tenant, ServerID: "s", ToolName: "file:///tmp/a", TargetKind: "resource"}); got != nil {
		t.Fatalf("工具类通配策略不应命中资源: %#v", got)
	}
	if got := ResolveMCPPolicy(policies, MCPPolicyScope{TenantID: tenant, ServerID: "s", ToolName: "file:///etc/shadow", TargetKind: "resource"}); got == nil || got.ID != resource.ID {
		t.Fatalf("资源策略应命中: %#v", got)
	}
	if got := ResolveMCPPolicy(policies, MCPPolicyScope{TenantID: tenant, ServerID: "s", ToolName: "delete_repo"}); got == nil || got.ID != legacy.ID {
		t.Fatalf("空类别=tool 应命中工具策略: %#v", got)
	}
	resource.DefaultAction = "audit"
	if err := repo.Update(ctx, resource); err != nil {
		t.Fatalf("update: %v", err)
	}
	reloaded, err := repo.Get(ctx, tenant, resource.ID)
	if err != nil || reloaded.TargetKind != "resource" || reloaded.DefaultAction != "audit" {
		t.Fatalf("reload: %v %#v", err, reloaded)
	}
}

func TestWS1MCPServerLevelSupplyChainDropsToolReasons(t *testing.T) {
	unknown := resolveMCPSupplyChainState("approved", "", 1, "", "", 0, false, false, "")
	if !unknown.StructuralBlock {
		t.Fatal("前置：未知工具是结构阻断")
	}
	if got := MCPServerLevelSupplyChain(unknown); got.StructuralBlock {
		t.Fatalf("非工具目标不应继承工具级结构阻断: %#v", got)
	}
	quarantined := resolveMCPSupplyChainState("quarantined", "manual", 1, "", "", 0, false, false, "")
	if got := MCPServerLevelSupplyChain(quarantined); !got.StructuralBlock || got.Status != "quarantined" {
		t.Fatalf("服务器隔离应保留: %#v", got)
	}
}
