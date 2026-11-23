package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupMCPServersTestDB opens a test DB and seeds a tenant.
func setupMCPServersTestDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tenantID := fmt.Sprintf("tenant_mcp_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM mcp_servers WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID
}

// TestMCPServersCRUD 是任务 1.8（P1-22，支柱⑦）的规格：mcp_servers 表的最小 CRUD 绑定，
// 含 trust_level/status 默认值与 capabilities JSON 往返；治理动作留阶段四。
func TestMCPServersCRUD(t *testing.T) {
	pool, tenantID := setupMCPServersTestDB(t)
	repo := NewMCPServersRepository(pool)
	ctx := context.Background()

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	m := &MCPServer{
		ID:           "mcp_" + sfx,
		TenantID:     tenantID,
		Name:         "weather-mcp",
		ServerURL:    "https://mcp.example.com/sse",
		Owner:        "platform-team",
		Capabilities: map[string]interface{}{"tools": []interface{}{"get_weather"}},
	}

	// Create：登记一台 MCP 服务器，trust_level/status 走默认值，created_at 由 RETURNING 回填。
	if err := repo.Create(ctx, m); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if m.TrustLevel != "low" {
		t.Errorf("default TrustLevel = %q, want low", m.TrustLevel)
	}
	if m.Status != "active" {
		t.Errorf("default Status = %q, want active", m.Status)
	}
	if m.CreatedAt.IsZero() {
		t.Errorf("CreatedAt should be set by RETURNING")
	}

	// Get：读回，字段与 capabilities JSON 必须一致（099 起租户硬隔离：按 tenant+id 查）。
	got, err := repo.Get(ctx, tenantID, m.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "weather-mcp" {
		t.Errorf("Name = %q, want weather-mcp", got.Name)
	}
	if got.ServerURL != "https://mcp.example.com/sse" {
		t.Errorf("ServerURL = %q, want https://mcp.example.com/sse", got.ServerURL)
	}
	if got.Owner != "platform-team" {
		t.Errorf("Owner = %q, want platform-team", got.Owner)
	}
	if got.TrustLevel != "low" {
		t.Errorf("TrustLevel = %q, want low", got.TrustLevel)
	}
	if got.Capabilities == nil || got.Capabilities["tools"] == nil {
		t.Errorf("Capabilities round-trip failed: %v", got.Capabilities)
	}

	// ListByTenant：能按租户列出刚登记的服务器。
	list, err := repo.ListByTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	found := false
	for _, item := range list {
		if item.ID == m.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("ListByTenant did not return server %s", m.ID)
	}

	// Update：改名/URL/负责人/信任级别/能力/状态（租户硬隔离签名；SetAuth=false 时凭据不变）。
	newCaps := map[string]interface{}{"tools": []interface{}{"get_weather", "get_forecast"}}
	if err := repo.Update(ctx, tenantID, m.ID, MCPServerUpdateParams{
		Name: "weather-mcp-v2", ServerURL: "https://mcp2.example.com/sse", Owner: "sec-team",
		TrustLevel: "high", Capabilities: newCaps, Status: "disabled",
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got2, err := repo.Get(ctx, tenantID, m.ID)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	// 租户硬隔离回归：换一个 tenant_id 去 Update/Delete 必须打不到（历史 IDOR 的修复验证）。
	if err := repo.Update(ctx, "tenant_other_"+sfx, m.ID, MCPServerUpdateParams{
		Name: "hijacked", TrustLevel: "high", Status: "active",
	}); err == nil {
		t.Errorf("cross-tenant Update should fail with no rows")
	}
	if err := repo.Delete(ctx, "tenant_other_"+sfx, m.ID); err == nil {
		t.Errorf("cross-tenant Delete should fail with no rows")
	}
	if got2.Name != "weather-mcp-v2" {
		t.Errorf("after Update Name = %q, want weather-mcp-v2", got2.Name)
	}
	if got2.ServerURL != "https://mcp2.example.com/sse" {
		t.Errorf("after Update ServerURL = %q", got2.ServerURL)
	}
	if got2.Owner != "sec-team" {
		t.Errorf("after Update Owner = %q, want sec-team", got2.Owner)
	}
	if got2.TrustLevel != "high" {
		t.Errorf("after Update TrustLevel = %q, want high", got2.TrustLevel)
	}
	if got2.Status != "disabled" {
		t.Errorf("after Update Status = %q, want disabled", got2.Status)
	}
	if got2.Capabilities == nil || got2.Capabilities["tools"] == nil {
		t.Errorf("after Update Capabilities round-trip failed: %v", got2.Capabilities)
	}

	// capabilities 省略（nil）= 保持不变回归：前端编辑表单不回传 capabilities，
	// 无条件覆盖会把该列清成 {}（集成审查发现的跨车道契约缺口）。
	if err := repo.Update(ctx, tenantID, m.ID, MCPServerUpdateParams{
		Name: "weather-mcp-v2", ServerURL: "https://mcp2.example.com/sse", Owner: "sec-team",
		TrustLevel: "high", Capabilities: nil, Status: "disabled",
	}); err != nil {
		t.Fatalf("Update with nil Capabilities: %v", err)
	}
	got3, err := repo.Get(ctx, tenantID, m.ID)
	if err != nil {
		t.Fatalf("Get after nil-capabilities update: %v", err)
	}
	if got3.Capabilities == nil || got3.Capabilities["tools"] == nil {
		t.Errorf("nil Capabilities update must preserve existing capabilities, got: %v", got3.Capabilities)
	}

	// Delete：删除后 Get 应报错（无行）。
	if err := repo.Delete(ctx, tenantID, m.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := repo.Get(ctx, tenantID, m.ID); err == nil {
		t.Errorf("Get after Delete should error, got nil")
	}
}
