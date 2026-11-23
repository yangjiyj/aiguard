package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// insertToolCallTyped 插入一条指定 tool_type/tool_name 的 tool_call_logs 记录（态势 tool_type 过滤用）。
func insertToolCallTyped(t *testing.T, db *pgxpool.Pool, ctx context.Context, tenantID, toolName, toolType, riskLevel string, createdAt time.Time) {
	t.Helper()
	_, err := db.Exec(ctx, `
		INSERT INTO tool_call_logs (
			id, request_id, session_id, tenant_id, user_id, tool_name, tool_type, risk_level,
			parameters, result, status, mode, created_at
		) VALUES ($1, '', '', $2, '', $3, $4, $5, '{}'::jsonb, '', 'success', 'audit', $6)
	`, fmt.Sprintf("tc_typed_%d", time.Now().UnixNano()), tenantID, toolName, toolType, riskLevel, createdAt)
	if err != nil {
		t.Fatalf("insert typed tool call: %v", err)
	}
}

// TestGetRiskOverviewToolTypeFilter 验证 GetRiskOverview 的 tool_type 过滤与 TopServers 派生。
// DB 门控：无 CONTENT_LOGS_TEST_DATABASE_URL 时 skip（属正常）。
func TestGetRiskOverviewToolTypeFilter(t *testing.T) {
	db, ctx, tenantID, _, _ := setupAuditStatsRegressionFixture(t)
	registerToolCallLogCleanup(t, db, ctx, tenantID)

	now := time.Now().UTC()
	// 2 条 MCP（tool_name 用 'server__tool' 约定），1 条非 MCP。
	insertToolCallTyped(t, db, ctx, tenantID, "srvA__fs.read", "mcp", "high", now)
	insertToolCallTyped(t, db, ctx, tenantID, "srvA__fs.write", "mcp", "low", now)
	insertToolCallTyped(t, db, ctx, tenantID, "shell.exec", "system", "critical", now)

	repo := NewToolCallLogRepository(db)
	start, end := now.Add(-time.Hour), now.Add(time.Hour)

	// 不过滤：3 条全计入。
	all, err := repo.GetRiskOverview(ctx, tenantID, start, end, "")
	if err != nil {
		t.Fatalf("overview all: %v", err)
	}
	if all.TotalToolCalls != 3 {
		t.Errorf("不过滤 TotalToolCalls=%d，期望 3", all.TotalToolCalls)
	}

	// tool_type='mcp'：只计 2 条 MCP。
	mcp, err := repo.GetRiskOverview(ctx, tenantID, start, end, "mcp")
	if err != nil {
		t.Fatalf("overview mcp: %v", err)
	}
	if mcp.TotalToolCalls != 2 {
		t.Errorf("mcp 过滤 TotalToolCalls=%d，期望 2", mcp.TotalToolCalls)
	}
	// TopServers 从 tool_name 前缀（split_part '__' 1）派生：应只有 srvA，计数 2。
	if len(mcp.TopServers) != 1 || mcp.TopServers[0].ID != "srvA" || mcp.TopServers[0].Count != 2 {
		t.Errorf("mcp TopServers=%+v，期望 [{srvA 2}]", mcp.TopServers)
	}
}

// TestListConfirmationsSourceFilter 验证确认单按 source 过滤（MCP 审批页 source='mcp' 只看 MCP 单）。
// DB 门控：无 CONTENT_LOGS_TEST_DATABASE_URL 时 skip（属正常）。
func TestListConfirmationsSourceFilter(t *testing.T) {
	db, ctx, tenantID, _, _ := setupAuditStatsRegressionFixture(t)
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, "DELETE FROM agentguard_confirmations WHERE tenant_id = $1", tenantID)
	})

	repo := NewAgentGuardPolicyRepository(db)
	expires := time.Now().Add(10 * time.Minute)
	if err := repo.CreateConfirmation(ctx, &AgentGuardConfirmation{TenantID: tenantID, TraceID: "tr_ag", ToolName: "network.upload", ExpiresAt: expires}); err != nil {
		t.Fatalf("create agentguard confirmation: %v", err)
	}
	if err := repo.CreateConfirmation(ctx, &AgentGuardConfirmation{TenantID: tenantID, TraceID: "tr_mcp", ToolName: "srvA__fs.delete", Source: "mcp", ExpiresAt: expires}); err != nil {
		t.Fatalf("create mcp confirmation: %v", err)
	}

	// source='mcp'：只回 MCP 来源的确认单。
	mcpOnly, err := repo.ListConfirmations(ctx, tenantID, "", "mcp")
	if err != nil {
		t.Fatalf("list mcp confirmations: %v", err)
	}
	if len(mcpOnly) != 1 || mcpOnly[0].Source != "mcp" || mcpOnly[0].ToolName != "srvA__fs.delete" {
		t.Errorf("source=mcp 结果=%+v，期望仅 1 条 mcp 单", mcpOnly)
	}

	// source='agentguard' 是虚拟来源：兼容历史空 source，但排除 MCP。
	agentguardOnly, err := repo.ListConfirmations(ctx, tenantID, "", "agentguard")
	if err != nil {
		t.Fatalf("list agentguard confirmations: %v", err)
	}
	if len(agentguardOnly) != 1 || agentguardOnly[0].Source == "mcp" || agentguardOnly[0].ToolName != "network.upload" {
		t.Errorf("source=agentguard 结果=%+v，期望仅 1 条非 mcp 单", agentguardOnly)
	}

	// source='' 不过滤：两条都在（旧口径，AgentGuard 行为不变）。
	all, err := repo.ListConfirmations(ctx, tenantID, "", "")
	if err != nil {
		t.Fatalf("list all confirmations: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("不过滤结果数=%d，期望 2", len(all))
	}
}
