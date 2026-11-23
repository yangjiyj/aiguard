package repository

import (
	"context"
	"testing"
)

// 审查意见 3（仓库）：协议为空的“确认”策略对所有协议生效（以前只对 MCP 请求生效）；
// 只管 MCP 的确认策略仍只对 MCP 请求生效。
func TestAgentOperationConfirm2922ResolvesForNonMCPProtocols(t *testing.T) {
	db := setupAgentOperationTestDB(t)
	repo := NewAgentOperationRepository(db)
	ctx := context.Background()
	mutation := validAgentOperationMutation()
	mutation.ScopeType, mutation.ScopeRef, mutation.Mode, mutation.Action = "tenant", "", "audit", "confirm"
	mutation.NotifyChannelIDs = nil
	if _, err := repo.SavePolicy(ctx, mutation); err != nil {
		t.Fatalf("save tenant confirm: %v", err)
	}
	for _, protocol := range []string{"chat", "responses", "mcp"} {
		effective, err := repo.ResolveEffectivePolicy(ctx, mutation.TenantID, AgentOperationEffectivePolicyInput{Protocol: protocol})
		if err != nil {
			t.Fatal(err)
		}
		if effective.Action != "confirm" || effective.ScopeType != "tenant" {
			t.Fatalf("%s: a confirm policy for all protocols must resolve: %+v", protocol, effective)
		}
	}

	scoped := validAgentOperationMutation()
	scoped.Action, scoped.Protocol, scoped.ScopeRef = "confirm", "mcp", "app-a"
	if _, err := repo.SavePolicy(ctx, scoped); err != nil {
		t.Fatalf("save mcp confirm: %v", err)
	}
	chat, err := repo.ResolveEffectivePolicy(ctx, scoped.TenantID, AgentOperationEffectivePolicyInput{ApplicationID: "app-a", Protocol: "chat"})
	if err != nil {
		t.Fatal(err)
	}
	if chat.ScopeType != "tenant" {
		t.Fatalf("an MCP-only confirm policy stays MCP-only; chat falls back to the tenant policy: %+v", chat)
	}
}
