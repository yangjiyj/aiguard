package repository

import (
	"context"
	"strings"
	"testing"
)

// 批次 2B：受限文件作用范围落库、读回、随有效策略带出；变更不带作用范围时保留现值，新建时三项全选。
func TestAgentOperationRestrictedFileScopesRoundTrip(t *testing.T) {
	db := setupAgentOperationTestDB(t)
	repo := NewAgentOperationRepository(db)
	ctx := context.Background()

	mutation := validAgentOperationMutation()
	mutation.RestrictedFilePatterns = []string{"*.docx"}
	saved, err := repo.SavePolicy(ctx, mutation)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if strings.Join(saved.RestrictedFileScopes, ",") != "tool_call,user_mention,proxy_output" {
		t.Fatalf("new policy defaults to all scopes: %v", saved.RestrictedFileScopes)
	}

	mutation.ExpectedVersion = saved.Version
	mutation.RestrictedFileScopes = []string{"proxy_output", "tool_call", "bogus"}
	if saved, err = repo.SavePolicy(ctx, mutation); err != nil {
		t.Fatalf("save scopes: %v", err)
	}
	stored, err := repo.GetPolicy(ctx, mutation.TenantID, mutation.ScopeType, mutation.ScopeRef)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(stored.RestrictedFileScopes, ",") != "tool_call,proxy_output" {
		t.Fatalf("scopes are normalized and stored: %v", stored.RestrictedFileScopes)
	}

	mutation.ExpectedVersion = saved.Version
	mutation.RestrictedFileScopes = nil
	if saved, err = repo.SavePolicy(ctx, mutation); err != nil {
		t.Fatalf("save without scopes: %v", err)
	}
	if strings.Join(saved.RestrictedFileScopes, ",") != "tool_call,proxy_output" {
		t.Fatalf("a mutation without scopes keeps them: %v", saved.RestrictedFileScopes)
	}

	mutation.ExpectedVersion = saved.Version
	mutation.RestrictedFileScopes = []string{}
	if _, err = repo.SavePolicy(ctx, mutation); err != nil {
		t.Fatalf("save empty scopes: %v", err)
	}
	effective, err := repo.ResolveEffectivePolicy(ctx, mutation.TenantID, AgentOperationEffectivePolicyInput{
		ApplicationID: "app-a", AgentType: "codex-a", Protocol: "responses",
	})
	if err != nil {
		t.Fatal(err)
	}
	if effective.RestrictedFileScopes == nil || len(effective.RestrictedFileScopes) != 0 {
		t.Fatalf("an empty selection means none, not all: %#v", effective.RestrictedFileScopes)
	}
	none, err := repo.ResolveEffectivePolicy(ctx, "tenant-without-policy", AgentOperationEffectivePolicyInput{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(none.RestrictedFileScopes, ",") != "tool_call,user_mention,proxy_output" {
		t.Fatalf("no policy means default scopes: %v", none.RestrictedFileScopes)
	}
}
