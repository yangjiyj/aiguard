package repository

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 迁移 852 文本断言：列、默认值、CHECK 约束齐全且对现网既有行安全。
func TestAgentRestrictedFilePatternsMigrationShape(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "migrations", "853_agent_restricted_file_patterns.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, required := range []string{
		"alter table agent_destructive_policies",
		"add column if not exists restricted_file_patterns_json jsonb not null default '[]'::jsonb",
		"add column if not exists restricted_file_action varchar(16) not null default 'block'",
		"agent_destructive_json_string_array_valid(restricted_file_patterns_json)",
		"jsonb_array_length(restricted_file_patterns_json) <= 64",
		"restricted_file_action in ('record', 'alert_allow', 'block')",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration 852 missing %q", required)
		}
	}
}

// 写读后一致性 + 默认值 + ResolveEffectivePolicy 带出新字段。
func TestAgentOperationRestrictedFilePatternsRoundTrip(t *testing.T) {
	db := setupAgentOperationTestDB(t)
	repo := NewAgentOperationRepository(db)
	ctx := context.Background()

	mutation := validAgentOperationMutation()
	mutation.RestrictedFilePatterns = []string{"*.pdf", "docs/**/*.docx", "/srv/contracts/"}
	mutation.RestrictedFileAction = "alert_allow"
	if _, err := repo.SavePolicy(ctx, mutation); err != nil {
		t.Fatalf("save with restricted patterns: %v", err)
	}

	stored, err := repo.GetPolicy(ctx, mutation.TenantID, mutation.ScopeType, mutation.ScopeRef)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if strings.Join(stored.RestrictedFilePatterns, ",") != "*.pdf,docs/**/*.docx,/srv/contracts/" {
		t.Fatalf("patterns round trip: %v", stored.RestrictedFilePatterns)
	}
	if stored.RestrictedFileAction != "alert_allow" {
		t.Fatalf("action round trip: %q", stored.RestrictedFileAction)
	}

	effective, err := repo.ResolveEffectivePolicy(ctx, mutation.TenantID, AgentOperationEffectivePolicyInput{
		ApplicationID: "app-a", AgentType: "codex-a", Protocol: "responses", Mode: "strict",
	})
	if err != nil {
		t.Fatalf("resolve effective: %v", err)
	}
	if len(effective.RestrictedFilePatterns) != 3 || effective.RestrictedFileAction != "alert_allow" {
		t.Fatalf("effective restricted fields: %+v", effective)
	}
}

// 默认值：不写受限文件字段时读回空数组 + block。
func TestAgentOperationRestrictedFilePatternsDefaults(t *testing.T) {
	db := setupAgentOperationTestDB(t)
	repo := NewAgentOperationRepository(db)
	ctx := context.Background()

	mutation := validAgentOperationMutation()
	if _, err := repo.SavePolicy(ctx, mutation); err != nil {
		t.Fatalf("save: %v", err)
	}
	stored, err := repo.GetPolicy(ctx, mutation.TenantID, mutation.ScopeType, mutation.ScopeRef)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(stored.RestrictedFilePatterns) != 0 {
		t.Fatalf("default patterns should be empty: %v", stored.RestrictedFilePatterns)
	}
	if stored.RestrictedFileAction != "block" {
		t.Fatalf("default action should be block: %q", stored.RestrictedFileAction)
	}
}
