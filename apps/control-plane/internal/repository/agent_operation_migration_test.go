package repository

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentOperationMigrationDeclaresPublicEventAndAuditFacts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "migrations", "140_agent_destructive_operation_governance.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, required := range []string{
		"add column if not exists public_event_id",
		"uq_tool_call_logs_destructive_public_event",
		"(tenant_id, public_event_id)",
		"where public_event_id is not null",
		"create table if not exists agent_destructive_policy_audits",
		"before_json jsonb",
		"after_json jsonb",
		"actor_id",
		"source",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration 140 missing %q", required)
		}
	}
}

func TestAgentOperationMigrationWidensToolCallStatusForConfirmation(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "migrations", "141_tool_call_log_status_width.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, required := range []string{
		"alter table tool_call_logs",
		"alter column status type varchar(32)",
		"waiting_confirmation",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration 141 missing %q", required)
		}
	}
}

func TestAgentOperationPolicyScopeMigrationSupportsGlobalBaselines(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "migrations", "142_agent_operation_policy_scopes.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, required := range []string{
		"alter table agent_destructive_policies",
		"alter column tenant_id drop not null",
		"alter table agent_destructive_policy_audits",
		"uq_agent_destructive_policies_enabled_tenant_scope",
		"uq_agent_destructive_policies_enabled_global_scope",
		"tenant_id is null",
		"notify_channel_ids_json",
		"scope_type <> 'application'",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration 142 missing %q", required)
		}
	}
}
