package repository

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentAuthorizationMigrationUsesReserved861WithoutRuntimeMutation(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "deploy", "migrations", "861_trusted_agent_authorization.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, required := range []string{
		"create table if not exists agent_authorization_principals",
		"create table if not exists agent_authorization_grants",
		"create table if not exists agent_authorization_usage",
		"create table if not exists agent_authorization_requests",
		"credential_hash char(64) not null unique",
		"status in ('active', 'revoked')",
		"foreign key (tenant_id, principal_id)",
		"quota_window_seconds integer not null check",
		"primary key (tenant_id, principal_id, idempotency_key)",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration missing %q", required)
		}
	}
	if strings.Contains(sql, "860_") {
		t.Fatal("T13 migration must not reuse T08 reserved version 860")
	}
}
