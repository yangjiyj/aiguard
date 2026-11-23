package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAgentGuardPolicyTenantUpdateCannotOverwriteAnotherTenant(t *testing.T) {
	databaseURL := os.Getenv("AGENTGUARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("AGENTGUARD_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	t.Cleanup(adminPool.Close)

	schema := fmt.Sprintf("agentguard_policy_test_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse database config: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated pool: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, dropErr := adminPool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); dropErr != nil {
			t.Errorf("drop test schema: %v", dropErr)
		}
	})

	_, err = db.Exec(ctx, `
		CREATE TABLE agentguard_policies (
			id VARCHAR(64) PRIMARY KEY,
			tenant_id VARCHAR(64) NOT NULL,
			name VARCHAR(128) NOT NULL,
			scope_type VARCHAR(32) NOT NULL,
			scope_ref VARCHAR(128) NOT NULL DEFAULT '',
			mode VARCHAR(16) NOT NULL DEFAULT 'audit',
			default_action VARCHAR(16) NOT NULL DEFAULT 'audit',
			fail_policy VARCHAR(16) NOT NULL DEFAULT 'fail_closed',
			priority INTEGER NOT NULL DEFAULT 0,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			template_id VARCHAR(64),
			rules_json JSONB NOT NULL DEFAULT '{}'::jsonb,
			behavior_json JSONB NOT NULL DEFAULT '{}'::jsonb,
			dlp_json JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_by VARCHAR(64),
			updated_by VARCHAR(64),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE agentguard_policy_versions (
			id VARCHAR(64) PRIMARY KEY,
			tenant_id VARCHAR(64) NOT NULL,
			policy_id VARCHAR(64) NOT NULL REFERENCES agentguard_policies(id) ON DELETE CASCADE,
			policy_version VARCHAR(64) NOT NULL,
			snapshot_json JSONB NOT NULL,
			config_hash VARCHAR(128) NOT NULL,
			active BOOLEAN NOT NULL DEFAULT FALSE,
			created_by VARCHAR(64),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(policy_id, policy_version)
		);
		CREATE UNIQUE INDEX idx_agentguard_policy_versions_one_active
			ON agentguard_policy_versions(policy_id) WHERE active = TRUE;
	`)
	if err != nil {
		t.Fatalf("create agentguard tables: %v", err)
	}

	repo := NewAgentGuardPolicyRepository(db)
	policy := &AgentGuardPolicy{
		ID: "agp_client_controlled", TenantID: "tenant-a", Name: "租户 A 策略",
		ScopeType: "tenant", Mode: AgentGuardModeAudit, DefaultAction: AgentGuardActionAudit,
		FailPolicy: AgentGuardFailClosed, Enabled: true,
	}
	stored, version, err := repo.CreatePolicyWithVersion(ctx, policy, "user-a")
	if err != nil {
		t.Fatalf("create tenant A policy: %v", err)
	}
	if policy.ID == "agp_client_controlled" || policy.ID == "" {
		t.Fatalf("create accepted client policy id: %q", policy.ID)
	}
	if stored == nil || version == nil {
		t.Fatalf("atomic create returned incomplete state: policy=%#v version=%#v", stored, version)
	}

	crossTenant := *policy
	crossTenant.TenantID = "tenant-b"
	crossTenant.Name = "租户 B 覆盖"
	crossTenant.Mode = AgentGuardModeStrict
	crossTenant.DefaultAction = AgentGuardActionBlock
	updatedPolicy, updatedVersion, updated, err := repo.UpdatePolicyWithVersion(ctx, &crossTenant, "user-b")
	if err != nil {
		t.Fatalf("cross-tenant update: %v", err)
	}
	if updated || updatedPolicy != nil || updatedVersion != nil {
		t.Fatal("cross-tenant update unexpectedly reported success")
	}

	stored, err = repo.GetPolicy(ctx, "tenant-a", policy.ID)
	if err != nil {
		t.Fatalf("reload tenant A policy: %v", err)
	}
	if stored == nil || stored.Name != "租户 A 策略" || stored.Mode != AgentGuardModeAudit {
		t.Fatalf("tenant A policy changed: %#v", stored)
	}
	versions, err := repo.ListVersions(ctx, "tenant-a", policy.ID)
	if err != nil {
		t.Fatalf("list tenant A versions: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("tenant A version count = %d, want 1", len(versions))
	}
}
