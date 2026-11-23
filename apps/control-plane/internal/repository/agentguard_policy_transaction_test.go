package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func newAgentGuardPolicyTransactionTestRepo(t *testing.T) (*AgentGuardPolicyRepository, *pgxpool.Pool) {
	t.Helper()
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

	schema := fmt.Sprintf("agentguard_policy_tx_test_%d", time.Now().UnixNano())
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
		t.Fatalf("create agentguard transaction tables: %v", err)
	}
	return NewAgentGuardPolicyRepository(db), db
}

func validAgentGuardTransactionPolicy() *AgentGuardPolicy {
	return &AgentGuardPolicy{
		TenantID:      "tenant-a",
		Name:          "事务策略 v1",
		ScopeType:     "tenant",
		Mode:          AgentGuardModeStrict,
		DefaultAction: AgentGuardActionAudit,
		FailPolicy:    AgentGuardFailClosed,
		Enabled:       true,
		RulesJSON: map[string]any{"rules": []any{
			map[string]any{"id": "block-network", "tool_pattern": "network.*", "action": AgentGuardActionBlock, "enabled": true},
		}},
		CreatedBy: "user-a",
		UpdatedBy: "user-a",
	}
}

func TestSaveAgentGuardPolicyWithVersionIsIdempotentInPostgreSQL(t *testing.T) {
	repo, db := newAgentGuardPolicyTransactionTestRepo(t)
	ctx := context.Background()
	policy := validAgentGuardTransactionPolicy()

	stored, firstVersion, err := repo.CreatePolicyWithVersion(ctx, policy, "user-a")
	if err != nil {
		t.Fatalf("create policy with version: %v", err)
	}
	identical := *stored
	identical.UpdatedBy = "user-b"
	storedAgain, secondVersion, updated, err := repo.UpdatePolicyWithVersion(ctx, &identical, "user-b")
	if err != nil {
		t.Fatalf("save identical policy with version: %v", err)
	}
	if !updated || storedAgain == nil || secondVersion == nil {
		t.Fatalf("idempotent save did not return persisted state: updated=%v policy=%#v version=%#v", updated, storedAgain, secondVersion)
	}
	if secondVersion.ID != firstVersion.ID || secondVersion.PolicyVersion != firstVersion.PolicyVersion {
		t.Fatalf("identical save created a different version: first=%#v second=%#v", firstVersion, secondVersion)
	}

	var total, active int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE active)
		FROM agentguard_policy_versions
		WHERE tenant_id = $1 AND policy_id = $2
	`, stored.TenantID, stored.ID).Scan(&total, &active); err != nil {
		t.Fatalf("query version state: %v", err)
	}
	if total != 1 || active != 1 {
		t.Fatalf("version state after idempotent save = total:%d active:%d, want 1/1", total, active)
	}
}

func TestUpdateAgentGuardPolicyWithVersionRollsBackOnVersionInsertFailure(t *testing.T) {
	repo, db := newAgentGuardPolicyTransactionTestRepo(t)
	ctx := context.Background()
	policy := validAgentGuardTransactionPolicy()
	stored, oldVersion, err := repo.CreatePolicyWithVersion(ctx, policy, "user-a")
	if err != nil {
		t.Fatalf("create initial policy with version: %v", err)
	}

	_, err = db.Exec(ctx, `
		CREATE FUNCTION fail_agentguard_policy_version_insert() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'forced agentguard version insert failure';
		END;
		$$;
		CREATE TRIGGER fail_agentguard_policy_version_insert
		BEFORE INSERT ON agentguard_policy_versions
		FOR EACH ROW EXECUTE FUNCTION fail_agentguard_policy_version_insert();
	`)
	if err != nil {
		t.Fatalf("install version failure trigger: %v", err)
	}

	changed := *stored
	changed.Name = "不应提交的事务策略 v2"
	changed.Mode = AgentGuardModeAudit
	changed.UpdatedBy = "user-b"
	if _, _, _, err := repo.UpdatePolicyWithVersion(ctx, &changed, "user-b"); err == nil {
		t.Fatal("expected forced version insert failure")
	}

	reloaded, err := repo.GetPolicy(ctx, stored.TenantID, stored.ID)
	if err != nil {
		t.Fatalf("reload policy after rollback: %v", err)
	}
	if reloaded == nil || reloaded.Name != stored.Name || reloaded.Mode != stored.Mode {
		t.Fatalf("policy content changed despite version failure: before=%#v after=%#v", stored, reloaded)
	}
	versions, err := repo.ListVersions(ctx, stored.TenantID, stored.ID)
	if err != nil {
		t.Fatalf("list versions after rollback: %v", err)
	}
	if len(versions) != 1 || versions[0].ID != oldVersion.ID || !versions[0].Active {
		t.Fatalf("version state changed despite rollback: %#v", versions)
	}
}

func TestRollbackAgentGuardPolicyAcceptsLegacyVersionWithoutRuleIDs(t *testing.T) {
	repo, db := newAgentGuardPolicyTransactionTestRepo(t)
	ctx := context.Background()
	stored, currentVersion, err := repo.CreatePolicyWithVersion(ctx, validAgentGuardTransactionPolicy(), "user-a")
	if err != nil {
		t.Fatalf("create current policy: %v", err)
	}

	legacyPolicy := *stored
	legacyPolicy.Name = "历史无规则 ID 策略"
	legacyPolicy.Mode = AgentGuardModeAudit
	legacyPolicy.RulesJSON = map[string]any{"rules": []any{
		map[string]any{"tool_pattern": "network.*", "action": AgentGuardActionAudit},
	}}
	legacyVersion, err := NewAgentGuardPolicyVersion(&legacyPolicy, "legacy-user")
	if err != nil {
		t.Fatalf("build legacy version: %v", err)
	}
	snapshotJSON, err := json.Marshal(legacyVersion.SnapshotJSON)
	if err != nil {
		t.Fatalf("marshal legacy snapshot: %v", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO agentguard_policy_versions (
			id, tenant_id, policy_id, policy_version, snapshot_json, config_hash, active, created_by, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,FALSE,$7,$8)
	`, legacyVersion.ID, legacyVersion.TenantID, legacyVersion.PolicyID, legacyVersion.PolicyVersion,
		snapshotJSON, legacyVersion.ConfigHash, legacyVersion.CreatedBy, legacyVersion.CreatedAt)
	if err != nil {
		t.Fatalf("insert legacy version: %v", err)
	}

	rolledBack, err := repo.RollbackPolicy(ctx, stored.TenantID, stored.ID, legacyVersion.ID, "admin-user")
	if err != nil {
		t.Fatalf("rollback legacy version: %v", err)
	}
	if rolledBack == nil || rolledBack.Name != legacyPolicy.Name || rolledBack.Mode != legacyPolicy.Mode {
		t.Fatalf("legacy snapshot was not restored: %#v", rolledBack)
	}
	rules := normalizeAgentGuardRuleMaps(rolledBack.RulesJSON)
	if len(rules) != 1 || stringFromRule(rules[0], "id") != "" {
		t.Fatalf("legacy empty rule id was unexpectedly rewritten: %#v", rolledBack.RulesJSON)
	}

	var activeID string
	var activeCount int
	if err := db.QueryRow(ctx, `
		SELECT COALESCE(MAX(id) FILTER (WHERE active), ''), COUNT(*) FILTER (WHERE active)
		FROM agentguard_policy_versions WHERE tenant_id = $1 AND policy_id = $2
	`, stored.TenantID, stored.ID).Scan(&activeID, &activeCount); err != nil {
		t.Fatalf("query active rollback version: %v", err)
	}
	if activeID != legacyVersion.ID || activeCount != 1 || activeID == currentVersion.ID {
		t.Fatalf("rollback active version = %q/%d, want %q/1", activeID, activeCount, legacyVersion.ID)
	}
}

func TestInvalidOptionalAgentGuardRuleTypesWriteNothingInPostgreSQL(t *testing.T) {
	repo, db := newAgentGuardPolicyTransactionTestRepo(t)
	ctx := context.Background()

	invalidCreate := validAgentGuardTransactionPolicy()
	invalidCreate.RulesJSON = map[string]any{"rules": []any{
		map[string]any{"id": "bad-enabled", "name": "错误 enabled", "tool_pattern": "network.*", "action": AgentGuardActionBlock, "enabled": "true"},
	}}
	if _, _, err := repo.CreatePolicyWithVersion(ctx, invalidCreate, "user-a"); err == nil {
		t.Fatal("create with non-bool rule enabled should fail")
	}
	var policyCount, versionCount int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agentguard_policies`).Scan(&policyCount); err != nil {
		t.Fatalf("count policies after invalid create: %v", err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM agentguard_policy_versions`).Scan(&versionCount); err != nil {
		t.Fatalf("count versions after invalid create: %v", err)
	}
	if policyCount != 0 || versionCount != 0 {
		t.Fatalf("invalid create wrote policy/version rows: policies=%d versions=%d", policyCount, versionCount)
	}

	stored, version, err := repo.CreatePolicyWithVersion(ctx, validAgentGuardTransactionPolicy(), "user-a")
	if err != nil {
		t.Fatalf("create valid baseline policy: %v", err)
	}
	invalidUpdate := *stored
	invalidUpdate.Name = "不应提交的策略"
	invalidUpdate.RulesJSON = map[string]any{"rules": []any{
		map[string]any{"id": "bad-name", "name": map[string]any{"zh": "错误 name"}, "tool_pattern": "network.*", "action": AgentGuardActionBlock, "enabled": true},
	}}
	if _, _, _, err := repo.UpdatePolicyWithVersion(ctx, &invalidUpdate, "user-b"); err == nil {
		t.Fatal("update with non-string rule name should fail")
	}

	reloaded, err := repo.GetPolicy(ctx, stored.TenantID, stored.ID)
	if err != nil {
		t.Fatalf("reload policy after invalid update: %v", err)
	}
	versions, err := repo.ListVersions(ctx, stored.TenantID, stored.ID)
	if err != nil {
		t.Fatalf("list versions after invalid update: %v", err)
	}
	if reloaded == nil || reloaded.Name != stored.Name {
		t.Fatalf("invalid update changed policy: before=%#v after=%#v", stored, reloaded)
	}
	if len(versions) != 1 || versions[0].ID != version.ID || !versions[0].Active {
		t.Fatalf("invalid update changed versions: %#v", versions)
	}
}
