package repository

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Migration 854 undoes the block that migrations 814/848 put on the built-in
// hardcoded-credential rule of legacy near-all-audit profiles, unless an
// administrator touched the rule in the console.
func TestMigration854RevertsUpgradeInventedBlockOnly(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	for tenantID, ruleSetID := range map[string]string{f.tenantA: f.ruleSetA, f.tenantB: f.ruleSetB} {
		if _, err := repo.SeedDefaultSubRules(ctx, tenantID, ruleSetID); err != nil {
			t.Fatalf("seed default policies: %v", err)
		}
		if _, err := f.pool.Exec(ctx, `UPDATE rules SET action='audit' WHERE rule_set_id=$1 AND policy_code LIKE 'builtin.%'`, ruleSetID); err != nil {
			t.Fatalf("create legacy profile: %v", err)
		}
		if _, err := f.pool.Exec(ctx, `UPDATE rules SET action='block' WHERE rule_set_id=$1 AND policy_code=$2`, ruleSetID, hardcodedCredentialPolicyCode); err != nil {
			t.Fatalf("apply upgrade-invented block: %v", err)
		}
	}
	if _, err := f.pool.Exec(ctx, `CREATE TABLE audit_operations (
		id VARCHAR(64) PRIMARY KEY, user_id VARCHAR(64), action_type VARCHAR(128) NOT NULL,
		action_detail JSONB, target_type VARCHAR(64), target_id VARCHAR(128), ip_address VARCHAR(64),
		created_at TIMESTAMPTZ DEFAULT NOW())`); err != nil {
		t.Fatalf("create audit_operations: %v", err)
	}
	var editedRuleID string
	if err := f.pool.QueryRow(ctx, `SELECT id FROM rules WHERE rule_set_id=$1 AND policy_code=$2`, f.ruleSetB, hardcodedCredentialPolicyCode).Scan(&editedRuleID); err != nil {
		t.Fatalf("read rule B: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO audit_operations(id,action_type,target_type,target_id) VALUES ('op-1','security_policy.update','security_policy',$1)`, editedRuleID); err != nil {
		t.Fatalf("record administrator edit: %v", err)
	}

	body, err := os.ReadFile("../../../../deploy/migrations/854_revert_upgrade_invented_block_rule.sql")
	if err != nil {
		t.Fatalf("read migration 854: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := f.pool.Exec(ctx, string(body), pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatalf("apply migration 854 attempt %d: %v", attempt, err)
		}
	}

	action := func(ruleSetID string) string {
		var value string
		if err := f.pool.QueryRow(ctx, `SELECT action FROM rules WHERE rule_set_id=$1 AND policy_code=$2`, ruleSetID, hardcodedCredentialPolicyCode).Scan(&value); err != nil {
			t.Fatalf("read action: %v", err)
		}
		return value
	}
	if got := action(f.ruleSetA); got != "audit" {
		t.Fatalf("upgrade-invented block must revert to audit, got %q", got)
	}
	if got := action(f.ruleSetB); got != "block" {
		t.Fatalf("an administrator-edited rule must keep its block, got %q", got)
	}
}

func TestMigration854LeavesFreshInstallDefaultsUntouched(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	if _, err := NewRuleRepository(f.pool).SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA); err != nil {
		t.Fatalf("seed default policies: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `CREATE TABLE audit_operations (id VARCHAR(64) PRIMARY KEY, action_type VARCHAR(128), target_id VARCHAR(128))`); err != nil {
		t.Fatalf("create audit_operations: %v", err)
	}
	var before int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules WHERE rule_set_id=$1 AND action='block'`, f.ruleSetA).Scan(&before); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("../../../../deploy/migrations/854_revert_upgrade_invented_block_rule.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, string(body), pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("apply migration 854: %v", err)
	}
	var after int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules WHERE rule_set_id=$1 AND action='block'`, f.ruleSetA).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("fresh-install defaults changed: blocks %d -> %d", before, after)
	}
}
