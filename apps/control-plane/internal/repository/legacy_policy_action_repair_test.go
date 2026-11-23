package repository

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestLegacyNearAllAuditProfileGetsMaskAndBlockActions(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	if _, err := repo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA); err != nil {
		t.Fatalf("seed default policies: %v", err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE rules SET action='audit' WHERE rule_set_id=$1 AND policy_code LIKE 'builtin.%'`,
		f.ruleSetA); err != nil {
		t.Fatalf("create legacy profile: %v", err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE rules SET action='block' WHERE rule_set_id=$1 AND policy_code=$2`,
		f.ruleSetA, hardcodedCredentialPolicyCode); err != nil {
		t.Fatalf("create legacy block policy: %v", err)
	}

	body, err := os.ReadFile("../../../../deploy/migrations/848_repair_legacy_policy_actions.sql")
	if err != nil {
		t.Fatalf("read migration 848: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := f.pool.Exec(ctx, string(body), pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatalf("apply migration 848 attempt %d: %v", attempt, err)
		}
	}

	var masks, blocks int
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE action='mask'),
		       COUNT(*) FILTER (WHERE action='block')
		FROM rules WHERE rule_set_id=$1 AND policy_code LIKE 'builtin.%'
	`, f.ruleSetA).Scan(&masks, &blocks); err != nil {
		t.Fatalf("count repaired actions: %v", err)
	}
	if masks != 16 || blocks != 1 {
		t.Fatalf("repaired mask/block=%d/%d want 16/1", masks, blocks)
	}
}

func TestPolicyActionPreservationRevertsMigration848Fingerprint(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	if _, err := repo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA); err != nil {
		t.Fatalf("seed default policies: %v", err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE rules SET action='audit' WHERE rule_set_id=$1 AND policy_code LIKE 'builtin.%'`,
		f.ruleSetA); err != nil {
		t.Fatalf("create legacy profile: %v", err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE rules SET action='block' WHERE rule_set_id=$1 AND policy_code=$2`,
		f.ruleSetA, hardcodedCredentialPolicyCode); err != nil {
		t.Fatalf("create legacy block policy: %v", err)
	}
	for _, migration := range []string{
		"848_repair_legacy_policy_actions.sql",
		"849_preserve_legacy_policy_actions.sql",
		"849_preserve_legacy_policy_actions.sql",
	} {
		body, err := os.ReadFile("../../../../deploy/migrations/" + migration)
		if err != nil {
			t.Fatalf("read migration %s: %v", migration, err)
		}
		if _, err := f.pool.Exec(ctx, string(body), pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatalf("apply migration %s: %v", migration, err)
		}
	}
	var masks, blocks int
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE action='mask'),
		       COUNT(*) FILTER (WHERE action='block')
		FROM rules WHERE rule_set_id=$1 AND policy_code LIKE 'builtin.%'
	`, f.ruleSetA).Scan(&masks, &blocks); err != nil {
		t.Fatalf("count preserved actions: %v", err)
	}
	if masks != 0 || blocks != 1 {
		t.Fatalf("preserved mask/block=%d/%d want 0/1", masks, blocks)
	}
}

func TestPolicyActionPreservationLeavesCurrentDefaultProfileUntouched(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	if _, err := repo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA); err != nil {
		t.Fatalf("seed default policies: %v", err)
	}
	var beforeMask, beforeBlock int
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE action='mask'),
		       COUNT(*) FILTER (WHERE action='block')
		FROM rules WHERE rule_set_id=$1 AND policy_code LIKE 'builtin.%'
	`, f.ruleSetA).Scan(&beforeMask, &beforeBlock); err != nil {
		t.Fatalf("count default actions: %v", err)
	}
	body, err := os.ReadFile("../../../../deploy/migrations/849_preserve_legacy_policy_actions.sql")
	if err != nil {
		t.Fatalf("read migration 849: %v", err)
	}
	if _, err := f.pool.Exec(ctx, string(body), pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("apply migration 849: %v", err)
	}
	var afterMask, afterBlock int
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE action='mask'),
		       COUNT(*) FILTER (WHERE action='block')
		FROM rules WHERE rule_set_id=$1 AND policy_code LIKE 'builtin.%'
	`, f.ruleSetA).Scan(&afterMask, &afterBlock); err != nil {
		t.Fatalf("count default actions after migration: %v", err)
	}
	if afterMask != beforeMask || afterBlock != beforeBlock {
		t.Fatalf("default profile changed mask/block %d/%d -> %d/%d",
			beforeMask, beforeBlock, afterMask, afterBlock)
	}
}

func TestLegacyActionRepairLeavesCustomizedProfileUntouched(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	if _, err := repo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA); err != nil {
		t.Fatalf("seed default policies: %v", err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE rules SET action='audit' WHERE rule_set_id=$1 AND policy_code LIKE 'builtin.%'`,
		f.ruleSetA); err != nil {
		t.Fatalf("create customized audit profile: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		UPDATE rules SET action='block'
		WHERE rule_set_id=$1 AND policy_code LIKE 'builtin.%'
		  AND id IN (SELECT id FROM rules WHERE rule_set_id=$1 AND policy_code LIKE 'builtin.%' ORDER BY id LIMIT 2)
	`, f.ruleSetA); err != nil {
		t.Fatalf("create customized profile: %v", err)
	}

	body, err := os.ReadFile("../../../../deploy/migrations/848_repair_legacy_policy_actions.sql")
	if err != nil {
		t.Fatalf("read migration 848: %v", err)
	}
	if _, err := f.pool.Exec(ctx, string(body), pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("apply migration 848: %v", err)
	}

	var masks int
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM rules WHERE rule_set_id=$1 AND action='mask'
	`, f.ruleSetA).Scan(&masks); err != nil {
		t.Fatalf("count customized actions: %v", err)
	}
	if masks != 0 {
		t.Fatalf("customized profile unexpectedly repaired: masks=%d", masks)
	}
}
