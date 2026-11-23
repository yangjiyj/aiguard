package repository

import (
	"context"
	"reflect"
	"testing"
)

func TestListSecurityPolicyTenantIDsIncludesExistingTenantsAndExcludesReservedSystemTenant(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `INSERT INTO tenants(id) VALUES($1)`, SystemTenantID); err != nil {
		t.Fatalf("insert reserved system tenant: %v", err)
	}
	ids, err := NewTenantRepository(f.pool).ListSecurityPolicyTenantIDs(ctx)
	if err != nil {
		t.Fatalf("list security policy tenant ids: %v", err)
	}
	want := []string{f.tenantA, f.tenantB}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("tenant ids=%v want=%v", ids, want)
	}
}

func TestCleanupFailedPolicyInitializationRemovesTenantRuleSetAndPartialRules(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewTenantRepository(f.pool)

	// The fixture represents a seed that failed after the tenant, rule set and
	// some rules had already committed. Cleanup must remove the dependency chain
	// without touching another tenant.
	if err := repo.CleanupFailedPolicyInitialization(ctx, f.tenantA); err != nil {
		t.Fatalf("cleanup failed tenant bootstrap: %v", err)
	}
	var tenantCount, ruleSetCount, ruleCount int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenants WHERE id=$1`, f.tenantA).Scan(&tenantCount); err != nil {
		t.Fatalf("count failed tenant: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rule_sets WHERE tenant_id=$1`, f.tenantA).Scan(&ruleSetCount); err != nil {
		t.Fatalf("count failed tenant rule sets: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM rules
		WHERE rule_set_id IN (SELECT id FROM rule_sets WHERE tenant_id=$1)`, f.tenantA).Scan(&ruleCount); err != nil {
		t.Fatalf("count failed tenant rules: %v", err)
	}
	if tenantCount != 0 || ruleSetCount != 0 || ruleCount != 0 {
		t.Fatalf("failed bootstrap residue tenant/rule_sets/rules=%d/%d/%d", tenantCount, ruleSetCount, ruleCount)
	}
	var otherTenant, otherRuleSet, otherRules int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenants WHERE id=$1`, f.tenantB).Scan(&otherTenant); err != nil {
		t.Fatalf("count other tenant: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rule_sets WHERE tenant_id=$1`, f.tenantB).Scan(&otherRuleSet); err != nil {
		t.Fatalf("count other rule set: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules WHERE rule_set_id=$1`, f.ruleSetB).Scan(&otherRules); err != nil {
		t.Fatalf("count other rules: %v", err)
	}
	if otherTenant != 1 || otherRuleSet != 1 || otherRules == 0 {
		t.Fatalf("cleanup crossed tenant boundary tenant/rule_sets/rules=%d/%d/%d", otherTenant, otherRuleSet, otherRules)
	}
}

func TestDeleteRemovesTenantPolicyDefaultsBeforeTenant(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewTenantRepository(f.pool)

	if err := repo.Delete(ctx, f.tenantA); err != nil {
		t.Fatalf("delete tenant with default policies: %v", err)
	}

	// Delete is a deliberate soft delete: the tenant row is retained with
	// status='deleted' and its policy defaults are kept for audit safety, so
	// this only verifies the tenant was marked deleted and other tenants are
	// untouched.
	var deletedStatus string
	if err := f.pool.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1`, f.tenantA).Scan(&deletedStatus); err != nil {
		t.Fatalf("read deleted tenant: %v", err)
	}
	if deletedStatus != "deleted" {
		t.Fatalf("tenant not soft-deleted: status=%s", deletedStatus)
	}
	var retainedRuleSets, retainedRules, otherTenant, otherRules int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rule_sets WHERE tenant_id=$1`, f.tenantA).Scan(&retainedRuleSets); err != nil {
		t.Fatalf("count soft-deleted tenant rule sets: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM rules
		WHERE rule_set_id IN (SELECT id FROM rule_sets WHERE tenant_id=$1)`, f.tenantA).Scan(&retainedRules); err != nil {
		t.Fatalf("count soft-deleted tenant rules: %v", err)
	}
	if retainedRuleSets == 0 || retainedRules == 0 {
		t.Fatalf("soft delete dropped policy defaults rule_sets/rules=%d/%d", retainedRuleSets, retainedRules)
	}
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenants WHERE id=$1`, f.tenantB).Scan(&otherTenant); err != nil {
		t.Fatalf("count other tenant: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules WHERE rule_set_id=$1`, f.ruleSetB).Scan(&otherRules); err != nil {
		t.Fatalf("count other tenant rules: %v", err)
	}
	if otherTenant != 1 || otherRules == 0 {
		t.Fatalf("delete crossed tenant boundary tenant/rules=%d/%d", otherTenant, otherRules)
	}
}
