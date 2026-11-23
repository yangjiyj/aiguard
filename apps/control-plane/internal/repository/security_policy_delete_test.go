package repository

import (
	"context"
	"errors"
	"testing"
)

// The shared fixture has neither security_events nor content_audit_exceptions. Only the foreign keys
// matter here: a policy that has ever fired is referenced by security_events.rule_id and cannot be
// removed from rules, and exceptions (ON DELETE CASCADE) must go away together with their policy.
func newPolicyDeleteFixture(t *testing.T) securityPoliciesFixture {
	t.Helper()
	f := newSecurityPoliciesFixture(t)
	for _, stmt := range []string{
		`CREATE TABLE security_events (id VARCHAR(64) PRIMARY KEY, rule_id VARCHAR(64) REFERENCES rules(id))`,
		`CREATE TABLE content_audit_exceptions (
			id VARCHAR(64) PRIMARY KEY,
			tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			scope_type VARCHAR(32) NOT NULL,
			scope_ref VARCHAR(255) NOT NULL DEFAULT '',
			include_children BOOLEAN NOT NULL DEFAULT FALSE,
			rule_id VARCHAR(64) REFERENCES rules(id) ON DELETE CASCADE,
			rule_ref TEXT,
			decision VARCHAR(16) NOT NULL,
			reason TEXT NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE,
			enabled BOOLEAN NOT NULL,
			created_by VARCHAR(64),
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`,
	} {
		if _, err := f.pool.Exec(context.Background(), stmt); err != nil {
			t.Fatalf("extend delete fixture: %v", err)
		}
	}
	return f
}

func policyIDs(policies []SecurityPolicy) map[string]bool {
	ids := make(map[string]bool, len(policies))
	for _, policy := range policies {
		ids[policy.ID] = true
	}
	return ids
}

func TestDeleteSecurityPolicyRetiresOrganizationPolicyAndKeepsAuditHistory(t *testing.T) {
	f := newPolicyDeleteFixture(t)
	ctx := context.Background()

	custom, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "新手机号场景策略", Scene: "sensitive_data", Severity: "high", Action: "mask", Enabled: true,
		CapabilityCategories: []string{"phone_cn"}, BindingMode: "any",
	})
	if err != nil {
		t.Fatalf("create custom policy: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO security_events(id, rule_id) VALUES('evt-1', $1)`, custom.ID); err != nil {
		t.Fatalf("record an alert against the policy: %v", err)
	}
	before, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil || !policyIDs(before)[custom.ID] {
		t.Fatalf("custom policy must be listed before deletion err=%v", err)
	}

	compilable := func() map[string]bool {
		rules, err := f.repo.ListCompilableRulesByTenant(ctx, f.tenantA, "generic")
		if err != nil {
			t.Fatalf("list compilable rules: %v", err)
		}
		ids := map[string]bool{}
		for _, rule := range rules {
			ids[rule.ID] = true
		}
		return ids
	}
	if !compilable()[custom.ID] {
		t.Fatalf("custom policy must be part of the rule pack before deletion")
	}

	if err := f.repo.DeleteSecurityPolicy(ctx, f.tenantA, custom.ID); err != nil {
		t.Fatalf("delete a policy that has alerts: %v", err)
	}
	if compilable()[custom.ID] {
		t.Fatalf("deleted policy must not reach the runtime rule pack, even as a disabled row")
	}

	after, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil || policyIDs(after)[custom.ID] || len(after) != len(before)-1 {
		t.Fatalf("deleted policy still listed or wrong count: %d -> %d err=%v", len(before), len(after), err)
	}
	if _, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, custom.ID); !errors.Is(err, ErrSecurityPolicyNotFound) {
		t.Fatalf("GetSecurityPolicy after delete err=%v want ErrSecurityPolicyNotFound", err)
	}
	var enabled, tombstoned bool
	if err := f.pool.QueryRow(ctx, `SELECT enabled, jsonb_exists(scope_json,'deleted_at') FROM rules WHERE id=$1`, custom.ID).Scan(&enabled, &tombstoned); err != nil {
		t.Fatalf("the retired row must remain for audit joins: %v", err)
	}
	if enabled || !tombstoned {
		t.Fatalf("retired row enabled=%v tombstoned=%v want false/true", enabled, tombstoned)
	}
	var name string
	if err := f.pool.QueryRow(ctx, `SELECT r.name FROM security_events e JOIN rules r ON r.id=e.rule_id WHERE e.id='evt-1'`).Scan(&name); err != nil || name != custom.Name {
		t.Fatalf("historical alert lost its policy name: %q err=%v", name, err)
	}

	// a retired policy can be neither re-enabled, nor edited, nor deleted again
	enable := true
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, custom.ID, SecurityPolicyUpdate{Enabled: &enable}); !errors.Is(err, ErrSecurityPolicyNotFound) {
		t.Fatalf("update after delete err=%v want ErrSecurityPolicyNotFound", err)
	}
	if err := f.repo.BatchUpdateSecurityPolicies(ctx, f.tenantA, []SecurityPolicyBatchUpdate{{ID: custom.ID, Update: SecurityPolicyUpdate{Enabled: &enable}}}); !errors.Is(err, ErrSecurityPolicyNotFound) {
		t.Fatalf("batch update after delete err=%v want ErrSecurityPolicyNotFound", err)
	}
	if err := f.repo.DeleteSecurityPolicy(ctx, f.tenantA, custom.ID); !errors.Is(err, ErrSecurityPolicyNotFound) {
		t.Fatalf("second delete err=%v want ErrSecurityPolicyNotFound", err)
	}
}

func TestDeleteSecurityPolicyRefusesBuiltinAndOtherTenantsPolicies(t *testing.T) {
	f := newPolicyDeleteFixture(t)
	ctx := context.Background()
	policies, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}

	// builtin.* policy copied into the tenant's own rule set: it can be disabled, never deleted
	builtin := findSecurityPolicy(t, policies, func(p SecurityPolicy) bool { return p.Origin == "preloaded" && p.Source == "tenant" })
	if err := f.repo.DeleteSecurityPolicy(ctx, f.tenantA, builtin.ID); !errors.Is(err, ErrSecurityPolicyNotDeletable) {
		t.Fatalf("builtin delete err=%v want ErrSecurityPolicyNotDeletable", err)
	}
	// a shipped system policy owned by the platform tenant is refused the same way
	system := findSecurityPolicy(t, policies, func(p SecurityPolicy) bool { return p.Source == "system" })
	if err := f.repo.DeleteSecurityPolicy(ctx, f.tenantA, system.ID); !errors.Is(err, ErrSecurityPolicyNotDeletable) {
		t.Fatalf("system delete err=%v want ErrSecurityPolicyNotDeletable", err)
	}
	for _, id := range []string{builtin.ID, system.ID} {
		if _, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, id); err != nil {
			t.Fatalf("a refused delete must leave policy %s in place: %v", id, err)
		}
	}

	custom, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "客户草稿策略", Scene: "content_safety", Severity: "medium", Action: "audit", Enabled: false,
	})
	if err != nil {
		t.Fatalf("create custom policy: %v", err)
	}
	// tenant B cannot see, and therefore cannot delete, tenant A's policy
	if err := f.repo.DeleteSecurityPolicy(ctx, f.tenantB, custom.ID); !errors.Is(err, ErrSecurityPolicyNotFound) {
		t.Fatalf("cross-tenant delete err=%v want ErrSecurityPolicyNotFound", err)
	}
	if _, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, custom.ID); err != nil {
		t.Fatalf("cross-tenant delete must not touch the policy: %v", err)
	}
	if err := f.repo.DeleteSecurityPolicy(ctx, f.tenantA, custom.ID); err != nil {
		t.Fatalf("owner delete of a custom policy: %v", err)
	}
}

func TestLegacyRuleDeleteRetiresInsteadOfFailingWhenAlertsReferenceIt(t *testing.T) {
	f := newPolicyDeleteFixture(t)
	ctx := context.Background()

	for _, id := range []string{"legacy_fired", "legacy_quiet"} {
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO rules(id,rule_set_id,rule_type,name,severity,match_config_json,action,enabled)
			VALUES($1,$2,'keyword',$1,'high','{"keywords":["x"]}'::jsonb,'audit',true)`, id, f.ruleSetA); err != nil {
			t.Fatalf("insert legacy rule %s: %v", id, err)
		}
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO security_events(id, rule_id) VALUES('evt-legacy', 'legacy_fired')`); err != nil {
		t.Fatalf("record an alert against the legacy rule: %v", err)
	}
	if err := f.repo.Delete(ctx, f.tenantA, "legacy_fired"); err != nil {
		t.Fatalf("legacy delete of a rule with alerts must succeed: %v", err)
	}
	if rule, err := f.repo.GetByID(ctx, f.tenantA, "legacy_fired"); err != nil || rule != nil {
		t.Fatalf("retired legacy rule must read as gone rule=%v err=%v", rule, err)
	}
	var enabled, tombstoned bool
	if err := f.pool.QueryRow(ctx, `SELECT enabled, jsonb_exists(scope_json,'deleted_at') FROM rules WHERE id='legacy_fired'`).Scan(&enabled, &tombstoned); err != nil || enabled || !tombstoned {
		t.Fatalf("legacy rule row must remain as a disabled tombstone enabled=%v tombstoned=%v err=%v", enabled, tombstoned, err)
	}

	// without alerts the row is removed for real, exactly as before
	if err := f.repo.Delete(ctx, f.tenantA, "legacy_quiet"); err != nil {
		t.Fatalf("legacy delete without alerts: %v", err)
	}
	var left int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rules WHERE id='legacy_quiet'`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("rule without alerts should be hard-deleted left=%d err=%v", left, err)
	}
}

func countExceptionsFor(t *testing.T, f securityPoliciesFixture, ruleID string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM content_audit_exceptions WHERE rule_id=$1 OR rule_ref=$1`, ruleID).Scan(&n); err != nil {
		t.Fatalf("count exceptions: %v", err)
	}
	return n
}

// A permanent "allow" exception of a deleted policy must not outlive it: it would stay active, stay in
// the exception list and keep being shipped to the engine. A real delete cascades them away; the
// tombstone has to do the same.
func TestDeleteSecurityPolicyRemovesItsExceptionsButNotOthers(t *testing.T) {
	f := newPolicyDeleteFixture(t)
	ctx := context.Background()
	mk := func(name string) *SecurityPolicy {
		p, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
			Name: name, Scene: "sensitive_data", Severity: "high", Action: "block", Enabled: true,
			CapabilityCategories: []string{"phone_cn"}, BindingMode: "any",
		})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return p
	}
	doomed, kept := mk("将被删除的策略"), mk("保留的策略")
	for _, row := range []struct{ id, ruleID, ruleRef string }{
		{"exc-by-id", doomed.ID, ""},           // linked through the foreign key
		{"exc-by-ref", "", doomed.ID},          // referenced by rule_ref only
		{"exc-other-policy", kept.ID, kept.ID}, // belongs to a policy that stays
		{"exc-tenant-wide", "", ""},            // not tied to any policy
	} {
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO content_audit_exceptions(id,tenant_id,scope_type,scope_ref,rule_id,rule_ref,decision,reason,enabled)
			VALUES($1,$2,'rule','',NULLIF($3,''),NULLIF($4,''),'allow','e2e',true)`,
			row.id, f.tenantA, row.ruleID, row.ruleRef); err != nil {
			t.Fatalf("insert exception %s: %v", row.id, err)
		}
	}

	if err := f.repo.DeleteSecurityPolicy(ctx, f.tenantA, doomed.ID); err != nil {
		t.Fatalf("delete policy: %v", err)
	}
	if n := countExceptionsFor(t, f, doomed.ID); n != 0 {
		t.Fatalf("exceptions of the deleted policy must be removed with it, %d left", n)
	}
	active, err := f.repo.ListActiveContentAuditExceptionsByTenant(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list active exceptions: %v", err)
	}
	got := map[string]bool{}
	for _, e := range active {
		got[e.ID] = true
	}
	if got["exc-by-id"] || got["exc-by-ref"] {
		t.Fatalf("deleted policy's exceptions are still shipped to the engine: %v", got)
	}
	if !got["exc-other-policy"] || !got["exc-tenant-wide"] {
		t.Fatalf("unrelated exceptions must survive the delete: %v", got)
	}
}

// A retired legacy rule behaves like a deleted one for every legacy mutation too: no edit, no toggle,
// no batch update can revive it, and its exceptions go away like they would with a real delete.
func TestRetiredLegacyRuleCannotBeRevivedAndLosesItsExceptions(t *testing.T) {
	f := newPolicyDeleteFixture(t)
	ctx := context.Background()
	for _, id := range []string{"legacy_fired", "legacy_live"} {
		if _, err := f.pool.Exec(ctx, `
			INSERT INTO rules(id,rule_set_id,rule_type,name,severity,match_config_json,action,enabled)
			VALUES($1,$2,'keyword',$1,'high','{"keywords":["x"]}'::jsonb,'audit',true)`, id, f.ruleSetA); err != nil {
			t.Fatalf("insert legacy rule %s: %v", id, err)
		}
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO security_events(id, rule_id) VALUES('evt-legacy', 'legacy_fired')`); err != nil {
		t.Fatalf("record an alert against the legacy rule: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO content_audit_exceptions(id,tenant_id,scope_type,scope_ref,rule_id,rule_ref,decision,reason,enabled)
		VALUES('exc-legacy',$1,'rule','','legacy_fired','legacy_fired','allow','e2e',true)`, f.tenantA); err != nil {
		t.Fatalf("insert exception: %v", err)
	}
	if err := f.repo.Delete(ctx, f.tenantA, "legacy_fired"); err != nil {
		t.Fatalf("legacy delete with alerts: %v", err)
	}
	if n := countExceptionsFor(t, f, "legacy_fired"); n != 0 {
		t.Fatalf("exceptions of the retired legacy rule must be removed, %d left", n)
	}

	if err := f.repo.Update(ctx, f.tenantA, "legacy_fired", "block", "high", 5, true, "复活"); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("Update of a retired rule err=%v want ErrRuleNotFound", err)
	}
	if _, err := f.repo.ToggleEnabled(ctx, f.tenantA, "legacy_fired"); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("ToggleEnabled of a retired rule err=%v want ErrRuleNotFound", err)
	}
	if err := f.repo.Delete(ctx, f.tenantA, "legacy_fired"); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("second Delete of a retired rule err=%v want ErrRuleNotFound", err)
	}
	enable := true
	if err := f.repo.BatchUpdateByType(ctx, f.tenantA, f.ruleSetA, "keyword", &enable, nil, nil); err != nil {
		t.Fatalf("batch update of the live rules: %v", err)
	}
	var retiredEnabled, liveEnabled bool
	if err := f.pool.QueryRow(ctx, `SELECT enabled FROM rules WHERE id='legacy_fired'`).Scan(&retiredEnabled); err != nil || retiredEnabled {
		t.Fatalf("batch update must not re-enable the retired rule enabled=%v err=%v", retiredEnabled, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT enabled FROM rules WHERE id='legacy_live'`).Scan(&liveEnabled); err != nil || !liveEnabled {
		t.Fatalf("the live rule should still be updated enabled=%v err=%v", liveEnabled, err)
	}
}
