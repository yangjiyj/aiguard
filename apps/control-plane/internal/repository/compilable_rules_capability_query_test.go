package repository

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildCompilableRulesQueryAggregatesRuntimeCapabilitiesInOneQuery(t *testing.T) {
	query, args := buildCompilableRulesQuery("tenant_demo", "finance")
	if len(args) != 3 {
		t.Fatalf("args=%#v want exactly tenant/system/industry inputs", args)
	}
	for _, want := range []string{
		"COALESCE(r.policy_code, '')",
		"LEFT JOIN LATERAL",
		"rule_capability_bindings",
		"security_capabilities",
		"jsonb_agg",
		"bro.capability_categories IS NULL",
		"bro.capability_categories IS NOT NULL",
		"bro.capability_categories ? capability.category",
		"'binding_mode', selected.binding_mode",
		"'category'",
		"'binding_mode'",
		"'supported_stages'",
		"'allowed_actions'",
		"'mask_capable'",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("runtime capability aggregation missing %q:\n%s", want, query)
		}
	}
}

func TestRuntimePolicyCapabilityDecodesDatabaseJSONContract(t *testing.T) {
	var got []RuntimePolicyCapability
	err := json.Unmarshal([]byte(`[{"category":"phone_cn","binding_mode":"all","enabled":true,"supported_stages":["input"],"allowed_actions":["audit","block"],"mask_capable":false}]`), &got)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("capabilities=%d want 1", len(got))
	}
	capability := got[0]
	if capability.Category != "phone_cn" || capability.BindingMode != "all" || !capability.Enabled {
		t.Fatalf("identity contract lost during decode: %+v", capability)
	}
	if len(capability.SupportedStages) != 1 || capability.SupportedStages[0] != "input" ||
		len(capability.AllowedActions) != 2 || capability.MaskCapable {
		t.Fatalf("runtime contract lost during decode: %+v", capability)
	}
}

func requireCompilableRule(t *testing.T, rules []*Rule, id string) *Rule {
	t.Helper()
	for _, rule := range rules {
		if rule.ID == id {
			return rule
		}
	}
	t.Fatalf("compilable rule %s not found", id)
	return nil
}

func TestListCompilableRulesUsesTenantCapabilityOverride(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
		SELECT 'rule_g_phone',id,'any',50,'{}'::jsonb
		FROM security_capabilities WHERE category='phone_cn'
		ON CONFLICT(rule_id,capability_id) DO UPDATE
		SET binding_mode=EXCLUDED.binding_mode,priority=EXCLUDED.priority`); err != nil {
		t.Fatalf("seed product capability binding: %v", err)
	}

	rules, err := f.repo.ListCompilableRulesByTenant(ctx, f.tenantA, "generic")
	if err != nil {
		t.Fatalf("list inherited compilable rules: %v", err)
	}
	inherited := requireCompilableRule(t, rules, "rule_g_phone")
	if len(inherited.RuntimeCapabilities) != 1 ||
		inherited.RuntimeCapabilities[0].Category != "phone_cn" ||
		inherited.RuntimeCapabilities[0].BindingMode != "any" {
		t.Fatalf("inherited capability mismatch: %+v", inherited.RuntimeCapabilities)
	}

	if _, err := f.pool.Exec(ctx, `
		INSERT INTO builtin_rule_overrides(
			tenant_id,rule_id,capability_categories,binding_mode
		) VALUES($1,'rule_g_phone','["email"]'::jsonb,'all')`,
		f.tenantA); err != nil {
		t.Fatalf("insert tenant capability override: %v", err)
	}
	rules, err = f.repo.ListCompilableRulesByTenant(ctx, f.tenantA, "generic")
	if err != nil {
		t.Fatalf("list overridden compilable rules: %v", err)
	}
	overridden := requireCompilableRule(t, rules, "rule_g_phone")
	if len(overridden.RuntimeCapabilities) != 1 ||
		overridden.RuntimeCapabilities[0].Category != "email" ||
		overridden.RuntimeCapabilities[0].BindingMode != "all" {
		t.Fatalf("tenant override mismatch: %+v", overridden.RuntimeCapabilities)
	}

	if _, err := f.pool.Exec(ctx, `
		UPDATE builtin_rule_overrides
		SET capability_categories='[]'::jsonb,binding_mode='any'
		WHERE tenant_id=$1 AND rule_id='rule_g_phone'`, f.tenantA); err != nil {
		t.Fatalf("clear tenant capability override: %v", err)
	}
	rules, err = f.repo.ListCompilableRulesByTenant(ctx, f.tenantA, "generic")
	if err != nil {
		t.Fatalf("list explicitly cleared compilable rules: %v", err)
	}
	cleared := requireCompilableRule(t, rules, "rule_g_phone")
	if len(cleared.RuntimeCapabilities) != 0 {
		t.Fatalf("explicit empty override inherited product bindings: %+v", cleared.RuntimeCapabilities)
	}
}
