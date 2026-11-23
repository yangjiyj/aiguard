package repository

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSecurityRedactionValidationAndScope(t *testing.T) {
	for _, value := range []string{"", " ", "line\nbreak", "zero\x00", strings.Repeat("界", 129), "<JJD_reserved>"} {
		if _, err := NormalizeSecurityPolicyRedaction(&SecurityPolicyRedaction{Replacement: value}); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	scope, err := scopeWithRedaction([]byte(`{"scene":"data_security","subject_binding":{"project_ids":["one"]}}`), &SecurityPolicyRedaction{Replacement: "[姓名]", RestoreResponse: true})
	if err != nil {
		t.Fatal(err)
	}
	setting, ok := ParseSecurityPolicyRedaction(scope)
	if !ok || setting.Replacement != "[姓名]" || !setting.RestoreResponse || !strings.Contains(string(scope), "subject_binding") {
		t.Fatalf("bad scope %s", scope)
	}
	for _, raw := range []string{`{"redaction":{"replacement":"x","restore_response":"yes"}}`, `{"redaction":{"replacement":"x","unexpected":true}}`} {
		if _, ok := ParseSecurityPolicyRedaction([]byte(raw)); ok {
			t.Fatalf("accepted invalid redaction: %s", raw)
		}
	}
}

func TestSecurityRedactionSystemOverrideTenantIsolation(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	migration, err := os.ReadFile("../../../../deploy/migrations/950_security_redaction_rules.sql")
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := f.pool.Exec(ctx, string(migration)); err != nil {
			t.Fatal(err)
		}
	}
	setting := &SecurityPolicyRedaction{Replacement: "[手机号]", RestoreResponse: true}
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_phone", SecurityPolicyUpdate{Redaction: setting})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Redaction == nil || *updated.Redaction != *setting {
		t.Fatalf("setting not returned: %#v", updated.Redaction)
	}
	other, err := f.repo.GetSecurityPolicy(ctx, f.tenantB, "rule_g_phone")
	if err != nil {
		t.Fatal(err)
	}
	if other.Redaction != nil {
		t.Fatal("shared system policy changed for another tenant")
	}
	rules, err := f.repo.ListCompilableRulesByTenant(ctx, f.tenantA, "generic")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rule := range rules {
		if rule.ID == "rule_g_phone" {
			parsed, ok := ParseSecurityPolicyRedaction(rule.ScopeJSON)
			found = ok && parsed != nil && parsed.RestoreResponse
		}
	}
	if !found {
		t.Fatal("tenant override missing from runtime rule scope")
	}
	var globalScope []byte
	if err := f.pool.QueryRow(ctx, `SELECT scope_json FROM rules WHERE id='rule_g_phone'`).Scan(&globalScope); err != nil {
		t.Fatal(err)
	}
	var scope map[string]any
	_ = json.Unmarshal(globalScope, &scope)
	if scope["redaction"] != nil {
		t.Fatal("tenant redaction mutated shared system definition")
	}
}
