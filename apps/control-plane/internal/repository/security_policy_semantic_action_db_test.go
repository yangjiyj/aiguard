package repository

import (
	"context"
	"errors"
	"testing"
)

func markSemanticJudgeCapability(t *testing.T, f securityPoliciesFixture, category string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE security_capabilities SET component=$2 WHERE category=$1`, category, SemanticJudgeComponent); err != nil {
		t.Fatalf("mark semantic judge capability: %v", err)
	}
}

func compiledSemanticAction(t *testing.T, f securityPoliciesFixture, tenantID, ruleID string) string {
	t.Helper()
	rules, err := f.repo.ListCompilableRulesByTenant(context.Background(), tenantID, "generic")
	if err != nil {
		t.Fatalf("list compilable rules: %v", err)
	}
	for _, rule := range rules {
		if rule.ID == ruleID {
			return ParseSecurityPolicySemanticAction(rule.ScopeJSON)
		}
	}
	t.Fatalf("rule %s not compiled for %s", ruleID, tenantID)
	return ""
}

// 预置策略：「智能分析命中时」只写本租户覆盖，不改共享定义；缺省 audit，可切到 block/observe 再切回。
func TestSystemPolicySemanticActionOverrideIsTenantScopedAndCompiled(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	markSemanticJudgeCapability(t, f, "semantic_roleplay")
	bindSystemDefaultCapability(t, f, "rule_g_passport", "semantic_roleplay", "any")
	ctx := context.Background()

	before, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_g_passport")
	if err != nil || before.SemanticAction != SemanticActionAudit {
		t.Fatalf("default semantic action=%q err=%v, want audit", before.SemanticAction, err)
	}
	block := "block"
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{SemanticAction: &block})
	if err != nil || updated.SemanticAction != "block" {
		t.Fatalf("update semantic action=%#v err=%v", updated, err)
	}
	if got := compiledSemanticAction(t, f, f.tenantA, "rule_g_passport"); got != "block" {
		t.Fatalf("compiled tenant A semantic action=%q, want block", got)
	}
	other, err := f.repo.GetSecurityPolicy(ctx, f.tenantB, "rule_g_passport")
	if err != nil || other.SemanticAction != SemanticActionAudit {
		t.Fatalf("tenant B must keep audit: %#v err=%v", other, err)
	}
	if got := compiledSemanticAction(t, f, f.tenantB, "rule_g_passport"); got != SemanticActionAudit {
		t.Fatalf("compiled tenant B semantic action=%q, want audit", got)
	}
	var shared []byte
	if err := f.pool.QueryRow(ctx, `SELECT scope_json FROM rules WHERE id='rule_g_passport'`).Scan(&shared); err != nil {
		t.Fatalf("read shared definition: %v", err)
	}
	if ParseSecurityPolicySemanticAction(shared) != SemanticActionAudit {
		t.Fatalf("shared system definition was modified: %s", shared)
	}
	audit := "audit"
	reset, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{SemanticAction: &audit})
	if err != nil || reset.SemanticAction != SemanticActionAudit {
		t.Fatalf("reset semantic action=%#v err=%v", reset, err)
	}
	invalid := "mask"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{SemanticAction: &invalid}); !errors.Is(err, ErrInvalidSecurityPolicy) {
		t.Fatalf("invalid semantic action err=%v", err)
	}
}

func TestSemanticActionRequiresSemanticCapability(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	bindSystemDefaultCapability(t, f, "rule_g_passport", "email", "any")
	block := "block"
	if _, err := f.repo.UpdateSecurityPolicy(context.Background(), f.tenantA, "rule_g_passport", SecurityPolicyUpdate{SemanticAction: &block}); !errors.Is(err, ErrInvalidSecurityPolicy) {
		t.Fatalf("semantic block without semantic capability err=%v", err)
	}
}

// 租户自建策略：存放在 scope_json.semantic_action；切回 audit 时删除该键。
func TestTenantPolicySemanticActionRoundTrip(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	markSemanticJudgeCapability(t, f, "semantic_roleplay")
	ctx := context.Background()
	created, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "语义角色扮演拦截", Scene: "prompt_injection", Severity: "high", Action: "audit", Enabled: true,
		CapabilityCategories: []string{"semantic_roleplay"}, BindingMode: "any", SemanticAction: "block",
	})
	if err != nil || created.SemanticAction != "block" {
		t.Fatalf("create=%#v err=%v", created, err)
	}
	if got := compiledSemanticAction(t, f, f.tenantA, created.ID); got != "block" {
		t.Fatalf("compiled tenant policy semantic action=%q", got)
	}
	observe := "observe"
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, created.ID, SecurityPolicyUpdate{SemanticAction: &observe})
	if err != nil || updated.SemanticAction != "observe" {
		t.Fatalf("update=%#v err=%v", updated, err)
	}
	audit := "audit"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, created.ID, SecurityPolicyUpdate{SemanticAction: &audit}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	var scope []byte
	if err := f.pool.QueryRow(ctx, `SELECT scope_json FROM rules WHERE id=$1`, created.ID).Scan(&scope); err != nil {
		t.Fatalf("read scope: %v", err)
	}
	if ParseSecurityPolicySemanticAction(scope) != SemanticActionAudit || string(scope) == "" {
		t.Fatalf("scope after reset=%s", scope)
	}
	if _, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "邮箱语义拦截", Scene: "data_leak", Severity: "high", Action: "audit", Enabled: true,
		CapabilityCategories: []string{"email"}, BindingMode: "any", SemanticAction: "block",
	}); !errors.Is(err, ErrInvalidSecurityPolicy) {
		t.Fatalf("semantic block on a non-semantic policy err=%v", err)
	}
}
