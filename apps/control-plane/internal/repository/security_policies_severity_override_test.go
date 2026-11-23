package repository

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestSystemPolicySeverityOverrideIsTenantScoped(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	before, err := f.repo.GetSecurityPolicy(ctx, f.tenantB, "rule_g_passport")
	if err != nil {
		t.Fatalf("read tenant B policy: %v", err)
	}
	severity := "critical"
	if before.Severity == severity {
		severity = "low"
	}
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &severity})
	if err != nil {
		t.Fatalf("severity override rejected: %v", err)
	}
	if updated.Severity != severity {
		t.Fatalf("tenant A severity=%q want %q", updated.Severity, severity)
	}
	after, err := f.repo.GetSecurityPolicy(ctx, f.tenantB, "rule_g_passport")
	if err != nil || after.Severity != before.Severity {
		t.Fatalf("tenant B must keep %q, got %+v err=%v", before.Severity, after, err)
	}
	var stored string
	if err := f.pool.QueryRow(ctx, `SELECT severity FROM builtin_rule_overrides WHERE tenant_id=$1 AND rule_id='rule_g_passport'`, f.tenantA).Scan(&stored); err != nil || stored != severity {
		t.Fatalf("override row severity=%q err=%v", stored, err)
	}
}

func TestSystemPolicySeverityOverrideRejectsUnknownLevel(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	bad := "urgent"
	if _, err := f.repo.UpdateSecurityPolicy(context.Background(), f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &bad}); err == nil {
		t.Fatal("unknown severity must be rejected")
	} else if !errors.Is(err, ErrInvalidSecurityPolicy) {
		t.Fatalf("error=%v want ErrInvalidSecurityPolicy", err)
	}
	var rows int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM builtin_rule_overrides WHERE tenant_id=$1 AND rule_id='rule_g_passport' AND severity IS NOT NULL`, f.tenantA).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("rejected severity must not be stored: rows=%d err=%v", rows, err)
	}
}

func TestCompilableRulesBehaviorCarriesTenantSeverityOverride(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	severityOf := func(tenant, industry string) string {
		rules, err := f.repo.ListCompilableRulesByTenant(ctx, tenant, industry)
		if err != nil {
			t.Fatalf("compile rules for %s: %v", tenant, err)
		}
		for _, rule := range rules {
			if rule.ID == "rule_g_passport" {
				return rule.Severity
			}
		}
		t.Fatalf("rule_g_passport missing from compiled rules of %s", tenant)
		return ""
	}
	beforeB := severityOf(f.tenantB, "finance")
	severity := "critical"
	if beforeB == severity {
		severity = "low"
	}
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &severity}); err != nil {
		t.Fatalf("override: %v", err)
	}
	if got := severityOf(f.tenantA, "generic"); got != severity {
		t.Fatalf("tenant A compiled severity=%q want %q", got, severity)
	}
	if got := severityOf(f.tenantB, "finance"); got != beforeB {
		t.Fatalf("tenant B compiled severity=%q want %q", got, beforeB)
	}
}

func TestPolicyAssetsReturnTheTenantSeverityOverride(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	find := func(tenant, industry string) string {
		assets, err := f.repo.ListPolicyAssets(ctx, tenant, industry)
		if err != nil {
			t.Fatalf("list assets for %s: %v", tenant, err)
		}
		for _, asset := range assets {
			if asset.ID == "rule_g_passport" {
				return asset.Severity
			}
		}
		t.Fatalf("rule_g_passport missing from assets of %s", tenant)
		return ""
	}
	beforeB := find(f.tenantB, "finance")
	severity := "critical"
	if beforeB == severity {
		severity = "low"
	}
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &severity}); err != nil {
		t.Fatalf("override: %v", err)
	}
	if got := find(f.tenantA, "generic"); got != severity {
		t.Fatalf("tenant A asset severity=%q want %q", got, severity)
	}
	if got := find(f.tenantB, "finance"); got != beforeB {
		t.Fatalf("tenant B asset severity=%q want %q", got, beforeB)
	}
}

func TestTenantOwnedPreloadedPolicySeverityCanBeChanged(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	policies, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	preloaded := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool {
		return strings.HasPrefix(policy.PolicyCode, "builtin.")
	})
	severity := "critical"
	if preloaded.Severity == severity {
		severity = "low"
	}
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, preloaded.ID, SecurityPolicyUpdate{Severity: &severity})
	if err != nil {
		t.Fatalf("severity-only update rejected: %v", err)
	}
	if updated.Severity != severity {
		t.Fatalf("severity=%q want %q", updated.Severity, severity)
	}
	var stored string
	var overrides int
	if err := f.pool.QueryRow(ctx, `SELECT severity FROM rules WHERE id=$1`, preloaded.ID).Scan(&stored); err != nil || stored != severity {
		t.Fatalf("rules.severity=%q err=%v", stored, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM builtin_rule_overrides WHERE tenant_id=$1 AND rule_id=$2`, f.tenantA, preloaded.ID).Scan(&overrides); err != nil || overrides != 0 {
		t.Fatalf("tenant-owned copy must not create override rows: n=%d err=%v", overrides, err)
	}
}

func severityOverrideRow(t *testing.T, f securityPoliciesFixture, tenant, rule string) (exists bool, severity *string, action *string) {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT severity, action FROM builtin_rule_overrides WHERE tenant_id=$1 AND rule_id=$2`, tenant, rule)
	if err != nil {
		t.Fatalf("read override row: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&severity, &action); err != nil {
			t.Fatalf("scan override row: %v", err)
		}
		exists = true
	}
	return exists, severity, action
}

func otherSeverity(base string) string {
	if base == "critical" {
		return "low"
	}
	return "critical"
}

func TestSystemPolicySeverityResetToDefaultRemovesTheOverrideRow(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	base, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_g_passport")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if base.SeverityOverridden || base.DefaultSeverity != base.Severity {
		t.Fatalf("untouched policy default=%q severity=%q overridden=%v", base.DefaultSeverity, base.Severity, base.SeverityOverridden)
	}
	custom := otherSeverity(base.Severity)
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &custom})
	if err != nil {
		t.Fatalf("override: %v", err)
	}
	if !updated.SeverityOverridden || updated.DefaultSeverity != base.Severity || updated.PreviousSeverity != base.Severity {
		t.Fatalf("overridden policy default=%q overridden=%v previous=%q", updated.DefaultSeverity, updated.SeverityOverridden, updated.PreviousSeverity)
	}
	defaultSeverity := base.Severity
	reset, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &defaultSeverity})
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if reset.Severity != base.Severity || reset.SeverityOverridden || reset.PreviousSeverity != custom {
		t.Fatalf("reset severity=%q overridden=%v previous=%q", reset.Severity, reset.SeverityOverridden, reset.PreviousSeverity)
	}
	if exists, _, _ := severityOverrideRow(t, f, f.tenantA, "rule_g_passport"); exists {
		t.Fatal("a severity-only override must be deleted when reset to the default")
	}
	// 之后基准级别变化（任务 10 重新定级），租户 A 必须跟随。
	newBase := otherSeverity(base.Severity)
	if _, err := f.pool.Exec(ctx, `UPDATE rules SET severity=$1 WHERE id='rule_g_passport'`, newBase); err != nil {
		t.Fatalf("rebase: %v", err)
	}
	after, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_g_passport")
	if err != nil || after.Severity != newBase || after.DefaultSeverity != newBase {
		t.Fatalf("tenant A must follow the new base %q, got %+v err=%v", newBase, after, err)
	}
}

func TestSystemPolicySeverityResetKeepsOtherOverrides(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	base, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_g_passport")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	audit := "audit"
	custom := otherSeverity(base.Severity)
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Action: &audit}); err != nil {
		t.Fatalf("override action: %v", err)
	}
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &custom}); err != nil {
		t.Fatalf("override severity: %v", err)
	}
	defaultSeverity := base.Severity
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &defaultSeverity}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	exists, severity, action := severityOverrideRow(t, f, f.tenantA, "rule_g_passport")
	if !exists || severity != nil || action == nil || *action != "audit" {
		t.Fatalf("reset must only clear severity: exists=%v severity=%v action=%v", exists, severity, action)
	}
}

func TestSystemPolicySeverityResetWithoutOverrideWritesNothing(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	base, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_g_passport")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	same := base.Severity
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &same}); err != nil {
		t.Fatalf("submitting the default must succeed: %v", err)
	}
	if exists, _, _ := severityOverrideRow(t, f, f.tenantA, "rule_g_passport"); exists {
		t.Fatal("submitting the default level must not create an override row")
	}
}

func TestSeverityOnlyUpdateSkipsActionConfigurationValidation(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	bindSystemDefaultCapability(t, f, "rule_g_passport", "keyword_classic_injection", "any")
	// 存量动作与能力不配套（不允许 mask），仍应能只改级别。
	if _, err := f.pool.Exec(ctx, `UPDATE rules SET action='mask' WHERE id='rule_g_passport'`); err != nil {
		t.Fatalf("seed stale action: %v", err)
	}
	base, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_g_passport")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	custom := otherSeverity(base.Severity)
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &custom}); err != nil {
		t.Fatalf("severity-only update must not be blocked by the stored action: %v", err)
	}
	// 带上其它字段时照旧校验。
	enabled := true
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &custom, Enabled: &enabled}); !errors.Is(err, ErrPolicyActionUnsupported) {
		t.Fatalf("update with other fields must still validate, error=%v", err)
	}
}

func TestAuditActionAndSeverityCanBeChangedTogetherOnUnvalidatedSystemRegex(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	base, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_g_passport")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	audit := "audit"
	custom := otherSeverity(base.Severity)
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Action: &audit, Severity: &custom})
	if err != nil {
		t.Fatalf("audit action together with severity must pass: %v", err)
	}
	if updated.Severity != custom || updated.Action != "audit" {
		t.Fatalf("updated severity=%q action=%q", updated.Severity, updated.Action)
	}
	exists, severity, action := severityOverrideRow(t, f, f.tenantA, "rule_g_passport")
	if !exists || severity == nil || *severity != custom || action == nil || *action != "audit" {
		t.Fatalf("override row must hold both: exists=%v severity=%v action=%v", exists, severity, action)
	}
	// 带其它字段（redaction）时仍按原规则校验：未验证的 regex 不得借此通过。
	redaction := &SecurityPolicyRedaction{Replacement: "[x]"}
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Action: &audit, Severity: &custom, Redaction: redaction}); !errors.Is(err, ErrPolicyRuntimeValidation) {
		t.Fatalf("update with redaction must keep the original validation, error=%v", err)
	}
	// 非 audit 动作（block）同样仍要求运行时验证。
	block := "block"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Action: &block, Severity: &custom}); !errors.Is(err, ErrPolicyRuntimeValidation) {
		t.Fatalf("block with severity must keep the original validation, error=%v", err)
	}
}

func TestSeverityAndEnabledUpdatesOfTheSamePolicyDoNotDeadlock(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	const workers, rounds = 3, 30
	var wg sync.WaitGroup
	var mu sync.Mutex
	var deadlocks []string
	record := func(err error) {
		if err == nil {
			return
		}
		if strings.Contains(err.Error(), "40P01") {
			mu.Lock()
			deadlocks = append(deadlocks, err.Error())
			mu.Unlock()
			return
		}
		t.Errorf("unexpected update error: %v", err)
	}
	for worker := 0; worker < workers; worker++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for round := 0; round < rounds; round++ {
				severity := []string{"critical", "low", "medium"}[round%3]
				_, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &severity})
				record(err)
			}
		}()
		go func() {
			defer wg.Done()
			disabled := false
			for round := 0; round < rounds; round++ {
				_, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Enabled: &disabled})
				record(err)
			}
		}()
	}
	wg.Wait()
	if len(deadlocks) > 0 {
		t.Fatalf("lock order must be advisory lock then row lock; %d deadlocks, first: %s", len(deadlocks), deadlocks[0])
	}
}

func TestSystemPolicyEqualValueOverrideStaysVisibleAndCanBeCleared(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	critical := "critical"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &critical}); err != nil {
		t.Fatalf("override: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE rules SET severity='critical' WHERE id='rule_g_passport'`); err != nil {
		t.Fatalf("rebase: %v", err)
	}
	policy, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_g_passport")
	if err != nil || policy.Severity != "critical" || !policy.SeverityOverridden {
		t.Fatalf("equal-valued override must still read as overridden: %+v err=%v", policy, err)
	}
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Severity: &critical}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	policy, err = f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_g_passport")
	if err != nil || policy.SeverityOverridden {
		t.Fatalf("reset must clear the equal-valued override: %+v err=%v", policy, err)
	}
	if exists, _, _ := severityOverrideRow(t, f, f.tenantA, "rule_g_passport"); exists {
		t.Fatal("override row must be deleted")
	}
}

func insertTenantRegexPolicy(t *testing.T, f securityPoliciesFixture, id string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO rules(id,rule_set_id,policy_code,rule_type,name,severity,scope_json,match_config_json,action,enabled,description)
		VALUES($1::varchar,$2,'custom.'||$1::text,'regex','租户正则','high','{"scene":"data_leak"}','{"regex":"abc"}','audit',true,'')`, id, f.ruleSetA); err != nil {
		t.Fatalf("insert tenant regex policy: %v", err)
	}
}

func TestTenantOwnedPolicyHasNoDefaultSeverityAndIsNeverOverridden(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	insertTenantRegexPolicy(t, f, "rule_t9_own")
	policy, err := f.repo.GetSecurityPolicy(context.Background(), f.tenantA, "rule_t9_own")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if policy.Source != "tenant" || policy.DefaultSeverity != "" || policy.SeverityOverridden {
		t.Fatalf("tenant-owned policy default=%q overridden=%v source=%q", policy.DefaultSeverity, policy.SeverityOverridden, policy.Source)
	}
}

func TestTenantOwnedUnvalidatedRegexSeverityOnlyUpdateSkipsRuntimeValidation(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	insertTenantRegexPolicy(t, f, "rule_t9_regex")
	severity := "critical"
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_t9_regex", SecurityPolicyUpdate{Severity: &severity})
	if err != nil || updated.Severity != severity {
		t.Fatalf("severity-only update of an unvalidated enabled regex: %+v err=%v", updated, err)
	}
	name := "改名"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_t9_regex", SecurityPolicyUpdate{Severity: &severity, Name: &name}); !errors.Is(err, ErrPolicyRuntimeValidation) {
		t.Fatalf("update with other fields must keep the validation, error=%v", err)
	}
}
