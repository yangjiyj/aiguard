package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestRuleIsCapabilityCatalogUsesStablePolicyCodeAfterRename(t *testing.T) {
	renamedBuiltin := &Rule{
		PolicyCode: "builtin.prompt_injection.8894ce9a632bada9",
		RuleType:   "prompt_injection",
		Name:       "客户改过的展示名称",
	}
	if !RuleIsCapabilityCatalog(renamedBuiltin) {
		t.Fatal("renamed built-in policy was not protected by its stable policy code")
	}

	custom := &Rule{
		PolicyCode: "custom.018f7ec0-0000-7000-8000-000000000001",
		RuleType:   "prompt_injection",
		Name:       "经典注入指令检测",
	}
	if RuleIsCapabilityCatalog(custom) {
		t.Fatal("custom policy was mistaken for an immutable built-in policy")
	}
}

func TestSecurityPolicyJSONHidesInternalCodesAndComponents(t *testing.T) {
	policy := SecurityPolicy{
		ID: "rule_public", PolicyCode: "builtin.secret.internal", Name: "客户可见策略",
		Ownership: "organization", Origin: "preloaded",
		Capabilities: []SecurityPolicyCapability{{
			ID: "cap.static.phone_cn", Category: "phone_cn", Name: "手机号检测",
			Component: "security-engine.static-detectors",
		}},
	}
	body, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	encoded := string(body)
	for _, internal := range []string{"builtin.secret.internal", "cap.static.phone_cn", "security-engine.static-detectors"} {
		if strings.Contains(encoded, internal) {
			t.Fatalf("customer JSON leaked internal value %q: %s", internal, encoded)
		}
	}
	if !strings.Contains(encoded, `"category":"phone_cn"`) {
		t.Fatalf("customer JSON omitted stable capability category: %s", encoded)
	}
	for _, expected := range []string{`"ownership":"organization"`, `"origin":"preloaded"`} {
		if !strings.Contains(encoded, expected) {
			t.Fatalf("customer JSON omitted policy provenance %s: %s", expected, encoded)
		}
	}
}

func TestCapabilityBindingsStateRespectsAnyAndAllModes(t *testing.T) {
	partialAny := []SecurityPolicyCapability{
		{Category: "a", Enabled: true, BindingMode: "any"},
		{Category: "b", Enabled: false, BindingMode: "any"},
	}
	if ready, issue := capabilityBindingsState(partialAny); !ready || issue != "capability_unavailable" {
		t.Fatalf("partial any state=(%v,%q), want ready with degradation", ready, issue)
	}
	if ready, issue := capabilityRuntimeState(partialAny); !ready || issue != "capability_unavailable" {
		t.Fatalf("runtime partial any state=(%v,%q), want executable with degradation", ready, issue)
	}
	partialAll := []SecurityPolicyCapability{
		{Category: "a", Enabled: true, BindingMode: "all"},
		{Category: "b", Enabled: false, BindingMode: "all"},
	}
	if ready, issue := capabilityBindingsState(partialAll); ready || issue != "capability_unavailable" {
		t.Fatalf("partial all state=(%v,%q), want unavailable", ready, issue)
	}
	mixed := []SecurityPolicyCapability{
		{Category: "a", Enabled: true, BindingMode: "any"},
		{Category: "b", Enabled: true, BindingMode: "all"},
	}
	if ready, issue := capabilityBindingsState(mixed); ready || issue != "binding_mode_conflict" {
		t.Fatalf("mixed binding state=(%v,%q), want conflict", ready, issue)
	}
}

func TestBuiltinRuleOverridePatchMigrationAllowsPartialOverrides(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		CREATE TABLE builtin_rule_overrides (
 redaction_json JSONB,
 semantic_action VARCHAR(16),
			tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			rule_id VARCHAR(64) NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
			action TEXT NOT NULL CHECK(action IN ('audit','mask','block')),
			enabled BOOLEAN,
			PRIMARY KEY(tenant_id,rule_id)
		)`); err != nil {
		t.Fatalf("create pre-migration override table: %v", err)
	}
	body, err := os.ReadFile("../../../../deploy/migrations/126_nullable_builtin_rule_override_action.sql")
	if err != nil {
		t.Fatalf("read migration 126: %v", err)
	}
	if _, err := f.pool.Exec(ctx, string(body)); err != nil {
		t.Fatalf("apply migration 126: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO builtin_rule_overrides(tenant_id,rule_id,action,enabled)
		VALUES($1,$2,NULL,false)`, f.tenantA, f.runtimeA); err != nil {
		t.Fatalf("insert enabled-only partial override after migration: %v", err)
	}
	var action *string
	var enabled *bool
	if err := f.pool.QueryRow(ctx, `
		SELECT action,enabled FROM builtin_rule_overrides
		WHERE tenant_id=$1 AND rule_id=$2`, f.tenantA, f.runtimeA).Scan(&action, &enabled); err != nil {
		t.Fatalf("read partial override: %v", err)
	}
	if action != nil || enabled == nil || *enabled {
		t.Fatalf("partial override action=%v enabled=%v, want inherited action and false enabled", action, enabled)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO builtin_rule_overrides(tenant_id,rule_id,action,enabled)
		VALUES($1,$2,NULL,NULL)`, f.tenantA, f.catalogA); err == nil {
		t.Fatal("migration accepted an empty override row")
	}
}

type securityPoliciesFixture struct {
	rulesTenantFixture
	repo *RuleRepository
}

func newSecurityPoliciesFixture(t *testing.T) securityPoliciesFixture {
	t.Helper()
	base := newRulesTenantFixture(t)
	ctx := context.Background()
	for _, stmt := range []string{
		`ALTER TABLE tenants ADD COLUMN industry VARCHAR(64) NOT NULL DEFAULT 'generic'`,
		`ALTER TABLE rule_sets ADD COLUMN industry VARCHAR(64) NOT NULL DEFAULT 'generic'`,
		`ALTER TABLE security_capabilities ADD COLUMN name VARCHAR(255) NOT NULL DEFAULT ''`,
		`ALTER TABLE security_capabilities ADD COLUMN capability_kind VARCHAR(16) NOT NULL DEFAULT 'static'`,
		`ALTER TABLE security_capabilities ADD COLUMN component VARCHAR(128) NOT NULL DEFAULT 'security-engine.test'`,
		`ALTER TABLE security_capabilities ADD COLUMN supported_stages JSONB NOT NULL DEFAULT '["input","output"]'`,
		`ALTER TABLE security_capabilities ADD COLUMN allowed_actions JSONB NOT NULL DEFAULT '["audit","block"]'`,
		`ALTER TABLE security_capabilities ADD COLUMN mask_capable BOOLEAN NOT NULL DEFAULT FALSE`,
		`CREATE TABLE builtin_rule_overrides (
 severity VARCHAR(16) CHECK (severity IS NULL OR severity IN ('low','medium','high','critical')),
 redaction_json JSONB,
 semantic_action VARCHAR(16),
			tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			rule_id VARCHAR(64) NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
			action VARCHAR(32) CHECK(action IN ('audit','mask','block')),
			enabled BOOLEAN,
			capability_categories JSONB,
			binding_mode VARCHAR(8),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY(tenant_id,rule_id),
			CONSTRAINT ck_builtin_rule_overrides_capability_shape CHECK (
				(capability_categories IS NULL AND binding_mode IS NULL)
				OR (capability_categories IS NOT NULL AND jsonb_typeof(capability_categories)='array'
					AND binding_mode IS NOT NULL AND binding_mode IN ('any','all'))
			),
			CONSTRAINT ck_builtin_rule_overrides_has_value CHECK (
				action IS NOT NULL OR enabled IS NOT NULL OR capability_categories IS NOT NULL
				OR redaction_json IS NOT NULL OR semantic_action IS NOT NULL OR severity IS NOT NULL
			)
		)`,
	} {
		if _, err := base.pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("extend security policy fixture: %v", err)
		}
	}
	if _, err := base.pool.Exec(ctx, `UPDATE tenants SET industry=CASE id WHEN $1 THEN 'generic' WHEN $2 THEN 'finance' ELSE industry END`, base.tenantA, base.tenantB); err != nil {
		t.Fatalf("set fixture tenant industries: %v", err)
	}
	if _, err := base.pool.Exec(ctx, `
		UPDATE security_capabilities
		SET name=category,
		    allowed_actions=CASE WHEN category IN ('phone_cn','id_card_cn','bank_card_cn','email')
		                         THEN '["audit","mask","block"]'::jsonb
		                         ELSE '["audit","block"]'::jsonb END,
		    mask_capable=category IN ('phone_cn','id_card_cn','bank_card_cn','email')`); err != nil {
		t.Fatalf("complete fixture capabilities: %v", err)
	}
	if _, err := base.pool.Exec(ctx, `DELETE FROM rules`); err != nil {
		t.Fatalf("clear fixture rules: %v", err)
	}
	if _, err := base.pool.Exec(ctx, `DELETE FROM rule_sets`); err != nil {
		t.Fatalf("clear fixture rule sets: %v", err)
	}
	base.ruleSetA = DefaultSecurityRuleSetID(base.tenantA)
	base.ruleSetB = DefaultSecurityRuleSetID(base.tenantB)
	for _, item := range []struct{ id, tenant string }{{base.ruleSetA, base.tenantA}, {base.ruleSetB, base.tenantB}} {
		if _, err := base.pool.Exec(ctx, `
			INSERT INTO rule_sets(id,tenant_id,name,version,source_type,published,industry)
			VALUES($1,$2,'默认安全策略','1.0','system',true,'generic')`, item.id, item.tenant); err != nil {
			t.Fatalf("insert stable tenant rule set %s: %v", item.id, err)
		}
	}
	if _, err := base.pool.Exec(ctx, `INSERT INTO tenants(id,industry) VALUES($1,'generic')`, SystemTenantID); err != nil {
		t.Fatalf("insert system tenant: %v", err)
	}
	for _, item := range []struct {
		id, industry string
	}{
		{"ruleset_builtin_generic", "generic"},
		{"ruleset_builtin_medical", "medical"},
		{"ruleset_builtin_finance", "finance"},
	} {
		if _, err := base.pool.Exec(ctx, `
			INSERT INTO rule_sets(id,tenant_id,name,version,source_type,published,industry)
			VALUES($1,$2,$1,'1.0','builtin',true,$3)`, item.id, SystemTenantID, item.industry); err != nil {
			t.Fatalf("insert system rule set %s: %v", item.id, err)
		}
	}
	repo := NewRuleRepository(base.pool)
	for _, item := range []struct{ tenant, ruleSet string }{{base.tenantA, base.ruleSetA}, {base.tenantB, base.ruleSetB}} {
		if created, err := repo.SeedDefaultSubRules(ctx, item.tenant, item.ruleSet); err != nil || created != 241 {
			t.Fatalf("seed tenant policies %s=(%d,%v)", item.tenant, created, err)
		}
	}
	for index, id := range []string{"rule_g_phone", "rule_g_idcard", "rule_g_bankcard", "rule_g_email", "rule_g_passport"} {
		if _, err := base.pool.Exec(ctx, `
			INSERT INTO rules(id,rule_set_id,policy_code,rule_type,name,severity,scope_json,match_config_json,action,enabled,description)
			VALUES($1::varchar,'ruleset_builtin_generic','system.generic.'||$1::text,'regex',$2,'high','{"scene":"data_leak"}',jsonb_build_object('regex',$3::text),'audit',true,'系统通用敏感信息策略')`,
			id, "系统通用策略"+string(rune('A'+index)), "generic-pattern-"+id); err != nil {
			t.Fatalf("insert generic system rule %s: %v", id, err)
		}
	}
	for _, item := range []struct{ id, ruleSet, industry string }{
		{"rule_medical_only", "ruleset_builtin_medical", "medical"},
		{"rule_finance_only", "ruleset_builtin_finance", "finance"},
	} {
		if _, err := base.pool.Exec(ctx, `
			INSERT INTO rules(id,rule_set_id,policy_code,rule_type,name,severity,scope_json,match_config_json,action,enabled)
			VALUES($1::varchar,$2,'system.'||$3||'.'||$1::text,'regex',$1::text,'high',jsonb_build_object('scene',$3),jsonb_build_object('regex',$1::text),'audit',true)`,
			item.id, item.ruleSet, item.industry); err != nil {
			t.Fatalf("insert industry-only rule %s: %v", item.id, err)
		}
	}
	return securityPoliciesFixture{rulesTenantFixture: base, repo: repo}
}

func findSecurityPolicy(t *testing.T, policies []SecurityPolicy, predicate func(SecurityPolicy) bool) SecurityPolicy {
	t.Helper()
	for _, policy := range policies {
		if predicate(policy) {
			return policy
		}
	}
	t.Fatal("security policy not found")
	return SecurityPolicy{}
}

func TestListSecurityPoliciesReturnsExactlyApplicable246AndHonestBasis(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	policies, err := f.repo.ListSecurityPolicies(context.Background(), f.tenantA)
	if err != nil {
		t.Fatalf("list security policies: %v", err)
	}
	if len(policies) != 246 {
		t.Fatalf("generic tenant policy count=%d want=246", len(policies))
	}
	bySource := map[string]int{}
	byOrigin := map[string]int{}
	byScene := map[string]int{}
	for _, policy := range policies {
		bySource[policy.Source]++
		byOrigin[policy.Origin]++
		byScene[policy.Scene]++
		if policy.Industry == "medical" || policy.Industry == "finance" {
			t.Fatalf("inapplicable industry policy leaked into generic tenant: %#v", policy)
		}
	}
	if bySource["tenant"] != 241 || bySource["system"] != 5 {
		t.Fatalf("source counts=%v want tenant=241 system=5", bySource)
	}
	if byOrigin["preloaded"] != 246 || byOrigin["organization_created"] != 0 {
		t.Fatalf("origin counts=%v want all 246 preloaded", byOrigin)
	}
	sceneTotal := 0
	for _, count := range byScene {
		sceneTotal += count
	}
	if sceneTotal != len(policies) {
		t.Fatalf("scene groups lost policies total=%d policies=%d", sceneTotal, len(policies))
	}

	exact := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool { return policy.Name == "经典注入指令检测" })
	if exact.DetectionBasis != "capability" || !exact.DetectionConfigured || len(exact.Capabilities) != 2 {
		t.Fatalf("exact policy basis=%q configured=%v capabilities=%d", exact.DetectionBasis, exact.DetectionConfigured, len(exact.Capabilities))
	}
	if !exact.DetectionReady || exact.DetectionIssue != "" {
		t.Fatalf("executable capability binding was not ready: %#v", exact)
	}
	for _, policy := range policies {
		if policy.Origin == "preloaded" && !policy.DetectionConfigured {
			t.Fatalf("preloaded policy lacks executable detection basis: %#v", policy)
		}
	}
	system := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool { return policy.ID == "rule_g_phone" })
	if system.DetectionBasis != "matcher" || !system.DetectionConfigured || system.Source != "system" {
		t.Fatalf("system policy basis/source incorrect: %#v", system)
	}
	if system.DetectionReady || system.DetectionIssue != "runtime_validation_required" {
		t.Fatalf("unattested legacy regex was presented as runtime-ready: %#v", system)
	}
	if system.Scene != "data_leak" {
		t.Fatalf("generic PII policy scene=%q want data_leak", system.Scene)
	}
	if len(system.MatchConfigJSON) != 0 {
		t.Fatalf("system matcher details leaked to tenant: %s", system.MatchConfigJSON)
	}
}

func TestListSecurityPoliciesUsesTenantIndustryFromDatabase(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()

	genericPolicies, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list generic tenant policies: %v", err)
	}
	if len(genericPolicies) != 246 {
		t.Fatalf("generic tenant count=%d want=246", len(genericPolicies))
	}
	for _, policy := range genericPolicies {
		if policy.ID == "rule_finance_only" || policy.ID == "rule_medical_only" {
			t.Fatalf("generic tenant received non-applicable DB industry policy: %#v", policy)
		}
	}

	financePolicies, err := f.repo.ListSecurityPolicies(ctx, f.tenantB)
	if err != nil {
		t.Fatalf("list finance tenant policies: %v", err)
	}
	if len(financePolicies) != 247 {
		t.Fatalf("finance tenant count=%d want=247", len(financePolicies))
	}
	financeFound := false
	for _, policy := range financePolicies {
		switch policy.ID {
		case "rule_finance_only":
			financeFound = true
			if policy.Source != "system" || policy.Ownership != "platform" || policy.Origin != "preloaded" {
				t.Fatalf("shared industry policy identity=%#v", policy)
			}
		case "rule_medical_only":
			t.Fatalf("finance tenant received medical-only policy: %#v", policy)
		}
	}
	if !financeFound {
		t.Fatal("finance tenant did not receive finance policy from tenants.industry")
	}
}

func TestCreateSecurityPolicyKeepsDraftsDisabledAndAddsConfiguredPolicies(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	_, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "没有检测依据却启用", Scene: "content_safety", Severity: "high", Action: "block", Enabled: true,
	})
	if !errors.Is(err, ErrPolicyDetectionRequired) {
		t.Fatalf("enabled empty policy error=%v want ErrPolicyDetectionRequired", err)
	}
	draft, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "客户后续补充的策略", Description: "先保存为草稿", Scene: "content_safety", Severity: "medium", Action: "audit", Enabled: false,
	})
	if err != nil {
		t.Fatalf("create disabled draft: %v", err)
	}
	if draft.PolicyCode == "" || draft.Source != "tenant" || draft.Ownership != "organization" || draft.Origin != "organization_created" || draft.DetectionConfigured || draft.Enabled {
		t.Fatalf("unexpected draft: %#v", draft)
	}

	phoneCapability := "phone_cn"
	configured, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "新手机号场景策略", Scene: "sensitive_data", Severity: "high", Action: "mask", Enabled: true,
		CapabilityCategories: []string{phoneCapability}, BindingMode: "any",
	})
	if err != nil {
		t.Fatalf("create configured custom policy: %v", err)
	}
	if configured.DetectionBasis != "capability" || len(configured.Capabilities) != 1 || !configured.Enabled || !configured.DetectionReady || configured.DetectionIssue != "" {
		t.Fatalf("configured custom policy mismatch: %#v", configured)
	}
	policies, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil || len(policies) != 248 {
		t.Fatalf("list after two additions count=%d err=%v want=248", len(policies), err)
	}
	otherPolicies, err := f.repo.ListSecurityPolicies(ctx, f.tenantB)
	if err != nil || len(otherPolicies) != 247 {
		t.Fatalf("other finance tenant saw additions count=%d err=%v want=247", len(otherPolicies), err)
	}
}

func TestCreateSecurityPolicyRejectsMatcherAndCapabilitiesTogetherEvenAsDraft(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	_, err := f.repo.CreateSecurityPolicy(context.Background(), f.tenantA, CreateSecurityPolicyInput{
		Name: "冲突识别依据", Scene: "content_safety", Severity: "high", Action: "audit", Enabled: false,
		Matcher:              &SecurityPolicyMatcherInput{Type: "keyword", ConfigJSON: json.RawMessage(`{"keywords":["secret"]}`)},
		CapabilityCategories: []string{"phone_cn"}, BindingMode: "any",
	})
	if !errors.Is(err, ErrPolicyDetectionConflict) {
		t.Fatalf("hybrid draft error=%v want ErrPolicyDetectionConflict", err)
	}
}

func TestMatcherMaskOnlyAllowsRegex(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	for _, matcherType := range []string{"keyword", "field_name"} {
		config := json.RawMessage(`{"keywords":["secret"]}`)
		if matcherType == "field_name" {
			config = json.RawMessage(`{"field_names":["password"]}`)
		}
		_, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
			Name: "不安全脱敏 " + matcherType, Scene: "data_leak", Severity: "high", Action: "mask", Enabled: false,
			Matcher: &SecurityPolicyMatcherInput{Type: matcherType, ConfigJSON: config},
		})
		if !errors.Is(err, ErrPolicyActionUnsupported) {
			t.Fatalf("matcher=%s mask error=%v want ErrPolicyActionUnsupported", matcherType, err)
		}
	}
	created, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "关键词审计", Scene: "data_leak", Severity: "high", Action: "audit", Enabled: false,
		Matcher: &SecurityPolicyMatcherInput{Type: "keyword", ConfigJSON: json.RawMessage(`{"keywords":["secret"]}`)},
	})
	if err != nil {
		t.Fatalf("create keyword audit policy: %v", err)
	}
	mask := "mask"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, created.ID, SecurityPolicyUpdate{Action: &mask}); !errors.Is(err, ErrPolicyActionUnsupported) {
		t.Fatalf("update keyword policy to mask error=%v want ErrPolicyActionUnsupported", err)
	}
	unchanged, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, created.ID)
	if err != nil || unchanged.Action != "audit" {
		t.Fatalf("rejected matcher mask changed policy=%#v err=%v", unchanged, err)
	}
}

func TestCreateSecurityPolicyUsesStableRuleSetAndCanonicalPythonMatcher(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO rule_sets(id,tenant_id,name,version,source_type,published,industry,created_at)
		VALUES('rs_decoy_default',$1,'默认安全策略','1.0','system',true,'generic',NOW()-INTERVAL '1 day')`, f.tenantA); err != nil {
		t.Fatalf("insert decoy default rule set: %v", err)
	}

	_, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "未经引擎验证的正则", Scene: "content_safety", Severity: "high", Action: "block", Enabled: true,
		Matcher: &SecurityPolicyMatcherInput{Type: "regex", ConfigJSON: json.RawMessage(`{"regex":"("}`)},
	})
	if !errors.Is(err, ErrPolicyRuntimeValidation) {
		t.Fatalf("unattested regex error=%v want ErrPolicyRuntimeValidation", err)
	}

	created, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "Python 前瞻正则", Scene: "content_safety", Severity: "high", Action: "block", Enabled: true,
		Matcher: &SecurityPolicyMatcherInput{Type: "regex", RuntimeValidated: true, ConfigJSON: json.RawMessage(
			`{"regex":"(?=secret)secret","category":"private_key","reply_message":"internal","unknown":{"selector":"must-not-round-trip"}}`,
		)},
	})
	if err != nil {
		t.Fatalf("create Python-compatible lookahead matcher: %v", err)
	}
	if created.Scene != "content_safety" || created.DetectionBasis != "matcher" || !created.DetectionConfigured || !created.DetectionReady {
		t.Fatalf("created matcher policy=%#v", created)
	}
	var returnedMatcher map[string]any
	if err := json.Unmarshal(created.MatchConfigJSON, &returnedMatcher); err != nil {
		t.Fatalf("decode returned matcher: %v", err)
	}
	if len(returnedMatcher) != 1 || returnedMatcher["regex"] != "(?=secret)secret" {
		t.Fatalf("matcher returned unknown/internal fields: %#v", returnedMatcher)
	}

	var persistedRuleSet string
	var persistedMatcher []byte
	if err := f.pool.QueryRow(ctx, `SELECT rule_set_id,match_config_json FROM rules WHERE id=$1`, created.ID).Scan(&persistedRuleSet, &persistedMatcher); err != nil {
		t.Fatalf("read persisted matcher policy: %v", err)
	}
	if persistedRuleSet != DefaultSecurityRuleSetID(f.tenantA) {
		t.Fatalf("new policy rule_set_id=%q want stable default=%q", persistedRuleSet, DefaultSecurityRuleSetID(f.tenantA))
	}
	var storedMatcher map[string]any
	if err := json.Unmarshal(persistedMatcher, &storedMatcher); err != nil || len(storedMatcher) != 1 || storedMatcher["regex"] != "(?=secret)secret" {
		t.Fatalf("stored matcher was not canonical: %#v err=%v", storedMatcher, err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE rules SET match_config_json='{"regex":"("}'::jsonb WHERE id=$1`, created.ID); err != nil {
		t.Fatalf("tamper matcher after runtime validation: %v", err)
	}
	tampered, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, created.ID)
	if err != nil {
		t.Fatalf("read tampered matcher policy: %v", err)
	}
	if !tampered.DetectionConfigured || tampered.DetectionReady || tampered.DetectionIssue != "runtime_validation_required" {
		t.Fatalf("matcher whose validation digest no longer matches was presented ready: %#v", tampered)
	}

	for _, tc := range []struct {
		name    string
		pattern string
	}{
		{name: "nested quantifier", pattern: `(a+)+`},
		{name: "over 1000 bytes", pattern: strings.Repeat("a", 1001)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
				Name: tc.name, Scene: "content_safety", Severity: "high", Action: "block", Enabled: true,
				Matcher: &SecurityPolicyMatcherInput{Type: "regex", ConfigJSON: json.RawMessage(`{"regex":` + fmt.Sprintf("%q", tc.pattern) + `}`)},
			})
			if !errors.Is(err, ErrInvalidSecurityPolicy) {
				t.Fatalf("unsafe matcher error=%v want ErrInvalidSecurityPolicy", err)
			}
		})
	}
}

func TestUpdateSecurityPolicyRequiresExplicitBasisSwitch(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	draft, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "先用关键词", Scene: "content_safety", Severity: "high", Action: "audit", Enabled: false,
		Matcher: &SecurityPolicyMatcherInput{Type: "keyword", ConfigJSON: json.RawMessage(`{"keywords":["secret"]}`)},
	})
	if err != nil {
		t.Fatalf("create matcher draft: %v", err)
	}
	categories := []string{"phone_cn"}
	mode := "any"
	_, err = f.repo.UpdateSecurityPolicy(ctx, f.tenantA, draft.ID, SecurityPolicyUpdate{
		CapabilityCategories: &categories, BindingMode: &mode,
	})
	if !errors.Is(err, ErrPolicyDetectionConflict) {
		t.Fatalf("implicit matcher-to-capability switch error=%v want ErrPolicyDetectionConflict", err)
	}
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, draft.ID, SecurityPolicyUpdate{
		ClearMatcher: true, CapabilityCategories: &categories, BindingMode: &mode,
	})
	if err != nil {
		t.Fatalf("explicit matcher-to-capability switch: %v", err)
	}
	if updated.DetectionBasis != "capability" || len(updated.Capabilities) != 1 || len(updated.MatchConfigJSON) != 0 {
		t.Fatalf("explicit switch result=%#v", updated)
	}
}

func TestUpdateSecurityPolicyMatcherPreservesScene(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	created, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "更新 matcher 不丢场景", Scene: "content_safety", Severity: "medium", Action: "audit", Enabled: true,
		Matcher: &SecurityPolicyMatcherInput{Type: "regex", RuntimeValidated: true, ConfigJSON: json.RawMessage(`{"regex":"before"}`)},
	})
	if err != nil {
		t.Fatalf("create matcher policy: %v", err)
	}
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, created.ID, SecurityPolicyUpdate{
		Matcher: &SecurityPolicyMatcherInput{Type: "keyword", ConfigJSON: json.RawMessage(`{"keywords":["after"]}`)},
	})
	if err != nil {
		t.Fatalf("update matcher: %v", err)
	}
	if updated.Scene != "content_safety" || updated.RuleType != "keyword" {
		t.Fatalf("matcher update lost scene or type: %#v", updated)
	}
	var scene string
	if err := f.pool.QueryRow(ctx, `SELECT scope_json->>'scene' FROM rules WHERE id=$1`, created.ID).Scan(&scene); err != nil || scene != "content_safety" {
		t.Fatalf("persisted scene=%q err=%v", scene, err)
	}
}

func TestUpdateCapabilityOnlyPolicySceneKeepsRuntimeTypeInSync(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	created, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "能力策略场景切换", Scene: "content_safety", Severity: "medium", Action: "audit", Enabled: true,
		CapabilityCategories: []string{"phone_cn"}, BindingMode: "any",
	})
	if err != nil {
		t.Fatalf("create capability policy: %v", err)
	}
	nextScene := "data_leak"
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, created.ID, SecurityPolicyUpdate{Scene: &nextScene})
	if err != nil {
		t.Fatalf("update capability policy scene: %v", err)
	}
	if updated.Scene != nextScene || updated.RuleType != nextScene || updated.DetectionBasis != "capability" {
		t.Fatalf("updated capability policy=%#v", updated)
	}
	var ruleType, storedScene string
	if err := f.pool.QueryRow(ctx, `SELECT rule_type,scope_json->>'scene' FROM rules WHERE id=$1`, created.ID).Scan(&ruleType, &storedScene); err != nil {
		t.Fatalf("read updated capability policy: %v", err)
	}
	if ruleType != nextScene || storedScene != nextScene {
		t.Fatalf("runtime type=%q stored scene=%q want=%q", ruleType, storedScene, nextScene)
	}
}

func TestDisabledCapabilitiesRespectAnyBindingAndReportDegradation(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE security_capabilities SET enabled=false WHERE category='keyword_classic_injection'`); err != nil {
		t.Fatalf("disable bound capability: %v", err)
	}
	policies, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list policies with disabled capability: %v", err)
	}
	classic := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool { return policy.Name == "经典注入指令检测" })
	if !classic.DetectionConfigured || !classic.DetectionReady || classic.DetectionIssue != "partial_unavailable" || classic.UnavailableCount != 1 {
		t.Fatalf("runtime any binding lost executable degradation state: %#v", classic)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE security_capabilities SET enabled=false WHERE category='keyword_classic_injection_en'`); err != nil {
		t.Fatalf("disable remaining bound capability: %v", err)
	}
	policies, err = f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list policies with all capabilities disabled: %v", err)
	}
	classic = findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool { return policy.Name == "经典注入指令检测" })
	if !classic.DetectionConfigured || classic.DetectionReady || classic.DetectionIssue != "capability_unavailable" {
		t.Fatalf("all-disabled any binding lost configuration or was presented ready: %#v", classic)
	}
}

func TestSecurityPolicyAuditOnlyUpdateAllowsUnreadyPolicies(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	policies, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	systemUnready := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool {
		return policy.ID == "rule_g_phone"
	})
	// Retired catalog entries no longer leave an enabled tenant-owned unready
	// policy. Create one explicitly so the audit-only transition remains tested.
	if _, err := f.pool.Exec(ctx, `INSERT INTO rules(id,rule_set_id,policy_code,rule_type,name,action,enabled) VALUES($1,$2,$3,$4,$5,$6,true)`, "unready_audit_fixture", f.ruleSetA, "custom.unready.audit.fixture", "regex", "unready-audit-fixture", "audit"); err != nil {
		t.Fatalf("create unready tenant policy: %v", err)
	}
	policies, err = f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list policies after unready insert: %v", err)
	}
	tenantUnready := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool {
		return policy.Source == "tenant" && policy.Enabled && !policy.DetectionReady
	})
	for _, policyID := range []string{systemUnready.ID, tenantUnready.ID} {
		if _, err := f.pool.Exec(ctx, `UPDATE rules SET action='block' WHERE id=$1`, policyID); err != nil {
			t.Fatalf("prepare unready block policy %s: %v", policyID, err)
		}
	}

	audit := "audit"
	err = f.repo.BatchUpdateSecurityPolicies(ctx, f.tenantA, []SecurityPolicyBatchUpdate{
		{ID: systemUnready.ID, Update: SecurityPolicyUpdate{Action: &audit}},
		{ID: tenantUnready.ID, Update: SecurityPolicyUpdate{Action: &audit}},
	})
	if err != nil {
		t.Fatalf("batch audit-only downgrade: %v", err)
	}
	systemUpdated, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, systemUnready.ID)
	if err != nil || systemUpdated.Action != audit || !systemUpdated.Enabled || systemUpdated.DetectionReady {
		t.Fatalf("audit-only system downgrade=%#v err=%v", systemUpdated, err)
	}

	tenantUpdated, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, tenantUnready.ID)
	if err != nil || tenantUpdated.Action != audit || !tenantUpdated.Enabled || tenantUpdated.DetectionReady {
		t.Fatalf("audit-only tenant downgrade=%#v err=%v", tenantUpdated, err)
	}

	enabled := true
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, tenantUnready.ID, SecurityPolicyUpdate{
		Action: &audit, Enabled: &enabled,
	}); !errors.Is(err, ErrPolicyDetectionRequired) {
		t.Fatalf("audit plus enable unready tenant error=%v want ErrPolicyDetectionRequired", err)
	}
}

func TestSecurityPolicyUpdateValidatesCapabilitiesAndSystemOverrides(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	policies, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	classic := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool { return policy.Name == "经典注入指令检测" })
	phone := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool { return policy.ID == "rule_g_phone" })

	mask := "mask"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, classic.ID, SecurityPolicyUpdate{Action: &mask}); !errors.Is(err, ErrPolicyActionUnsupported) {
		t.Fatalf("non-maskable capability action error=%v want ErrPolicyActionUnsupported", err)
	}

	newName := "经典注入（租户自定义展示名）"
	newScene := "content_safety"
	block := "block"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, classic.ID, SecurityPolicyUpdate{Name: &newName, Scene: &newScene}); !errors.Is(err, ErrSystemPolicyFieldReadOnly) {
		t.Fatalf("preloaded definition update error=%v want ErrSystemPolicyFieldReadOnly", err)
	}
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, classic.ID, SecurityPolicyUpdate{Action: &block})
	if err != nil || updated.Name != classic.Name || updated.Scene != classic.Scene || updated.Action != block || updated.PolicyCode != classic.PolicyCode {
		t.Fatalf("update preloaded policy action=%#v err=%v", updated, err)
	}
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, phone.ID, SecurityPolicyUpdate{Action: &block}); !errors.Is(err, ErrPolicyRuntimeValidation) {
		t.Fatalf("enabled unattested system regex action-only error=%v want ErrPolicyRuntimeValidation", err)
	}

	disabled := false
	systemUpdated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, phone.ID, SecurityPolicyUpdate{Action: &mask, Enabled: &disabled})
	if err != nil || systemUpdated.Action != mask || systemUpdated.Enabled {
		t.Fatalf("update system override=%#v err=%v", systemUpdated, err)
	}
	var baseAction string
	var baseEnabled bool
	if err := f.pool.QueryRow(ctx, `SELECT action,enabled FROM rules WHERE id=$1`, phone.ID).Scan(&baseAction, &baseEnabled); err != nil || baseAction != "audit" || !baseEnabled {
		t.Fatalf("system base row changed action=%q enabled=%v err=%v", baseAction, baseEnabled, err)
	}
	enabled := true
	reenabled, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, phone.ID, SecurityPolicyUpdate{
		Enabled: &enabled, RuntimeValidated: true,
	})
	if err != nil {
		t.Fatalf("re-enable exact-runtime-attested system regex: %v", err)
	}
	if !reenabled.Enabled || !reenabled.DetectionReady {
		t.Fatalf("re-enabled system regex is not ready: %#v", reenabled)
	}
	var validationRuntime string
	if err := f.pool.QueryRow(ctx, `SELECT scope_json#>>'{matcher_validation,runtime}' FROM rules WHERE id=$1`, phone.ID).Scan(&validationRuntime); err != nil || validationRuntime != matcherValidationRuntime {
		t.Fatalf("system matcher attestation runtime=%q err=%v", validationRuntime, err)
	}
}

func TestSystemPolicyRejectsMaskForNonMaskableCapability(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	bindSystemDefaultCapability(t, f, "rule_g_passport", "keyword_classic_injection", "any")
	mask := "mask"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Action: &mask}); !errors.Is(err, ErrPolicyActionUnsupported) {
		t.Fatalf("system non-maskable capability action error=%v want ErrPolicyActionUnsupported", err)
	}
	var overrideCount int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM builtin_rule_overrides WHERE tenant_id=$1 AND rule_id='rule_g_passport'`, f.tenantA).Scan(&overrideCount); err != nil || overrideCount != 0 {
		t.Fatalf("rejected system mask persisted override count=%d err=%v", overrideCount, err)
	}
}

func TestSystemPolicyConcurrentPartialOverridesDoNotLoseFields(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	block := "block"
	disabled := false
	for attempt := 0; attempt < 12; attempt++ {
		if _, err := f.pool.Exec(ctx, `DELETE FROM builtin_rule_overrides WHERE tenant_id=$1 AND rule_id='rule_g_phone'`, f.tenantA); err != nil {
			t.Fatalf("attempt %d reset override: %v", attempt, err)
		}
		start := make(chan struct{})
		errs := make(chan error, 2)
		go func() {
			<-start
			_, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_phone", SecurityPolicyUpdate{Action: &block, RuntimeValidated: true})
			errs <- err
		}()
		go func() {
			<-start
			_, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_phone", SecurityPolicyUpdate{Enabled: &disabled})
			errs <- err
		}()
		close(start)
		for i := 0; i < 2; i++ {
			if err := <-errs; err != nil {
				t.Fatalf("attempt %d concurrent partial override: %v", attempt, err)
			}
		}
		policy, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_g_phone")
		if err != nil {
			t.Fatalf("attempt %d read effective override: %v", attempt, err)
		}
		if policy.Action != block || policy.Enabled {
			t.Fatalf("attempt %d lost partial override action=%q enabled=%v", attempt, policy.Action, policy.Enabled)
		}
	}
}

func TestBatchUpdateSecurityPoliciesRejectsTrimmedDuplicatesAndCommitsSuccess(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	policies, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	classic := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool { return policy.Name == "经典注入指令检测" })
	phone := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool { return policy.ID == "rule_g_phone" })

	err = f.repo.BatchUpdateSecurityPolicies(ctx, f.tenantA, []SecurityPolicyBatchUpdate{
		{ID: phone.ID, Update: SecurityPolicyUpdate{}},
		{ID: " \t" + phone.ID + " ", Update: SecurityPolicyUpdate{}},
	})
	if !errors.Is(err, ErrInvalidSecurityPolicy) {
		t.Fatalf("trimmed duplicate batch error=%v want ErrInvalidSecurityPolicy", err)
	}

	block := "block"
	disabled := false
	err = f.repo.BatchUpdateSecurityPolicies(ctx, f.tenantA, []SecurityPolicyBatchUpdate{
		{ID: classic.ID, Update: SecurityPolicyUpdate{Enabled: &disabled}},
		{ID: phone.ID, Update: SecurityPolicyUpdate{Action: &block, Enabled: &disabled}},
	})
	if err != nil {
		t.Fatalf("successful cross-source batch: %v", err)
	}
	updatedClassic, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, classic.ID)
	if err != nil || updatedClassic.Enabled {
		t.Fatalf("tenant batch result=%#v err=%v", updatedClassic, err)
	}
	updatedPhone, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, phone.ID)
	if err != nil || updatedPhone.Action != block || updatedPhone.Enabled {
		t.Fatalf("system batch result=%#v err=%v", updatedPhone, err)
	}
}

func TestBatchUpdateSecurityPoliciesIsAtomicAcrossTenantAndSystem(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	policies, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	classic := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool { return policy.Name == "经典注入指令检测" })
	phone := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool { return policy.ID == "rule_g_phone" })
	block := "block"
	disabled := false
	err = f.repo.BatchUpdateSecurityPolicies(ctx, f.tenantA, []SecurityPolicyBatchUpdate{
		{ID: classic.ID, Update: SecurityPolicyUpdate{Enabled: &disabled}},
		{ID: phone.ID, Update: SecurityPolicyUpdate{Action: &block, Enabled: &disabled}},
		{ID: "zzzz_missing_policy", Update: SecurityPolicyUpdate{Enabled: &disabled}},
	})
	if !errors.Is(err, ErrSecurityPolicyNotFound) {
		t.Fatalf("batch missing policy error=%v want ErrSecurityPolicyNotFound", err)
	}
	var enabled bool
	if err := f.pool.QueryRow(ctx, `SELECT enabled FROM rules WHERE id=$1`, classic.ID).Scan(&enabled); err != nil || !enabled {
		t.Fatalf("tenant update was not rolled back enabled=%v err=%v", enabled, err)
	}
	var overrideCount int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM builtin_rule_overrides WHERE tenant_id=$1 AND rule_id=$2`, f.tenantA, phone.ID).Scan(&overrideCount); err != nil || overrideCount != 0 {
		t.Fatalf("system override was not rolled back count=%d err=%v", overrideCount, err)
	}
}

func TestSecurityPolicyEmptyIDIsNotFound(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	if _, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, " \t "); !errors.Is(err, ErrSecurityPolicyNotFound) {
		t.Fatalf("empty get id error=%v want ErrSecurityPolicyNotFound", err)
	}
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, " ", SecurityPolicyUpdate{}); !errors.Is(err, ErrSecurityPolicyNotFound) {
		t.Fatalf("empty update id error=%v want ErrSecurityPolicyNotFound", err)
	}
}

func TestTenantOwnedPreloadedPolicyDefinitionFieldsRemainReadOnly(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	policies, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	preloaded := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool {
		return strings.HasPrefix(policy.PolicyCode, "builtin.")
	})
	name := "renamed"
	description := "redefined"
	scene := "custom_rules"
	matcher := &SecurityPolicyMatcherInput{Type: "keyword", ConfigJSON: json.RawMessage(`{"keywords":["override"]}`)}
	for index, update := range []SecurityPolicyUpdate{
		{Name: &name}, {Description: &description}, {Scene: &scene},
		{Matcher: matcher}, {ClearMatcher: true},
	} {
		if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, preloaded.ID, update); !errors.Is(err, ErrSystemPolicyFieldReadOnly) {
			t.Fatalf("preloaded definition update %d error=%v want ErrSystemPolicyFieldReadOnly", index, err)
		}
	}
}

func TestPreloadedPolicyRejectsCapabilityBindingReplacement(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	policies, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	classic := findSecurityPolicy(t, policies, func(policy SecurityPolicy) bool { return policy.Name == "经典注入指令检测" })
	if len(classic.Capabilities) != 2 {
		t.Fatalf("fixture exact binding count=%d want=2", len(classic.Capabilities))
	}
	categories := []string{"phone_cn"}
	mode := "all"
	mask := "mask"
	_, err = f.repo.UpdateSecurityPolicy(ctx, f.tenantA, classic.ID, SecurityPolicyUpdate{
		CapabilityCategories: &categories,
		BindingMode:          &mode,
		Action:               &mask,
	})
	if !errors.Is(err, ErrSystemPolicyFieldReadOnly) {
		t.Fatalf("replace preloaded policy bindings error=%v want ErrSystemPolicyFieldReadOnly", err)
	}
	var count int
	var originalBindings bool
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*),COALESCE(bool_and(cap.category IN ('keyword_classic_injection','keyword_classic_injection_en') AND binding.binding_mode='any'),false)
		FROM rule_capability_bindings binding
		JOIN security_capabilities cap ON cap.id=binding.capability_id
		WHERE binding.rule_id=$1`, classic.ID).Scan(&count, &originalBindings); err != nil {
		t.Fatalf("read original bindings: %v", err)
	}
	if count != 2 || !originalBindings {
		t.Fatalf("preloaded bindings changed count=%d originalBindings=%v", count, originalBindings)
	}
}

func TestAuthoringScopeVerifiesMatcherAndRejectsTampering(t *testing.T) {
	segments := []SecurityPolicyNumberSegment{{Kind: "fixed", Value: "HT-", Length: 3}, {Kind: "fixed", Value: "2026", Length: 4}, {Kind: "fixed", Value: "-", Length: 1}, {Kind: "digits", Length: 6}}
	matcher := []byte(`{"regex":"(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])"}`)
	authoring := &SecurityPolicyAuthoring{Version: 1, Kind: "number", MatcherPattern: "(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])", Segments: segments}
	scope, err := scopeWithAuthoring([]byte(`{"scene":"data_security"}`), authoring, "regex", matcher)
	if err != nil || parseSecurityPolicyAuthoring(scope, "regex", matcher) == nil || !strings.Contains(string(scope), `"_authoring"`) {
		t.Fatalf("authoring roundtrip: %v %s", err, scope)
	}
	if parseSecurityPolicyAuthoring(scope, "regex", []byte(`{"regex":".*"}`)) != nil {
		t.Fatal("tampered matcher retained authoring")
	}
	for _, invalid := range []*SecurityPolicyAuthoring{{Version: 2, Kind: "number", MatcherPattern: authoring.MatcherPattern, Segments: segments}, {Version: 1, Kind: "other", MatcherPattern: authoring.MatcherPattern, Segments: segments}, {Version: 1, Kind: "number", MatcherPattern: ".*", Segments: segments}, {Version: 1, Kind: "number", MatcherPattern: authoring.MatcherPattern, Segments: []SecurityPolicyNumberSegment{{Kind: "fixed", Value: "X"}, {Kind: "digits", Length: 3}}}} {
		if _, err := scopeWithAuthoring(scope, invalid, "regex", matcher); !errors.Is(err, ErrInvalidSecurityPolicy) {
			t.Fatalf("accepted invalid authoring: %+v %v", invalid, err)
		}
	}
	scope, err = scopeWithAuthoring(scope, nil, "regex", matcher)
	if err != nil || parseSecurityPolicyAuthoring(scope, "regex", matcher) != nil || strings.Contains(string(scope), `"_authoring"`) {
		t.Fatalf("manual matcher retained authoring: %v %s", err, scope)
	}
}

func TestAuthoringPersistReopenEditAndInvalidate(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	first := []SecurityPolicyNumberSegment{{Kind: "fixed", Value: "HT-", Length: 3}, {Kind: "fixed", Value: "2026", Length: 4}, {Kind: "fixed", Value: "-", Length: 1}, {Kind: "digits", Length: 6}}
	firstPattern, valid := numberSegmentPattern(first)
	if !valid {
		t.Fatal("initial segments invalid")
	}
	matcher := func(pattern string) *SecurityPolicyMatcherInput {
		config, err := json.Marshal(map[string]string{"regex": pattern})
		if err != nil {
			t.Fatal(err)
		}
		return &SecurityPolicyMatcherInput{Type: "regex", ConfigJSON: config, RuntimeValidated: true}
	}
	created, err := f.repo.CreateSecurityPolicy(ctx, f.tenantA, CreateSecurityPolicyInput{
		Name: "number segment persistence", Scene: "data_security", Severity: "medium", Action: "audit", Enabled: false,
		Matcher: matcher(firstPattern), Authoring: &SecurityPolicyAuthoring{Version: 1, Kind: "number", MatcherPattern: firstPattern, Segments: first},
	})
	if err != nil || len(created.Authoring.Segments) != len(first) {
		t.Fatalf("create and read segments: %v %+v", err, created)
	}
	if other, err := f.repo.GetSecurityPolicy(ctx, f.tenantB, created.ID); !errors.Is(err, ErrSecurityPolicyNotFound) || other != nil {
		t.Fatalf("segments policy leaked across tenants: %v %+v", err, other)
	}
	listed, err := f.repo.ListSecurityPolicies(ctx, f.tenantA)
	if err != nil || len(findSecurityPolicy(t, listed, func(policy SecurityPolicy) bool { return policy.ID == created.ID }).Authoring.Segments) != len(first) {
		t.Fatalf("listing omitted segments: %v", err)
	}
	second := []SecurityPolicyNumberSegment{{Kind: "fixed", Value: "HT-", Length: 3}, {Kind: "digits", Length: 4}, {Kind: "fixed", Value: "-", Length: 1}, {Kind: "digits", Length: 6}}
	secondPattern, valid := numberSegmentPattern(second)
	if !valid {
		t.Fatal("edited year segments invalid")
	}
	newAction := "block"
	preserved, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, created.ID, SecurityPolicyUpdate{Action: &newAction})
	if err != nil || preserved.Authoring == nil || preserved.Authoring.MatcherPattern != firstPattern {
		t.Fatalf("action-only patch lost authoring: %v %+v", err, preserved)
	}
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, created.ID, SecurityPolicyUpdate{Matcher: matcher(secondPattern), Authoring: &SecurityPolicyAuthoring{Version: 1, Kind: "number", MatcherPattern: secondPattern, Segments: second}})
	if err != nil || len(updated.Authoring.Segments) != len(second) || updated.Authoring.Segments[1].Kind != "digits" {
		t.Fatalf("edit and read segments: %v %+v", err, updated)
	}
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, created.ID, SecurityPolicyUpdate{Authoring: &SecurityPolicyAuthoring{Version: 1, Kind: "number", MatcherPattern: firstPattern, Segments: first}}); !errors.Is(err, ErrInvalidSecurityPolicy) {
		t.Fatalf("metadata-only update accepted: %v", err)
	}
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantB, created.ID, SecurityPolicyUpdate{Matcher: matcher(firstPattern), Authoring: &SecurityPolicyAuthoring{Version: 1, Kind: "number", MatcherPattern: firstPattern, Segments: first}}); !errors.Is(err, ErrSecurityPolicyNotFound) {
		t.Fatalf("cross-tenant metadata update accepted: %v", err)
	}
	manual, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, created.ID, SecurityPolicyUpdate{Matcher: matcher(firstPattern)})
	if err != nil || manual.Authoring != nil {
		t.Fatalf("manual regex replacement retained segments: %v %+v", err, manual)
	}
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, created.ID, SecurityPolicyUpdate{Matcher: matcher(secondPattern), Authoring: &SecurityPolicyAuthoring{Version: 1, Kind: "number", MatcherPattern: secondPattern, Segments: second}}); err != nil {
		t.Fatalf("restore edited segments: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE rules SET match_config_json=jsonb_build_object('regex', $1::text) WHERE id=$2`, firstPattern, created.ID); err != nil {
		t.Fatalf("tamper persisted matcher: %v", err)
	}
	tampered, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, created.ID)
	if err != nil || tampered.Authoring != nil {
		t.Fatalf("tampered regex exposed stale metadata: %v %+v", err, tampered)
	}
}
