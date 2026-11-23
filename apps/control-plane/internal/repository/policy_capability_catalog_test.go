package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	policyCapabilityMigration       = "125_policy_capability_bindings.sql"
	retiredCapabilityMigration      = "138_retire_encoding_zero_width.sql"
	sensitiveCapabilityMigration    = "154_sensitive_data_capabilities.sql"
	agentControlMigration           = "155_agent_client_governance.sql"
	runtimeCatalogMigration         = "156_runtime_policy_catalog.sql"
	deterministicCatalogMigration   = "157_deterministic_policy_catalog.sql"
	codeSecurityCatalogMigration    = "158_code_security_policy_catalog.sql"
	fraudTradeCatalogMigration      = "159_fraud_trade_policy_catalog.sql"
	injectionCatalogMigration       = "160_injection_policy_catalog.sql"
	copyrightPluginCatalogMigration = "161_copyright_plugin_policy_catalog.sql"
	contentSafetyCatalogMigration   = "162_content_safety_policy_catalog.sql"
	ragSupplyCatalogMigration       = "163_rag_supply_policy_catalog.sql"
	semanticPretextCatalogMigration = "164_semantic_pretext_policy_catalog.sql"
	requestContextCatalogMigration  = "165_request_context_policy_catalog.sql"
	policyRetirementMigration       = "166_policy_catalog_retirement.sql"
	profanityAbuseMigration         = "992_profanity_abuse_policy.sql"
)

const (
	staticCapabilityMarker    = "$static_capability_categories$"
	dynamicCapabilityMarker   = "$dynamic_capability_catalog$"
	defaultPolicyMarker       = "$default_policy_catalog$"
	exactBindingMarker        = "$exact_policy_capability_bindings$"
	retiredCapabilityMarker   = "$retired_static_capability_categories$"
	sensitiveCapabilityMarker = "$sensitive_data_capabilities$"
	sensitiveBindingMarker    = "$sensitive_data_policy_bindings$"
	runtimeCapabilityMarker   = "$runtime_policy_capabilities$"
	runtimeBindingMarker      = "$runtime_policy_bindings$"
	retiredPolicyMarker       = "$retired_policy_codes$"
	addedCapabilityMarker     = "$added_policy_capabilities$"
	addedBindingMarker        = "$added_exact_policy_capability_bindings$"
)

type migrationPolicyIdentity struct {
	RuleType   string `json:"rule_type"`
	Name       string `json:"name"`
	PolicyCode string `json:"policy_code"`
}

type migrationCapabilitySeed struct {
	Category        string   `json:"category"`
	Name            string   `json:"name"`
	Component       string   `json:"component"`
	SupportedStages []string `json:"supported_stages"`
	AllowedActions  []string `json:"allowed_actions"`
	BuiltinActions  []string `json:"builtin_actions"`
	MaskCapable     bool     `json:"mask_capable"`
}

type migrationBindingSeed struct {
	PolicyCode           string   `json:"policy_code"`
	RuleType             string   `json:"rule_type"`
	Name                 string   `json:"name"`
	CapabilityCategories []string `json:"capability_categories"`
	BindingMode          string   `json:"binding_mode"`
}

func readPolicyCapabilityMigration(t *testing.T) string {
	t.Helper()
	return readCapabilityMigration(t, policyCapabilityMigration)
}

func readCapabilityMigration(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile("../../../../deploy/migrations/" + name)
	if err != nil {
		t.Fatalf("read capability migration %s: %v", name, err)
	}
	return string(body)
}

func runtimeCatalogMigrations() []string {
	return []string{runtimeCatalogMigration, deterministicCatalogMigration, codeSecurityCatalogMigration, fraudTradeCatalogMigration, injectionCatalogMigration, copyrightPluginCatalogMigration, contentSafetyCatalogMigration, ragSupplyCatalogMigration, semanticPretextCatalogMigration, requestContextCatalogMigration, policyRetirementMigration}
}

func runtimeCapabilityCatalog(t *testing.T) []migrationCapabilitySeed {
	t.Helper()
	var catalog []migrationCapabilitySeed
	for _, migration := range runtimeCatalogMigrations() {
		catalog = append(catalog, decodeMigrationJSONBlock[[]migrationCapabilitySeed](
			t, readCapabilityMigration(t, migration), runtimeCapabilityMarker,
		)...)
	}
	return catalog
}

func runtimeBindingCatalog(t *testing.T) []migrationBindingSeed {
	t.Helper()
	var catalog []migrationBindingSeed
	for _, migration := range runtimeCatalogMigrations() {
		catalog = append(catalog, decodeMigrationJSONBlock[[]migrationBindingSeed](
			t, readCapabilityMigration(t, migration), runtimeBindingMarker,
		)...)
	}
	return catalog
}

func retiredStaticCapabilities(t *testing.T) map[string]bool {
	t.Helper()
	retired := decodeMigrationJSONBlock[[]string](t, readCapabilityMigration(t, retiredCapabilityMigration), retiredCapabilityMarker)
	result := make(map[string]bool, len(retired))
	for _, category := range retired {
		result[category] = true
	}
	return result
}

func withoutRetiredCapabilities(categories []string, retired map[string]bool) []string {
	result := make([]string, 0, len(categories))
	for _, category := range categories {
		if !retired[category] {
			result = append(result, category)
		}
	}
	return result
}

func decodeMigrationJSONBlock[T any](t *testing.T, source, marker string) T {
	t.Helper()
	parts := strings.Split(source, marker)
	if len(parts) != 3 {
		t.Fatalf("migration must contain exactly one %s JSON block, parts=%d", marker, len(parts))
	}
	var value T
	if err := json.Unmarshal([]byte(parts[1]), &value); err != nil {
		t.Fatalf("decode %s: %v", marker, err)
	}
	return value
}

func TestSecurityCapabilityMigrationCoversStaticEngineCategoriesExactly(t *testing.T) {
	source := readPolicyCapabilityMigration(t)
	got := decodeMigrationJSONBlock[[]string](t, source, staticCapabilityMarker)
	got = withoutRetiredCapabilities(got, retiredStaticCapabilities(t))
	sensitiveCatalog := decodeMigrationJSONBlock[[]migrationCapabilitySeed](t, readCapabilityMigration(t, sensitiveCapabilityMigration), sensitiveCapabilityMarker)
	runtimeCatalog := runtimeCapabilityCatalog(t)
	seenSensitive := map[string]bool{}
	for _, capability := range sensitiveCatalog {
		if seenSensitive[capability.Category] {
			t.Fatalf("duplicate sensitive capability %q", capability.Category)
		}
		seenSensitive[capability.Category] = true
		if strings.TrimSpace(capability.Name) == "" || strings.TrimSpace(capability.Component) == "" {
			t.Errorf("sensitive capability %q lacks customer metadata", capability.Category)
		}
		if len(capability.SupportedStages) != 2 || len(capability.BuiltinActions) != 3 || !capability.MaskCapable {
			t.Errorf("sensitive capability %q has incomplete execution contract", capability.Category)
		}
		got = append(got, capability.Category)
	}
	for _, capability := range runtimeCatalog {
		if capability.Component == "security-engine.code-patterns" || capability.Component == "security-engine.policy-catalog" {
			got = append(got, capability.Category)
		}
	}
	engineBody, err := os.ReadFile("../../../web-console/src/utils/engine_categories.json")
	if err != nil {
		t.Fatalf("read engine category catalog: %v", err)
	}
	var want []string
	if err := json.Unmarshal(engineBody, &want); err != nil {
		t.Fatalf("decode engine category catalog: %v", err)
	}
	if len(want) != 268 || len(got) != 268 {
		t.Fatalf("static capability counts got=%d want=%d", len(got), len(want))
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("static capability catalog drift\ngot=%v\nwant=%v", got, want)
	}
}

func TestSecurityCapabilityMigrationDynamicAllowlistIsExplicit(t *testing.T) {
	source := readPolicyCapabilityMigration(t)
	catalog := decodeMigrationJSONBlock[[]migrationCapabilitySeed](t, source, dynamicCapabilityMarker)
	want := []string{
		"agent_claude_code",
		"agent_cline",
		"agent_continue_dev",
		"agent_cursor",
		"agent_github_copilot",
		"agent_windsurf",
		"file_oversized",
		"semantic_instruction_override",
		"semantic_roleplay",
	}
	got := make([]string, 0, len(catalog))
	seen := map[string]bool{}
	for _, capability := range catalog {
		if seen[capability.Category] {
			t.Fatalf("duplicate dynamic capability %q", capability.Category)
		}
		seen[capability.Category] = true
		got = append(got, capability.Category)
		if strings.TrimSpace(capability.Name) == "" || strings.TrimSpace(capability.Component) == "" {
			t.Errorf("dynamic capability %q lacks customer name/component", capability.Category)
		}
		if len(capability.SupportedStages) == 0 || len(capability.AllowedActions) == 0 {
			t.Errorf("dynamic capability %q lacks stages/actions", capability.Category)
		}
		for _, forbidden := range []string{"timeout", "capacity_overflow", "telemetry", "shadow", "__normalized", "__decoded"} {
			if strings.Contains(capability.Category, forbidden) {
				t.Errorf("forbidden derived/operational capability %q", capability.Category)
			}
		}
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dynamic capability allowlist got=%v want=%v", got, want)
	}
}

func TestExactPolicyCapabilityBindingsMatchAuditedCatalog(t *testing.T) {
	source := readPolicyCapabilityMigration(t)
	migrationBindings := decodeMigrationJSONBlock[[]migrationBindingSeed](t, source, exactBindingMarker)
	migrationBindings = append(migrationBindings, decodeMigrationJSONBlock[[]migrationBindingSeed](t, readCapabilityMigration(t, sensitiveCapabilityMigration), sensitiveBindingMarker)...)
	migrationBindings = append(migrationBindings, runtimeBindingCatalog(t)...)
	retired := retiredStaticCapabilities(t)
	// 240 条冻结目录 + 迁移 992 新增的“辱骂脏话”。
	if len(exactPolicyCapabilityBindings) != 241 {
		t.Fatalf("exact Go binding policies=%d want=241", len(exactPolicyCapabilityBindings))
	}
	if len(migrationBindings) != 240 {
		t.Fatalf("exact migration binding policies=%d want=240", len(migrationBindings))
	}

	knownPolicies := map[string]string{}
	knownDisplayNames := map[string]bool{}
	for ruleType, rules := range defaultSubRules {
		for _, rule := range rules {
			knownPolicies[rule.PolicyCode] = ruleType + "\x00" + rule.Name
			knownDisplayNames[ruleType+"\x00"+rule.Name] = true
		}
	}
	staticCategories := decodeMigrationJSONBlock[[]string](t, source, staticCapabilityMarker)
	dynamicCapabilities := decodeMigrationJSONBlock[[]migrationCapabilitySeed](t, source, dynamicCapabilityMarker)
	knownCapabilities := map[string]bool{}
	for _, category := range staticCategories {
		knownCapabilities[category] = true
	}
	for _, capability := range dynamicCapabilities {
		knownCapabilities[capability.Category] = true
	}
	for _, capability := range decodeMigrationJSONBlock[[]migrationCapabilitySeed](t, readCapabilityMigration(t, sensitiveCapabilityMigration), sensitiveCapabilityMarker) {
		knownCapabilities[capability.Category] = true
	}
	for _, capability := range runtimeCapabilityCatalog(t) {
		knownCapabilities[capability.Category] = true
	}
	for _, capability := range decodeMigrationJSONBlock[[]migrationCapabilitySeed](t, readCapabilityMigration(t, profanityAbuseMigration), addedCapabilityMarker) {
		knownCapabilities[capability.Category] = true
	}

	type bindingValue struct {
		mode       string
		categories []string
	}
	goBindings := map[string]bindingValue{}
	for _, binding := range exactPolicyCapabilityBindings {
		displayKey := binding.RuleType + "\x00" + binding.Name
		if !knownDisplayNames[displayKey] {
			t.Errorf("binding references unknown default policy display %q", displayKey)
		}
		if got := knownPolicies[binding.PolicyCode]; got != displayKey {
			t.Errorf("binding policy_code %q resolves to %q want %q", binding.PolicyCode, got, displayKey)
		}
		if _, duplicate := goBindings[binding.PolicyCode]; duplicate {
			t.Errorf("duplicate exact policy binding %q", binding.PolicyCode)
		}
		categories := append([]string(nil), binding.CapabilityCategories...)
		for _, category := range categories {
			if retired[category] {
				t.Fatalf("Go binding %q references retired capability %q", binding.PolicyCode, category)
			}
		}
		sort.Strings(categories)
		for _, category := range categories {
			if !knownCapabilities[category] {
				t.Errorf("binding %q references unknown capability %q", binding.PolicyCode, category)
			}
		}
		goBindings[binding.PolicyCode] = bindingValue{mode: binding.BindingMode, categories: categories}
	}
	sshBinding, exact := exactCapabilityBindingForPolicy(defaultPolicyCode("data_leak", "SSH 密钥检测"))
	if !exact || !reflect.DeepEqual(sshBinding.CapabilityCategories, []string{"openssh_private_key"}) {
		t.Fatalf("SSH key policy binding=%+v exact=%v", sshBinding, exact)
	}
	for _, forbidden := range []string{"code_leak_api_key_leak", "code_leak_token_leak"} {
		for key, binding := range goBindings {
			for _, category := range binding.categories {
				if category == forbidden {
					t.Errorf("broad category %q must not be seeded as exact for %q", forbidden, key)
				}
			}
		}
	}

	migrationMap := map[string]bindingValue{}
	for _, binding := range migrationBindings {
		categories := withoutRetiredCapabilities(binding.CapabilityCategories, retired)
		sort.Strings(categories)
		migrationMap[binding.PolicyCode] = bindingValue{mode: binding.BindingMode, categories: categories}
	}
	for _, binding := range decodeMigrationJSONBlock[[]migrationBindingSeed](
		t, readCapabilityMigration(t, "815_bind_hardcoded_credential_policy_capability.sql"),
		"$added_exact_policy_capability_bindings$",
	) {
		categories := withoutRetiredCapabilities(binding.CapabilityCategories, retired)
		sort.Strings(categories)
		current := migrationMap[binding.PolicyCode]
		if current.mode != "" && current.mode != binding.BindingMode {
			t.Fatalf("migration binding mode conflict for %q: %q/%q", binding.PolicyCode, current.mode, binding.BindingMode)
		}
		current.mode = binding.BindingMode
		current.categories = append(current.categories, categories...)
		sort.Strings(current.categories)
		unique := current.categories[:0]
		for _, category := range current.categories {
			if len(unique) == 0 || unique[len(unique)-1] != category {
				unique = append(unique, category)
			}
		}
		current.categories = unique
		migrationMap[binding.PolicyCode] = current
	}
	for _, binding := range decodeMigrationJSONBlock[[]migrationBindingSeed](
		t, readCapabilityMigration(t, profanityAbuseMigration), addedBindingMarker,
	) {
		categories := withoutRetiredCapabilities(binding.CapabilityCategories, retired)
		sort.Strings(categories)
		if _, duplicate := migrationMap[binding.PolicyCode]; duplicate {
			t.Fatalf("migration 992 must add a new policy binding, %q already exists", binding.PolicyCode)
		}
		migrationMap[binding.PolicyCode] = bindingValue{mode: binding.BindingMode, categories: categories}
	}
	if !reflect.DeepEqual(migrationMap, goBindings) {
		t.Fatalf("migration and Go exact bindings differ\nmigration=%v\ngo=%v", migrationMap, goBindings)
	}
	for _, migration := range runtimeCatalogMigrations() {
		if migration != policyRetirementMigration && regexp.MustCompile(`(?i)delete\s+from\s+rules`).MatchString(readCapabilityMigration(t, migration)) {
			t.Fatalf("runtime capability migration %s must not delete policy rows", migration)
		}
	}
}

func TestRetiredDefaultPoliciesAreExplicitAndDoNotOverlapExecutableBindings(t *testing.T) {
	retiredCodes := decodeMigrationJSONBlock[[]string](
		t, readCapabilityMigration(t, policyRetirementMigration), retiredPolicyMarker,
	)
	if len(retiredCodes) != 15 || len(retiredDefaultPolicyCodes) != 15 {
		t.Fatalf("retired policy counts migration=%d go=%d want=15", len(retiredCodes), len(retiredDefaultPolicyCodes))
	}
	fromMigration := make(map[string]bool, len(retiredCodes))
	for _, code := range retiredCodes {
		if fromMigration[code] {
			t.Fatalf("duplicate retired policy code %q", code)
		}
		fromMigration[code] = true
		if _, known := retiredDefaultPolicyCodes[code]; !known {
			t.Errorf("migration retires unknown Go policy code %q", code)
		}
		if _, exact := exactCapabilityBindingForPolicy(code); exact {
			t.Errorf("retired policy %q also has an executable binding", code)
		}
	}
	for code, reason := range retiredDefaultPolicyCodes {
		if !fromMigration[code] {
			t.Errorf("Go-retired policy %q missing from migration", code)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("retired policy %q has no audit reason", code)
		}
	}
}

func TestHardcodedCredentialExactBindingIsAddedByForwardMigration(t *testing.T) {
	binding, exact := exactCapabilityBindingForPolicy(hardcodedCredentialPolicyCode)
	if !exact {
		t.Fatal("hardcoded credential policy must have an exact runtime capability binding")
	}
	if !reflect.DeepEqual(binding.CapabilityCategories, []string{"code_hardcoded_credential_generation", "code_leak_password_in_code"}) {
		t.Fatalf("categories=%v want both hardcoded-credential detectors", binding.CapabilityCategories)
	}
	if binding.BindingMode != "any" {
		t.Fatalf("binding_mode=%q want any", binding.BindingMode)
	}

	body := readCapabilityMigration(t, "815_bind_hardcoded_credential_policy_capability.sql")
	const marker = "$added_exact_policy_capability_bindings$"
	added := decodeMigrationJSONBlock[[]migrationBindingSeed](t, body, marker)
	if len(added) != 1 || added[0].PolicyCode != hardcodedCredentialPolicyCode {
		t.Fatalf("forward migration bindings=%+v", added)
	}
	if !reflect.DeepEqual(added[0].CapabilityCategories, []string{"code_leak_password_in_code"}) {
		t.Fatalf("forward migration categories=%v", added[0].CapabilityCategories)
	}
}

func TestDefaultPolicyCodesAreStableUniqueAndMigrationDoesNotAddRules(t *testing.T) {
	source := readPolicyCapabilityMigration(t)
	frozenCatalog := decodeMigrationJSONBlock[[]migrationPolicyIdentity](t, source, defaultPolicyMarker)
	if len(frozenCatalog) != 255 {
		t.Fatalf("frozen migration policy identities=%d want=255", len(frozenCatalog))
	}
	frozenIdentities := make(map[string]string, len(frozenCatalog))
	frozenCodes := make(map[string]bool, len(frozenCatalog))
	for _, identity := range frozenCatalog {
		key := identity.RuleType + "\x00" + identity.Name
		if previous, duplicate := frozenIdentities[key]; duplicate {
			t.Fatalf("duplicate frozen identity %q codes=%q/%q", key, previous, identity.PolicyCode)
		}
		frozenIdentities[key] = identity.PolicyCode
		if frozenCodes[identity.PolicyCode] {
			t.Fatalf("duplicate frozen policy code %q", identity.PolicyCode)
		}
		frozenCodes[identity.PolicyCode] = true
	}

	codePattern := regexp.MustCompile(`^builtin\.[a-z0-9_]+\.[a-f0-9]{16}$`)
	seen := map[string]string{}
	goCodes := map[string]bool{}
	count := 0
	for ruleType, rules := range defaultSubRules {
		for _, rule := range rules {
			count++
			code := rule.PolicyCode
			if !codePattern.MatchString(code) {
				t.Errorf("invalid policy code %q", code)
			}
			if previous, duplicate := seen[code]; duplicate {
				t.Errorf("duplicate policy code %q for %q and %q", code, previous, ruleType+"/"+rule.Name)
			}
			seen[code] = ruleType + "/" + rule.Name
			goCodes[code] = true
		}
	}
	// 255 条冻结目录 + 迁移 992 新增的“辱骂脏话”。冻结集合必须全部还在，新增的只能是 992 声明的。
	if count != 256 {
		t.Fatalf("default policy count=%d want=256", count)
	}
	addedCodes := map[string]bool{}
	for _, binding := range decodeMigrationJSONBlock[[]migrationBindingSeed](
		t, readCapabilityMigration(t, profanityAbuseMigration), addedBindingMarker,
	) {
		addedCodes[binding.PolicyCode] = true
	}
	expectedCodes := map[string]bool{}
	for code := range frozenCodes {
		expectedCodes[code] = true
	}
	for code := range addedCodes {
		if frozenCodes[code] {
			t.Fatalf("migration 992 policy %q is already in the frozen migration code set", code)
		}
		expectedCodes[code] = true
	}
	if !reflect.DeepEqual(expectedCodes, goCodes) {
		t.Fatal("current Go policy codes differ from the frozen migration code set plus migration 992")
	}

	lower := strings.ToLower(source)
	if regexp.MustCompile(`(?i)\binsert\s+into\s+rules(?:\s|\()`).MatchString(source) {
		t.Fatal("capability migration must not insert policy rows")
	}
	for _, required := range []string{
		"alter table rules add column if not exists policy_code",
		"create table if not exists security_capabilities",
		"create table if not exists rule_capability_bindings",
		"create unique index if not exists uq_rules_rule_set_policy_code",
		"ruleset_builtin_generic",
		"rule_g_phone",
		"rule_g_idcard",
		"rule_g_bankcard",
		"rule_g_email",
		"rule_g_passport",
		"having count(*) > 1",
		"ambiguous duplicate default policy rows",
		"policy action is not supported by its capability binding",
	} {
		if !strings.Contains(lower, required) {
			t.Errorf("migration missing required contract %q", required)
		}
	}
	for _, forbidden := range []string{"detector_policy", "semantic_timeout", "semantic_capacity_overflow"} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("migration contains forbidden old/operational concept %q", forbidden)
		}
	}
}

func TestDefaultPolicyIdentityDoesNotDependOnDisplayName(t *testing.T) {
	policy := defaultSubRules["prompt_injection"][0]
	if policy.PolicyCode == "" {
		t.Fatal("default policy seed is missing its literal policy code")
	}
	renamed := policy
	renamed.Name = "重命名后的展示文案"
	if renamed.PolicyCode != policy.PolicyCode {
		t.Fatal("changing display text changed the immutable policy identity")
	}
}

func TestAgentClientPoliciesUseControlLanguage(t *testing.T) {
	want := map[string]string{
		"builtin.agent_detect.f93768ab6617606e": "Claude Code 管控",
		"builtin.agent_detect.b620fc06d06c1fc7": "Cursor IDE 管控",
		"builtin.agent_detect.12438c4c568f8c24": "GitHub Copilot 管控",
		"builtin.agent_detect.60879276c451279a": "Cline/Roo Code 管控",
		"builtin.agent_detect.c1896e0995119428": "Windsurf/Cascade 管控",
		"builtin.agent_detect.1d449b7a84677bb2": "Continue.dev 管控",
	}
	for _, policy := range defaultSubRules["agent_detect"] {
		if name, ok := want[policy.PolicyCode]; ok {
			if policy.Name != name {
				t.Errorf("agent client policy %s name=%q want=%q", policy.PolicyCode, policy.Name, name)
			}
			delete(want, policy.PolicyCode)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing agent client policies: %v", want)
	}

	migration := readCapabilityMigration(t, agentControlMigration)
	for _, name := range []string{
		"Claude Code 管控", "Cursor IDE 管控", "GitHub Copilot 管控",
		"Cline/Roo Code 管控", "Windsurf/Cascade 管控", "Continue.dev 管控",
	} {
		if !strings.Contains(migration, name) {
			t.Errorf("agent control migration missing %q", name)
		}
	}
}

func TestPolicyCapabilityMigrationIsIdempotentAndPreservesPolicies(t *testing.T) {
	dsn := os.Getenv("RULES_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("RULES_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect migration test database: %v", err)
	}
	schema := fmt.Sprintf("policy_capability_%d", time.Now().UnixNano())
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		admin.Close()
		t.Fatalf("create migration schema: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		admin.Close()
		t.Fatalf("parse migration database: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		admin.Close()
		t.Fatalf("connect migration schema: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+ident+" CASCADE"); err != nil {
			t.Errorf("drop migration schema: %v", err)
		}
		admin.Close()
	})

	for _, statement := range []string{
		`CREATE TABLE tenants (id VARCHAR(64) PRIMARY KEY)`,
		`CREATE TABLE rule_sets (
			id VARCHAR(64) PRIMARY KEY,
			tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
			name VARCHAR(255) NOT NULL,
			source_type VARCHAR(32)
		)`,
		`CREATE TABLE rules (
			id VARCHAR(64) PRIMARY KEY,
			rule_set_id VARCHAR(64) NOT NULL REFERENCES rule_sets(id),
			rule_type VARCHAR(64) NOT NULL,
			name VARCHAR(255) NOT NULL,
			severity VARCHAR(32) DEFAULT 'medium',
			scope_json JSONB DEFAULT '{}',
			match_config_json JSONB DEFAULT '{}',
			action VARCHAR(32) NOT NULL DEFAULT 'audit',
			enabled BOOLEAN DEFAULT TRUE,
			description TEXT DEFAULT ''
		)`,
		`INSERT INTO tenants(id) VALUES ('tenant_a'),('tenant_b'),('tenant_system')`,
		`INSERT INTO rule_sets(id,tenant_id,name,source_type) VALUES
			('rs_a','tenant_a','默认安全策略','system'),
			('rs_b','tenant_b','默认安全策略','system'),
			('rs_manual','tenant_a','客户规则','manual'),
			('ruleset_builtin_generic','tenant_system','通用数据安全（PII）','builtin')`,
		`INSERT INTO rules(id,rule_set_id,rule_type,name,severity,action,enabled) VALUES
			('rule_manual_same_name','rs_manual','prompt_injection','经典注入指令检测','high','audit',true),
			('rule_g_phone','ruleset_builtin_generic','regex','手机号','medium','audit',true),
			('rule_g_idcard','ruleset_builtin_generic','regex','身份证号','high','audit',true),
			('rule_g_bankcard','ruleset_builtin_generic','regex','银行卡号','high','audit',true),
			('rule_g_email','ruleset_builtin_generic','regex','电子邮箱','low','audit',true),
			('rule_g_passport','ruleset_builtin_generic','regex','护照号','high','audit',true)`,
	} {
		if _, err := db.Exec(ctx, statement); err != nil {
			t.Fatalf("prepare migration fixture: %v", err)
		}
	}
	// Migration 125 predates the retirement in migration 166: seed its own
	// frozen identity catalog instead of the current 240-entry runtime catalog.
	legacyCatalog := decodeMigrationJSONBlock[[]migrationPolicyIdentity](t, readPolicyCapabilityMigration(t), defaultPolicyMarker)
	if len(legacyCatalog) != 255 {
		t.Fatalf("migration 125 identity catalog=%d want=255", len(legacyCatalog))
	}
	legacyIndex := 0
	for _, ruleSetID := range []string{"rs_a", "rs_b"} {
		for _, rule := range legacyCatalog {
			legacyIndex++
			if _, err := db.Exec(ctx, `
					INSERT INTO rules(id,rule_set_id,rule_type,name,severity,action,enabled,description)
					VALUES($1,$2,$3,$4,$5,$6,true,$7)`,
				fmt.Sprintf("legacy_%03d", legacyIndex), ruleSetID, rule.RuleType, rule.Name,
				"medium", "audit", "",
			); err != nil {
				t.Fatalf("insert legacy default policy %s/%s: %v", rule.RuleType, rule.Name, err)
			}
		}
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO rules(id,rule_set_id,rule_type,name,severity,match_config_json,action,enabled,description)
		VALUES('rule_same_name_custom','rs_a','prompt_injection','经典注入指令检测','high',
		       '{"keywords":["customer matcher"]}'::jsonb,'audit',true,'customer rule with the same display name')`); err != nil {
		t.Fatalf("insert same-name customer rule: %v", err)
	}

	var beforeCount int
	var beforeSnapshot string
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM rules`).Scan(&beforeCount); err != nil {
		t.Fatalf("count policies before migration: %v", err)
	}
	if err := db.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(r)-'policy_code' ORDER BY r.id)::text FROM rules r`).Scan(&beforeSnapshot); err != nil {
		t.Fatalf("snapshot policies before migration: %v", err)
	}
	migration := readPolicyCapabilityMigration(t)
	for run := 1; run <= 2; run++ {
		if _, err := db.Exec(ctx, migration); err != nil {
			t.Fatalf("migration run %d: %v", run, err)
		}
	}
	if _, err := db.Exec(ctx, `UPDATE security_capabilities SET enabled=false WHERE category='semantic_roleplay'`); err != nil {
		t.Fatalf("disable capability before idempotency check: %v", err)
	}
	if _, err := db.Exec(ctx, migration); err != nil {
		t.Fatalf("migration must preserve a runtime-disabled capability: %v", err)
	}
	sensitiveMigration := readCapabilityMigration(t, sensitiveCapabilityMigration)
	for run := 1; run <= 2; run++ {
		if _, err := db.Exec(ctx, sensitiveMigration); err != nil {
			t.Fatalf("sensitive capability migration run %d: %v", run, err)
		}
	}
	retirement := readCapabilityMigration(t, retiredCapabilityMigration)
	for run := 1; run <= 2; run++ {
		if _, err := db.Exec(ctx, retirement); err != nil {
			t.Fatalf("retirement migration run %d: %v", run, err)
		}
	}
	forwardBinding := readCapabilityMigration(t, "815_bind_hardcoded_credential_policy_capability.sql")
	for run := 1; run <= 2; run++ {
		if _, err := db.Exec(ctx, forwardBinding); err != nil {
			t.Fatalf("forward binding migration run %d: %v", run, err)
		}
	}
	var retiredEnabled bool
	var retiredBindings int
	if err := db.QueryRow(ctx, `SELECT enabled FROM security_capabilities WHERE category='encoding_zero_width'`).Scan(&retiredEnabled); err != nil {
		t.Fatalf("read retired capability: %v", err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM rule_capability_bindings b JOIN security_capabilities c ON c.id=b.capability_id WHERE c.category='encoding_zero_width'`).Scan(&retiredBindings); err != nil {
		t.Fatalf("count retired capability bindings: %v", err)
	}
	if retiredEnabled || retiredBindings != 0 {
		t.Fatalf("retired capability enabled=%v bindings=%d", retiredEnabled, retiredBindings)
	}
	var disabledCapabilityStillDisabled bool
	if err := db.QueryRow(ctx, `SELECT NOT enabled FROM security_capabilities WHERE category='semantic_roleplay'`).Scan(&disabledCapabilityStillDisabled); err != nil || !disabledCapabilityStillDisabled {
		t.Fatalf("migration re-enabled runtime-disabled capability disabled=%v err=%v", disabledCapabilityStillDisabled, err)
	}

	var afterCount, staticCount, dynamicCount, boundPolicies, bindingRows int
	var afterSnapshot string
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM rules`).Scan(&afterCount); err != nil {
		t.Fatalf("count policies after migration: %v", err)
	}
	if err := db.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(r)-'policy_code' ORDER BY r.id)::text FROM rules r`).Scan(&afterSnapshot); err != nil {
		t.Fatalf("snapshot policies after migration: %v", err)
	}
	if beforeSnapshot != afterSnapshot {
		t.Fatal("migration changed policy fields other than policy_code")
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FILTER (WHERE capability_kind='static'), COUNT(*) FILTER (WHERE capability_kind='dynamic') FROM security_capabilities`).Scan(&staticCount, &dynamicCount); err != nil {
		t.Fatalf("count capabilities: %v", err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(DISTINCT rule_id), COUNT(*) FROM rule_capability_bindings`).Scan(&boundPolicies, &bindingRows); err != nil {
		t.Fatalf("count exact bindings: %v", err)
	}
	expectedBindingRows := 0
	for _, binding := range append(
		decodeMigrationJSONBlock[[]migrationBindingSeed](t, migration, exactBindingMarker),
		decodeMigrationJSONBlock[[]migrationBindingSeed](t, sensitiveMigration, sensitiveBindingMarker)...,
	) {
		expectedBindingRows += len(binding.CapabilityCategories) * 2
	}
	if beforeCount != afterCount || staticCount != 102 || dynamicCount != 9 || boundPolicies != 118 || bindingRows != expectedBindingRows {
		t.Fatalf("migration counts rules=%d->%d static=%d dynamic=%d bound=%d rows=%d", beforeCount, afterCount, staticCount, dynamicCount, boundPolicies, bindingRows)
	}
	var codedDefaults int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM rules r JOIN rule_sets rs ON rs.id=r.rule_set_id
		WHERE rs.source_type='system' AND rs.name='默认安全策略' AND r.policy_code IS NOT NULL`,
	).Scan(&codedDefaults); err != nil || codedDefaults != 510 {
		t.Fatalf("coded legacy defaults=%d err=%v want=510", codedDefaults, err)
	}

	var manualCode string
	if err := db.QueryRow(ctx, `SELECT COALESCE(policy_code,'') FROM rules WHERE id='rule_manual_same_name'`).Scan(&manualCode); err != nil {
		t.Fatalf("read manual policy code: %v", err)
	}
	if manualCode != "" {
		t.Fatalf("manual policy received internal code %q", manualCode)
	}
	var customCode string
	var customBindings int
	if err := db.QueryRow(ctx, `
		SELECT COALESCE(r.policy_code,''),COUNT(b.rule_id)
		FROM rules r LEFT JOIN rule_capability_bindings b ON b.rule_id=r.id
		WHERE r.id='rule_same_name_custom'
		GROUP BY r.policy_code`,
	).Scan(&customCode, &customBindings); err != nil {
		t.Fatalf("read same-name customer rule: %v", err)
	}
	if customCode != "" || customBindings != 0 {
		t.Fatalf("same-name customer rule was cataloged code=%q bindings=%d", customCode, customBindings)
	}
	var systemCoded int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM rules WHERE rule_set_id='ruleset_builtin_generic' AND policy_code IS NOT NULL`).Scan(&systemCoded); err != nil || systemCoded != 5 {
		t.Fatalf("system generic policy codes=%d err=%v want=5", systemCoded, err)
	}

	if _, err := db.Exec(ctx, `
		INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode)
		VALUES ('legacy_001','cap.static.keyword_classic_injection','invalid')`); err == nil {
		t.Fatal("binding_mode constraint accepted invalid value")
	}

	if _, err := db.Exec(ctx, `DELETE FROM rule_capability_bindings; DELETE FROM rules`); err != nil {
		t.Fatalf("prepare fresh-install policy state: %v", err)
	}
	if _, err := db.Exec(ctx, sensitiveMigration); err != nil {
		t.Fatalf("sensitive capability migration must allow bootstrap before default policies exist: %v", err)
	}
	var freshCapabilityCount int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM security_capabilities
		WHERE metadata_json->>'catalog'='sensitive_data_complete'`,
	).Scan(&freshCapabilityCount); err != nil {
		t.Fatalf("count fresh-install sensitive capabilities: %v", err)
	}
	if freshCapabilityCount != 22 {
		t.Fatalf("fresh-install sensitive capabilities=%d want=22", freshCapabilityCount)
	}
}
