package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func runtimeCapability(category string) repository.RuntimePolicyCapability {
	return repository.RuntimePolicyCapability{
		Category:        category,
		BindingMode:     "any",
		Enabled:         true,
		SupportedStages: []string{"input", "output"},
		AllowedActions:  []string{"audit", "block"},
		MaskCapable:     false,
	}
}

func capabilityPolicy(index int) *repository.Rule {
	return &repository.Rule{
		ID:                  fmt.Sprintf("policy_bound_%02d", index),
		PolicyCode:          fmt.Sprintf("builtin.bound.%02d", index),
		RuleType:            "prompt_injection",
		Name:                fmt.Sprintf("能力策略 %02d", index),
		Severity:            "critical",
		Action:              "audit",
		Enabled:             true,
		MatchConfigJSON:     []byte(`{}`),
		RuntimeCapabilities: []repository.RuntimePolicyCapability{runtimeCapability(fmt.Sprintf("category_%02d", index))},
	}
}

func matcherIdentityPolicy(index int) *repository.Rule {
	return &repository.Rule{
		ID:              fmt.Sprintf("matcher_%02d", index),
		PolicyCode:      fmt.Sprintf("system.generic.matcher_%02d", index),
		RuleType:        "keyword",
		Name:            fmt.Sprintf("扩展规则 %02d", index),
		Severity:        "medium",
		Action:          "audit",
		Enabled:         true,
		MatchConfigJSON: []byte(fmt.Sprintf(`{"keywords":["marker-%02d"],"category":"custom_%02d"}`, index, index)),
	}
}

func managementOnlyPolicy(index int) *repository.Rule {
	return &repository.Rule{
		ID:              fmt.Sprintf("management_%03d", index),
		PolicyCode:      fmt.Sprintf("builtin.management.%03d", index),
		RuleType:        "content_safety",
		Name:            fmt.Sprintf("管理策略 %03d", index),
		Severity:        "medium",
		Action:          "audit",
		Enabled:         true,
		MatchConfigJSON: []byte(`{}`),
	}
}

func TestCompilePoliciesIncludesFiftyEightBindingsAndFiveMatcherIdentities(t *testing.T) {
	candidates := make([]*repository.Rule, 0, 260)
	for index := 0; index < 58; index++ {
		candidates = append(candidates, capabilityPolicy(index))
	}
	for index := 0; index < 5; index++ {
		candidates = append(candidates, matcherIdentityPolicy(index))
	}
	for index := 0; index < 197; index++ {
		candidates = append(candidates, managementOnlyPolicy(index))
	}

	pack := Compile("tenant-a", candidates, nil)
	if len(pack.Policies) != 63 {
		t.Fatalf("policies=%d want 63", len(pack.Policies))
	}
	if len(pack.Rules) != 5 {
		t.Fatalf("matcher rules=%d want 5", len(pack.Rules))
	}
	if pack.Diagnostics.CatalogCount != 260 || pack.Diagnostics.CompiledCount != 63 || pack.Diagnostics.SkippedCount != 197 {
		t.Fatalf("diagnostics=%+v want catalog/compiled/skipped 260/63/197", pack.Diagnostics)
	}
	if got := pack.Diagnostics.SkipReasons["management_only"]; got != 197 {
		t.Fatalf("management_only=%d want 197", got)
	}

	bound := pack.Policies[0]
	if bound.PolicyCode != "builtin.bound.00" || bound.PolicyID != "policy_bound_00" || bound.PolicyName != "能力策略 00" || bound.PolicyType != "prompt_injection" {
		t.Fatalf("bound policy identity=%+v", bound)
	}
	if bound.Action != "audit" || !bound.Enabled || bound.BindingMode != "any" || len(bound.Capabilities) != 1 {
		t.Fatalf("bound policy runtime contract=%+v", bound)
	}
	identity := pack.Policies[58]
	if identity.PolicyID != "matcher_00" || identity.MatcherRuleID != "matcher_00" || len(identity.Capabilities) != 0 {
		t.Fatalf("matcher identity policy=%+v", identity)
	}
}

func TestCompilePoliciesCarriesDisabledPolicyForRuntimeSuppression(t *testing.T) {
	policy := capabilityPolicy(0)
	policy.Enabled = false

	pack := Compile("tenant-a", []*repository.Rule{policy}, nil)
	if len(pack.Policies) != 1 || pack.Policies[0].Enabled {
		t.Fatalf("disabled configured policy must enter pack as disabled: %+v", pack.Policies)
	}
	if pack.Diagnostics.CompiledCount != 1 || pack.Diagnostics.SkippedCount != 0 {
		t.Fatalf("disabled policy is a compiled suppression instruction: %+v", pack.Diagnostics)
	}
}

func TestHardcodedCredentialEnabledBuiltinEntersRuntimePolicyPack(t *testing.T) {
	policy := &repository.Rule{
		ID:         "hardcoded-credential-policy",
		PolicyCode: "builtin.code_security.9640acf0d1083905",
		RuleType:   "code_security",
		Name:       "硬编码凭据示例",
		Severity:   "high",
		Action:     "block",
		Enabled:    true,
		RuntimeCapabilities: []repository.RuntimePolicyCapability{{
			Category:        "code_leak_password_in_code",
			BindingMode:     "any",
			Enabled:         true,
			SupportedStages: []string{"input", "output"},
			AllowedActions:  []string{"audit", "block"},
			MaskCapable:     false,
		}},
	}
	pack := Compile("tenant-a", []*repository.Rule{policy}, nil)
	if len(pack.Policies) != 1 {
		t.Fatalf("policies=%d skipped=%+v diagnostics=%+v", len(pack.Policies), pack.Skipped, pack.Diagnostics)
	}
	compiled := pack.Policies[0]
	if compiled.PolicyCode != policy.PolicyCode || compiled.Action != "block" || !compiled.Enabled {
		t.Fatalf("compiled policy=%+v", compiled)
	}
	if len(compiled.Capabilities) != 1 || compiled.Capabilities[0].Category != "code_leak_password_in_code" || compiled.Capabilities[0].MaskCapable {
		t.Fatalf("compiled capabilities=%+v", compiled.Capabilities)
	}
}

func TestEnabledBuiltinUnsupportedActionIsExplicitlyDegradedAndPending(t *testing.T) {
	policy := capabilityPolicy(0)
	policy.Action = "mask"

	pack := Compile("tenant-a", []*repository.Rule{policy}, nil)
	if !pack.Degraded {
		t.Fatal("enabled unsupported policy action must degrade the runtime pack")
	}
	if pack.Diagnostics.PendingCount != 1 || pack.Diagnostics.SkipReasons["unsupported_policy_action"] != 1 {
		t.Fatalf("diagnostics=%+v", pack.Diagnostics)
	}
	if len(pack.Skipped) != 1 || pack.Skipped[0].Reason != "unsupported_policy_action" {
		t.Fatalf("skipped=%+v", pack.Skipped)
	}
	if !containsValue(pack.Warnings, "enabled_policy_unsupported_action") {
		t.Fatalf("warnings=%v", pack.Warnings)
	}
}

func TestAllEnabledAuditedBuiltinPoliciesEnterRuntimePack(t *testing.T) {
	contracts := repository.DefaultRuntimePolicyContracts()
	policies := make([]*repository.Rule, 0, len(contracts))
	maskCapable := map[string]bool{
		"phone_cn": true, "id_card_cn": true, "bank_card_cn": true, "email": true,
		"passport_cn": true, "hk_macao_taiwan_id": true, "officer_id_cn": true,
		"driver_license_cn": true, "social_security_cn": true, "home_address_cn": true,
		"ip_address": true, "birth_date": true, "communication_record": true,
		"gps_location": true, "plain_password": true, "cloud_credential": true,
		"credit_card_cvv": true, "bank_statement": true, "insurance_info": true,
		"medical_record": true, "genetic_data": true, "biometric_data": true,
		"internal_project_code": true, "sensitive_code": true,
		"education_background": true, "criminal_record": true,
	}
	for index, contract := range contracts {
		capabilities := make([]repository.RuntimePolicyCapability, 0, len(contract.CapabilityCategories))
		for _, category := range contract.CapabilityCategories {
			actions := []string{"audit", "block"}
			if maskCapable[category] {
				actions = []string{"audit", "mask", "block"}
			}
			capabilities = append(capabilities, repository.RuntimePolicyCapability{
				Category: category, BindingMode: contract.BindingMode, Enabled: true,
				SupportedStages: []string{"input", "output"},
				AllowedActions:  actions, MaskCapable: maskCapable[category],
			})
		}
		policies = append(policies, &repository.Rule{
			ID: fmt.Sprintf("builtin-contract-%02d", index), PolicyCode: contract.PolicyCode,
			RuleType: contract.RuleType, Name: contract.Name, Severity: "high",
			Action: contract.Action, Enabled: true, RuntimeCapabilities: capabilities,
		})
	}
	pack := Compile("tenant-a", policies, nil)
	if len(pack.Policies) != len(contracts) || pack.Diagnostics.SkippedCount != 0 || pack.Degraded {
		t.Fatalf("compiled=%d want=%d skipped=%+v diagnostics=%+v warnings=%v",
			len(pack.Policies), len(contracts), pack.Skipped, pack.Diagnostics, pack.Warnings)
	}
	for _, policy := range pack.Policies {
		if !policy.Enabled || policy.Action == "" || len(policy.Capabilities) == 0 {
			t.Fatalf("enabled built-in missing runtime contract: %+v", policy)
		}
	}
}

func TestCompileGenericPIIMatcherCarriesDataLeakScene(t *testing.T) {
	policy := &repository.Rule{
		ID: "rule_g_phone", PolicyCode: "system.generic.rule_g_phone",
		RuleType: "regex", Name: "手机号检测", Severity: "high", Action: "audit", Enabled: true,
		ScopeJSON:       []byte(`{"data_level":"L3","scene":"data_leak"}`),
		MatchConfigJSON: []byte(`{"regex":"1[3-9][0-9]{9}"}`),
	}
	pack := Compile("tenant-a", []*repository.Rule{policy}, nil)
	if len(pack.Policies) != 1 || pack.Policies[0].Scene != "data_leak" {
		t.Fatalf("compiled PII policy scene=%+v want data_leak", pack.Policies)
	}
	if len(pack.Rules) != 1 || pack.Rules[0].Scope["scene"] != "data_leak" {
		t.Fatalf("compiled PII matcher scope=%+v want data_leak", pack.Rules)
	}
}

func TestPolicyContentChangesRulePackVersion(t *testing.T) {
	policy := capabilityPolicy(0)
	before := Compile("tenant-a", []*repository.Rule{policy}, nil)
	policy.Action = "block"
	after := Compile("tenant-a", []*repository.Rule{policy}, nil)
	if before.Version == after.Version {
		t.Fatal("policy action must participate in rule-pack content version")
	}
}

func TestCompileRejectsHybridMatcherAndCapabilityPolicy(t *testing.T) {
	policy := capabilityPolicy(0)
	policy.RuleType = "keyword"
	policy.MatchConfigJSON = []byte(`{"keywords":["legacy-marker"],"category":"legacy"}`)

	pack := Compile("tenant-a", []*repository.Rule{policy}, nil)
	if len(pack.Policies) != 0 || len(pack.Rules) != 0 {
		t.Fatalf("hybrid policy must fail closed, got policies/rules=%d/%d", len(pack.Policies), len(pack.Rules))
	}
	if pack.Diagnostics.CompiledCount != 0 || pack.Diagnostics.SkippedCount != 1 {
		t.Fatalf("hybrid policy diagnostics=%+v", pack.Diagnostics)
	}
	if got := pack.Diagnostics.SkipReasons["hybrid_detection_basis_unsupported"]; got != 1 {
		t.Fatalf("hybrid skip reason=%d want 1; diagnostics=%+v", got, pack.Diagnostics)
	}
}

func TestTenantCapabilityAdditionAndClearChangePackMembership(t *testing.T) {
	defaults := make([]*repository.Rule, 0, 260)
	for index := 0; index < 58; index++ {
		defaults = append(defaults, capabilityPolicy(index))
	}
	for index := 0; index < 5; index++ {
		defaults = append(defaults, matcherIdentityPolicy(index))
	}
	for index := 0; index < 197; index++ {
		defaults = append(defaults, managementOnlyPolicy(index))
	}

	tenantPolicy := capabilityPolicy(99)
	tenantPolicy.ID = "tenant_scene_policy"
	tenantPolicy.PolicyCode = "tenant.scene.policy"
	withAddition := append(append([]*repository.Rule{}, defaults...), tenantPolicy)
	added := Compile("tenant-a", withAddition, nil)
	if len(added.Policies) != 64 || len(added.Rules) != 5 {
		t.Fatalf("tenant addition pack policies/rules=%d/%d want 64/5", len(added.Policies), len(added.Rules))
	}
	if added.Diagnostics.SkippedCount != 197 {
		t.Fatalf("tenant addition skipped=%d want 197", added.Diagnostics.SkippedCount)
	}

	// An explicit empty detector selection removes this capability-only policy
	// from the executable pack while retaining it in the management catalog.
	tenantPolicy.RuntimeCapabilities = []repository.RuntimePolicyCapability{}
	cleared := Compile("tenant-a", withAddition, nil)
	if len(cleared.Policies) != 63 || len(cleared.Rules) != 5 {
		t.Fatalf("cleared pack policies/rules=%d/%d want 63/5", len(cleared.Policies), len(cleared.Rules))
	}
	if cleared.Diagnostics.SkipReasons["management_only"] != 198 {
		t.Fatalf("cleared management-only diagnostics=%+v", cleared.Diagnostics)
	}
}

func TestCompiledPolicyMatchesSecurityEngineWireFixture(t *testing.T) {
	rule := &repository.Rule{
		ID:              "contract_policy_phone",
		PolicyCode:      "contract.scene.phone",
		RuleType:        "scene_policy",
		Name:            "手机号场景",
		Severity:        "high",
		Action:          "mask",
		Enabled:         true,
		ScopeJSON:       []byte(`{"scene":"data_leak"}`),
		MatchConfigJSON: []byte(`{}`),
		RuntimeCapabilities: []repository.RuntimePolicyCapability{{
			Category:        "phone_cn",
			BindingMode:     "any",
			Enabled:         true,
			SupportedStages: []string{"output", "input"},
			AllowedActions:  []string{"mask", "audit", "block"},
			MaskCapable:     true,
		}},
	}
	pack := Compile("tenant-a", []*repository.Rule{rule}, nil)
	if len(pack.Policies) != 1 {
		t.Fatalf("compiled policy count=%d want 1", len(pack.Policies))
	}
	actualJSON, err := json.Marshal(pack.Policies[0])
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := os.ReadFile("../../../../deploy/tests/fixtures/compiled_policy_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var actual, expected any
	if err := json.Unmarshal(actualJSON, &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(expectedJSON, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("wire contract drift\nactual=%s\nexpected=%s", actualJSON, expectedJSON)
	}
}

func TestCompilePolicyCarriesSceneFromScope(t *testing.T) {
	rule := capabilityPolicy(0)
	rule.ScopeJSON = []byte(`{"scene":"prompt_injection"}`)

	pack := Compile("tenant-a", []*repository.Rule{rule}, nil)
	if len(pack.Policies) != 1 {
		t.Fatalf("compiled policy count=%d want 1", len(pack.Policies))
	}
	encoded, err := json.Marshal(pack.Policies[0])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["scene"] != "prompt_injection" {
		t.Fatalf("compiled scene=%v want prompt_injection; payload=%s", payload["scene"], encoded)
	}
}
