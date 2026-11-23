package handler

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

func TestRuleRuntimeStatusReportsStableCompiledRuleIDs(t *testing.T) {
	pack := &rules.RulePack{
		Version: "version-compiled-ids",
		Rules: []rules.CompiledRule{
			{RuleID: "rule-z"},
			{RuleID: "rule-a"},
			{RuleID: "rule-m"},
		},
		Diagnostics: rules.RuleDiagnostics{
			CatalogCount:  5,
			CompiledCount: 3,
			SkippedCount:  2,
		},
	}

	status := ruleRuntimeStatusFromPack(pack, rulePackConvergence{})
	want := []string{"rule-a", "rule-m", "rule-z"}
	if !reflect.DeepEqual(status.CompiledRuleIDs, want) {
		t.Fatalf("compiled_rule_ids = %v, want stable complete set %v", status.CompiledRuleIDs, want)
	}
}

func TestRuleRuntimeStatusReportsRuleDetailsAndConfiguredPendingOnly(t *testing.T) {
	pack := &rules.RulePack{
		Version: "version-rule-details",
		Rules: []rules.CompiledRule{
			{RuleID: "rule-z", RuleName: "手机号检测", RuleType: "regex", Category: "phone", Severity: "medium", Action: "audit"},
			{RuleID: "rule-a", RuleName: "身份证号检测", RuleType: "regex", Category: "idcard", Severity: "critical", Action: "block"},
		},
		Skipped: []rules.SkippedRule{
			{RuleID: "catalog", RuleName: "能力目录", RuleType: "prompt_injection", Reason: "no_supported_matcher"},
			{RuleID: "disabled", RuleName: "停用邮箱规则", RuleType: "regex", Reason: "disabled", ConfiguredMatcher: true},
		},
		Diagnostics: rules.RuleDiagnostics{CatalogCount: 4, CompiledCount: 2, SkippedCount: 2, PendingCount: 1},
	}

	status := ruleRuntimeStatusFromPack(pack, rulePackConvergence{})

	if status.PendingCount != 1 || len(status.PendingRules) != 1 {
		t.Fatalf("pending_count=%d pending=%+v", status.PendingCount, status.PendingRules)
	}
	if status.PendingRules[0].RuleName != "停用邮箱规则" || status.PendingRules[0].Reason != "disabled" {
		t.Fatalf("pending=%+v", status.PendingRules)
	}
	if len(status.CompiledRules) != 2 || status.CompiledRules[0].RuleID != "rule-a" || status.CompiledRules[0].RuleName != "身份证号检测" {
		t.Fatalf("compiled rules must be stable and complete: %+v", status.CompiledRules)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	if strings.Contains(string(encoded), "能力目录") {
		t.Fatalf("capability catalog leaked into customer pending rules: %s", encoded)
	}
}

func TestUnavailableRuleRuntimeStatusSerializesEmptyCompiledRuleIDs(t *testing.T) {
	encoded, err := json.Marshal(unavailableRuleRuntimeStatus())
	if err != nil {
		t.Fatalf("marshal unavailable runtime status: %v", err)
	}
	if !strings.Contains(string(encoded), `"compiled_rule_ids":[]`) {
		t.Fatalf("unavailable runtime must expose an empty array, got %s", encoded)
	}
}

func TestRuleRuntimeStatusExposesEnabledUnsupportedPolicyAction(t *testing.T) {
	pack := &rules.RulePack{
		Version: "unsupported-policy-action",
		Skipped: []rules.SkippedRule{{
			RuleID: "policy-1", PolicyCode: "builtin.test.policy-1",
			RuleName: "策略一", RuleType: "scene_policy", Action: "reply",
			Enabled: true, Reason: "unsupported_policy_action",
		}},
		Diagnostics: rules.RuleDiagnostics{
			CatalogCount: 1,
			SkippedCount: 1,
			PendingCount: 1,
			SkipReasons:  map[string]int{"unsupported_policy_action": 1},
		},
		Degraded: true,
	}
	status := ruleRuntimeStatusFromPack(pack, rulePackConvergence{})
	if len(status.PendingRules) != 1 || status.PendingRules[0].Reason != "unsupported_policy_action" {
		t.Fatalf("pending_rules=%+v", status.PendingRules)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"unsupported_policy_action", "builtin.test.policy-1", "reply", "策略一", "runtime_pack_degraded"} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("runtime status missing %q: %s", want, encoded)
		}
	}
}
