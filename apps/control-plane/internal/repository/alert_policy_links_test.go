package repository

import "testing"

func TestAlertOccurrencePolicyLinkCoversAgentToolAlerts(t *testing.T) {
	cases := []struct {
		name string
		item AlertOccurrence
		want string
	}{
		{"managed tool alert", AlertOccurrence{Type: "tool_policy_alert", RuleID: "policy-center-network_egress", RuleName: "curl", RuleType: "agentguard"}, "/security/agents?behavior=network_egress"},
		{"custom advanced tool alert", AlertOccurrence{Type: "tool_policy_alert", RuleID: "adv_rule_1", RuleName: "curl", RuleType: "agentguard"}, ""},
		{"unknown managed key", AlertOccurrence{Type: "tool_policy_alert", RuleID: "policy-center-nope", RuleType: "agentguard"}, ""},
		{"restricted file input", AlertOccurrence{Type: "restricted_file_access", Category: "restricted_file_access", RuleID: "agentguard-restricted-file-pattern", RuleName: "agentguard-restricted-file-pattern"}, "/security/agents?behavior=sensitive_resource"},
		{"restricted file tool audit", AlertOccurrence{Type: "security_audit", Category: "restricted_file_access", RuleName: "Read"}, "/security/agents?behavior=sensitive_resource"},
		{"custom rule borrowing the category", AlertOccurrence{Category: "restricted_file_access", RuleID: "rule_abc", RuleType: "regex", RuleName: "x"}, "/security/policies?policy=rule_abc"},
		{"confirmation release", AlertOccurrence{Type: "security_audit", Category: "agentguard_confirmation", RuleName: "Bash"}, ""},
		{"policy load failure", AlertOccurrence{Type: "coverage_gap", RuleID: "agentguard_policy_load_failed", RuleName: "Bash"}, ""},
		{"blocked destructive call", AlertOccurrence{Type: "tool_attempt_blocked", RuleID: "destructive_operation", RuleName: "删除与破坏"}, "/security/agents?behavior=destructive_operation"},
		{"blocked managed call", AlertOccurrence{Type: "tool_attempt_blocked", RuleName: "系统命令", ManagedBehavior: "system_command"}, "/security/agents?behavior=system_command"},
		{"blocked call with unknown behavior", AlertOccurrence{Type: "tool_attempt_blocked", RuleName: "x", ManagedBehavior: "nope"}, ""},
		{"behavior only counts for the blocked call finding", AlertOccurrence{Type: "pii", ManagedBehavior: "system_command"}, ""},
		{"destructive still works", AlertOccurrence{Type: "tool_destructive_intent", RuleName: "Bash"}, "/security/agents?behavior=destructive_operation"},
	}
	for _, tc := range cases {
		link := alertPolicyLink(&tc.item)
		got := ""
		if link != nil {
			got = link.Path
		}
		if got != tc.want {
			t.Fatalf("%s: path=%q want %q", tc.name, got, tc.want)
		}
	}
}
