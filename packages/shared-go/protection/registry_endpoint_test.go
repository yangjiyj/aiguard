package protection

import "testing"

func TestEndpointRuleItemsAreRegisteredPerBuiltinRule(t *testing.T) {
	want := []string{
		"builtin_destructive_rm", "builtin_destructive_system", "builtin_destructive_dd",
		"builtin_secret_arguments", "builtin_ssh_authorized_keys", "builtin_ssh_private_keys",
		"builtin_env_files", "builtin_curl_file_egress",
	}
	count := 0
	for _, item := range All() {
		if item.Group == GroupEndpoint {
			count++
		}
	}
	if count != len(want) {
		t.Fatalf("endpoint items = %d, want %d", count, len(want))
	}
	for _, ruleID := range want {
		item, ok := Lookup(EndpointRuleKey(ruleID))
		if !ok {
			t.Fatalf("%s not registered", ruleID)
		}
		if item.Group != GroupEndpoint || item.Default != ActionAlertAllow || item.Label == "" {
			t.Fatalf("%s: %+v", ruleID, item)
		}
		if byReason, ok := ItemForReason(ruleID); !ok || byReason.Key != item.Key {
			t.Fatalf("rule id %s must be the item's reason code: %+v", ruleID, byReason)
		}
		for _, action := range []Action{ActionRecord, ActionAlertAllow, ActionConfirm, ActionBlock} {
			if !item.Allows(action) {
				t.Fatalf("%s must allow %s", item.Key, action)
			}
		}
	}
	if got := EndpointRuleID("endpoint.rule.builtin_env_files"); got != "builtin_env_files" {
		t.Fatalf("EndpointRuleID = %q", got)
	}
	if got := EndpointRuleID("agent.env_file"); got != "" {
		t.Fatalf("non-endpoint key must not map to a rule: %q", got)
	}
}
