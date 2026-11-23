package agentguardmatch

import "testing"

func TestGovernanceCanonicalToolClassificationAndProvenance(t *testing.T) {
	for _, test := range []struct{ name, configured, want, source string }{
		{"mcp__server__read", "file", "mcp", "name_classification"},
		{"Skill", "system", "skill", "name_classification"},
		{"skill__team_helper", "network", "skill", "name_classification"},
		{"write_stdin", "", "system", "name_classification"},
		{"Read", "network", "network", "configured_mapping"},
		{"custom_opaque", "system", "system", "configured_mapping"},
		{"custom_opaque", "", "unknown", "unverified"},
		{"custom_opaque", "invalid", "unknown", "unverified"},
		{"spawn_agent", "", "unknown", "unverified"},
		{"exec_command", " SYSTEM ", "system", "configured_mapping"},
	} {
		got, source := ResolveObservedToolType(test.name, test.configured)
		if got != test.want || source != test.source {
			t.Errorf("%s configured %q = %s/%s want %s/%s", test.name, test.configured, got, source, test.want, test.source)
		}
	}
}
