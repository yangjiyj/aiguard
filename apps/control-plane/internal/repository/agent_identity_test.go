package repository

import "testing"

func TestIdentityRegistrationRequiresBoundedEvidence(t *testing.T) {
	for _, tc := range []struct {
		a               AgentIdentityRecord
		scope           string
		dedicated, want bool
	}{
		{AgentIdentityRecord{SourceIP: "192.0.2.1"}, "fingerprint", false, false},
		{AgentIdentityRecord{ClientID: "shared"}, "fingerprint", false, false},
		{AgentIdentityRecord{ClientID: "shared", DeclaredType: "agent-tool-call"}, "fingerprint", false, false},
		{AgentIdentityRecord{ClientID: "shared", DeclaredType: "custom", Source: "content"}, "fingerprint", false, false},
		{AgentIdentityRecord{ClientID: "shared", DeclaredType: "cpu-perf", Source: "explicit_header"}, "fingerprint", false, true},
		{AgentIdentityRecord{ClientID: "shared", UserAgent: "client/1"}, "fingerprint", false, true},
		{AgentIdentityRecord{ClientID: "shared"}, "dedicated_key", false, false},
		{AgentIdentityRecord{ClientID: "dedicated"}, "dedicated_key", true, true},
		{AgentIdentityRecord{}, "dedicated_key", true, false},
		{AgentIdentityRecord{}, "request", false, true},
	} {
		if got := ValidIdentityScope(tc.a, tc.scope, tc.dedicated); got != tc.want {
			t.Fatalf("%+v: got %v", tc, got)
		}
	}
}
