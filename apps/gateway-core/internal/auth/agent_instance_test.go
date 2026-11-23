package auth

import "testing"

func TestAgentIdentityUsesCredentialBindingAndRejectsSpoofing(t *testing.T) {
	for _, tc := range []struct {
		name, bound, claimed, want string
		deny                       bool
	}{
		{"bound_only", "agent1", "", "agent1", false},
		{"matching_header", "agent1", "agent1", "agent1", false},
		{"cross_agent_header", "agent1", "agent2", "", true},
		{"malformed_header", "agent1", "agent/2", "", true},
		{"unbound_claim_is_rejected", "", "agent1", "", true},
		{"unbound_malformed_claim_is_rejected", "", "agent/2", "", true},
		{"legacy_key", "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, err := resolveAgentInstanceID(tc.bound, tc.claimed)
			if id != tc.want || (err != nil) != tc.deny {
				t.Fatalf("id=%q err=%v", id, err)
			}
		})
	}
}
