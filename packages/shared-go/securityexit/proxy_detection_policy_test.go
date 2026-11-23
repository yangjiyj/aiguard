package securityexit

import "testing"

func TestProxyDetectionPolicyUsesExplicitModeAndKeepsIndependentCapacity(t *testing.T) {
	for _, test := range []struct {
		mode   string
		closed bool
	}{
		{"", false}, {"open", false}, {" OPEN ", false}, {"closed", true}, {"close", true}, {"invalid", true},
	} {
		t.Run(test.mode, func(t *testing.T) {
			t.Setenv("PROXY_DETECTION_FAIL_MODE", test.mode)
			t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", "true")
			policy := ProxyDetectionPolicy()
			if policy.FailClosedOnDetectionFailure != test.closed || !policy.FailClosedOnCapacity {
				t.Fatalf("policy=%+v mode=%q", policy, test.mode)
			}
			if outcome := DecideWithPolicy(Record, "block", DetectionFailure, policy); outcome.Enforce || !outcome.Gap {
				t.Fatalf("Record must retain gap and hard lock: %+v", outcome)
			}
		})
	}
}
