package securityexit

import (
	"encoding/json"
	"testing"
)

func TestCapacityPolicyIsIndependentAndRecordLockWins(t *testing.T) {
	for _, test := range []struct {
		name                         string
		mode                         Mode
		cause                        Cause
		detection, capacity, enforce bool
	}{
		{"default", Protect, Capacity, false, false, false},
		{"detection-only", Protect, Capacity, true, false, false},
		{"capacity-only", Protect, Capacity, false, true, true},
		{"both", Protect, Capacity, true, true, true},
		{"record", Record, Capacity, true, true, false},
		{"capacity-does-not-cover-detection", Protect, DetectionFailure, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, _ := json.Marshal(map[string]bool{"FailClosedOnDetectionFailure": test.detection, "FailClosedOnCapacity": test.capacity})
			var policy Policy
			if err := json.Unmarshal(encoded, &policy); err != nil {
				t.Fatal(err)
			}
			got := DecideWithPolicy(test.mode, "", test.cause, policy)
			if got.Enforce != test.enforce || !got.Gap || (test.enforce && got.Action != "block") || (!test.enforce && got.Action != "audit") {
				t.Fatalf("independent capacity decision = %+v, want enforce=%t gap=true", got, test.enforce)
			}
		})
	}
}
