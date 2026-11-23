package securityexit

import "testing"

func TestDecideWithPolicyContract(t *testing.T) {
	causes := []Cause{RuleHit, ExplicitFileType, ToolPolicy, DetectionFailure, Capacity}
	actions := []string{"", "allow", "audit", "mask", "block", "reply", "deny", "quarantine"}
	for _, mode := range []Mode{Record, Protect} {
		for _, cause := range causes {
			for _, raw := range actions {
				for _, on := range []bool{false, true} {
					got := DecideWithPolicy(mode, raw, cause, Policy{FailClosedOnDetectionFailure: on})
					base := Decide(mode, raw, cause)
					if mode == Protect && on && cause == DetectionFailure {
						if !got.Enforce || !got.Gap || got.Action != "block" {
							t.Errorf("protect+on detection failure must enforce as a gap: %+v", got)
						}
						continue
					}
					if got != base {
						t.Errorf("DecideWithPolicy(%v,%q,%v,on=%v)=%+v differs from Decide %+v", mode, raw, cause, on, got, base)
					}
				}
			}
		}
	}
}

func TestFailClosedNeverEnforcesInRecordMode(t *testing.T) {
	got := DecideWithPolicy(Record, "block", DetectionFailure, Policy{FailClosedOnDetectionFailure: true})
	if got.Enforce || !got.Gap || got.Action != "audit" {
		t.Fatalf("record mode with fail-closed on must forward and record a gap: %+v", got)
	}
}

func TestFailClosedDoesNotCoverCapacity(t *testing.T) {
	got := DecideWithPolicy(Protect, "", Capacity, Policy{FailClosedOnDetectionFailure: true})
	if got.Enforce || !got.Gap {
		t.Fatalf("capacity must stay open even with fail-closed on: %+v", got)
	}
}

func TestZeroPolicyIsDecide(t *testing.T) {
	for _, mode := range []Mode{Record, Protect} {
		if got := DecideWithPolicy(mode, "block", DetectionFailure, Policy{}); got != Decide(mode, "block", DetectionFailure) {
			t.Fatalf("zero policy must equal Decide for mode %v: %+v", mode, got)
		}
	}
}
