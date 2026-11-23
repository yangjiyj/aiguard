package securityexit

import "testing"

func TestDecideContract(t *testing.T) {
	causes := []Cause{RuleHit, ExplicitFileType, ToolPolicy, DetectionFailure, Capacity}
	actions := []string{"", "allow", "audit", "alert", "mask", "redact", "block", "reply", "deny", "quarantine", "BLOCK", " deny "}
	for _, mode := range []Mode{Record, Protect} {
		for _, cause := range causes {
			for _, raw := range actions {
				got := Decide(mode, raw, cause)
				failure := cause == DetectionFailure || cause == Capacity
				wantEnforce := mode == Protect && !failure && Blocks(raw)
				if got.Enforce != wantEnforce {
					t.Errorf("Decide(%v,%q,%v).Enforce=%v want %v", mode, raw, cause, got.Enforce, wantEnforce)
				}
				if got.Gap != failure {
					t.Errorf("Decide(%v,%q,%v).Gap=%v want %v", mode, raw, cause, got.Gap, failure)
				}
				if mode == Record && Blocks(got.Action) {
					t.Errorf("record mode recorded blocking action %q for raw %q", got.Action, raw)
				}
				if failure && got.Action != "audit" {
					t.Errorf("detection failure must record audit, got %q", got.Action)
				}
			}
		}
	}
}

func TestBlockingSetIsSingle(t *testing.T) {
	for _, a := range []string{"block", "reply", "deny", "quarantine", "Block", " quarantine "} {
		if !Blocks(a) {
			t.Errorf("%q must block", a)
		}
	}
	for _, a := range []string{"", "allow", "audit", "alert", "mask", "redact", "confirm", "unknown"} {
		if Blocks(a) {
			t.Errorf("%q must not block", a)
		}
	}
}

func TestClampPassesNonBlockingActionsThrough(t *testing.T) {
	if got := Clamp(Record, "mask"); got != "mask" {
		t.Fatalf("mask must pass through, got %q", got)
	}
	if got := Clamp(Record, "block"); got != "audit" {
		t.Fatalf("record block must clamp to audit, got %q", got)
	}
	if got := Clamp(Protect, "block"); got != "block" {
		t.Fatalf("protect block must stay block, got %q", got)
	}
	if ModeFromAuditOnly(true) != Record || ModeFromAuditOnly(false) != Protect {
		t.Fatal("ModeFromAuditOnly mapping broken")
	}
}
