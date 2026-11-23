package agentguard

import "testing"

// W5 5.11: the control plane delivers mode=light; the gateway must keep it as
// light (alert and allow) instead of silently normalizing it to audit.
func TestWS5LightModeIsRecognized(t *testing.T) {
	if normalizeMode(ModeLight) != ModeLight {
		t.Fatalf("light must survive normalization, got %q", normalizeMode(ModeLight))
	}
	decision := ApplyPolicy(Decision{RawDecision: DecisionBlock}, PolicyContext{Mode: ModeLight, ExplicitBlock: true})
	if decision.Mode != ModeLight {
		t.Fatalf("decision must report light mode, got %q", decision.Mode)
	}
	if decision.EffectiveDecision != DecisionAudit {
		t.Fatalf("light alerts and allows, never blocks: got %q", decision.EffectiveDecision)
	}
	// Enforcement order: observe < audit < light < strict.
	if !(modeEnforcementRank(ModeAudit) < modeEnforcementRank(ModeLight) && modeEnforcementRank(ModeLight) < modeEnforcementRank(ModeStrict)) {
		t.Fatalf("light must rank between audit and strict")
	}
	// The audit-only ceiling still wins over a light policy.
	if clampModeToCeiling(ModeLight, ModeAudit) != ModeAudit {
		t.Fatalf("audit ceiling must clamp light")
	}
	if clampModeToCeiling(ModeStrict, ModeLight) != ModeLight {
		t.Fatalf("light ceiling must clamp strict")
	}
}
