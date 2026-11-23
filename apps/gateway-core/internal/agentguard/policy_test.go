package agentguard

import (
	"testing"
	"time"
)

func TestEffectivePolicyExplicitBlockOverridesAllow(t *testing.T) {
	policy := &EffectivePolicy{
		ID:            "agp_1",
		Name:          "生产严格策略",
		PolicyVersion: "v1",
		Mode:          ModeStrict,
		DefaultAction: DecisionAudit,
		Rules: []PolicyRule{
			{ID: "allow-read", ToolPattern: "file.*", Action: DecisionAllow, Enabled: true},
			{ID: "block-upload", ToolPattern: "network.upload", Action: DecisionBlock, Enabled: true},
		},
	}
	decision := ApplyEffectivePolicy(Decision{RawDecision: DecisionAllow}, PolicyEvaluationInput{
		ToolName: "network.upload",
		Target:   "https://example.com/upload",
		Policy:   policy,
	})
	if decision.EffectiveDecision != DecisionBlock || decision.MatchedPolicyID != "agp_1" {
		t.Fatalf("explicit block should win, got %#v", decision)
	}
}

func TestEffectivePolicyScopedExceptionDowngrades(t *testing.T) {
	policy := &EffectivePolicy{
		ID:            "agp_1",
		PolicyVersion: "v1",
		Mode:          ModeStrict,
		Exceptions: []PolicyException{
			{ID: "ex_1", RuleID: "secret_high_confidence", TargetPattern: "partner.example.com", Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)},
		},
	}
	decision := ApplyEffectivePolicy(Decision{RawDecision: DecisionBlock, Reason: "secret_high_confidence", Evidence: []Evidence{{RuleID: "secret_high_confidence"}}}, PolicyEvaluationInput{
		ToolName: "network.upload",
		Target:   "https://partner.example.com/upload",
		Policy:   policy,
	})
	if decision.EffectiveDecision != DecisionAudit || decision.EffectiveReason != "exception_downgrade" {
		t.Fatalf("exception should downgrade decision, got %#v", decision)
	}
}

func TestEffectivePolicyConfirmChannelKeepsConfirm(t *testing.T) {
	policy := &EffectivePolicy{
		ID:                    "agp_1",
		PolicyVersion:         "v1",
		Mode:                  ModeStrict,
		ConfirmChannelEnabled: true,
		Rules: []PolicyRule{{
			ID: "confirm-upload", ToolPattern: "network.*", Action: DecisionConfirm, Enabled: true,
		}},
	}
	decision := ApplyEffectivePolicy(Decision{RawDecision: DecisionConfirm}, PolicyEvaluationInput{
		ToolName: "network.upload",
		ToolType: "network",
		Target:   "https://example.com/upload",
		Policy:   policy,
	})
	if decision.EffectiveDecision != DecisionConfirm || decision.EffectiveReason != "confirm_channel_available" {
		t.Fatalf("confirm channel should keep confirm, got %#v", decision)
	}
}

func TestAuditOnlyClampsDestructiveCategoryPolicy(t *testing.T) {
	policy := &EffectivePolicy{
		ID:            "agp_destructive",
		PolicyVersion: "v1",
		Mode:          ModeStrict,
		DefaultAction: DecisionAudit,
		Destructive:   &DestructivePolicy{Action: DestructiveActionBlock},
		ConfigSource:  ConfigSourceTenantPolicy,
		Rules: []PolicyRule{{
			ID:          "block-destructive",
			ToolPattern: "destructive_change.*",
			Action:      DecisionBlock,
			Enabled:     true,
		}},
	}
	decision := ApplyEffectivePolicy(Decision{RawDecision: DecisionConfirm}, PolicyEvaluationInput{
		ToolName: "shell", ToolType: "system", Target: "/srv/data",
		RiskCategory: DestructiveRiskCategory, HighConfidence: true,
		Policy: policy, CallerMode: ModeAudit,
	})
	if decision.EffectiveDecision != DecisionAudit || decision.FinalAction != DestructiveActionRecord {
		t.Fatalf("global audit-only (观察留痕) is the ceiling for destructive policies too, got %#v", decision)
	}
	if decision.CustomAction != DestructiveActionBlock || decision.EffectiveReason != DestructiveEffectiveReasonGlobalAuditOnly {
		t.Fatalf("the record must keep the configured block and the reason it was not enforced, got %#v", decision)
	}
}

// Policy-center AgentGuard rules carry no console mode: a rule saved as block
// must block under the protect posture even when the delivered policy mode is
// the destructive policy's "audit".
func TestRuleModeLetsExplicitBlockEnforceUnderProtect(t *testing.T) {
	policy := &EffectivePolicy{
		ID: "policy-center-system_command", Mode: ModeAudit, RuleMode: ModeStrict,
		Rules: []PolicyRule{{ID: "policy-center-system_command", ToolPattern: "system.*", Action: DecisionBlock, Enabled: true}},
	}
	protect := ApplyEffectivePolicy(Decision{RawDecision: DecisionAllow}, PolicyEvaluationInput{
		ToolName: "shell", ToolType: "system", Policy: policy, CallerMode: ModeStrict,
	})
	if protect.EffectiveDecision != DecisionBlock {
		t.Fatalf("explicit block rule must block in protect mode, got %#v", protect)
	}
	record := ApplyEffectivePolicy(Decision{RawDecision: DecisionAllow}, PolicyEvaluationInput{
		ToolName: "shell", ToolType: "system", Policy: policy, CallerMode: ModeAudit,
	})
	if record.EffectiveDecision != DecisionAudit {
		t.Fatalf("explicit block rule must only record in record mode, got %#v", record)
	}
}
