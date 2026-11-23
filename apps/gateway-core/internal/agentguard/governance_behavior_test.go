package agentguard

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func governanceManagedPolicy(action string) *EffectivePolicy {
	return &EffectivePolicy{Mode: ModeStrict, RuleMode: ModeStrict, DefaultAction: DecisionAudit, Rules: []PolicyRule{{
		ID: "policy-center-system_command", ToolPattern: "system.*", Action: DecisionAudit, Enabled: true, PolicyCenterAction: action,
	}}}
}

func TestGovernanceBehaviorRecordAndAlertAllowHaveRealDistinctActions(t *testing.T) {
	risk := Decision{RawDecision: DecisionConfirm, Reason: reasonCommandNotAllowlisted, RiskLevel: "high", Confidence: .75}
	for _, action := range []string{"record", "alert_allow"} {
		t.Run(action, func(t *testing.T) {
			got := ApplyEffectivePolicy(risk, PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Policy: governanceManagedPolicy(action), CallerMode: ModeStrict})
			if got.EffectiveDecision != DecisionAudit || got.NotificationRequired != (action == "alert_allow") {
				t.Fatalf("decision=%+v", got)
			}
			for _, mode := range []Mode{ModeAudit, ModeObserve} {
				got = ApplyEffectivePolicy(risk, PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Policy: governanceManagedPolicy(action), CallerMode: mode})
				if got.NotificationRequired || got.EffectiveDecision != DecisionAudit {
					t.Fatalf("record ceiling failed: %+v", got)
				}
			}
		})
	}
	normal := ApplyEffectivePolicy(Decision{RawDecision: DecisionAllow, Reason: reasonCommandAllowed, RiskLevel: "low"}, PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Policy: governanceManagedPolicy("alert_allow"), CallerMode: ModeStrict})
	if normal.NotificationRequired {
		t.Fatal("normal tool operation generated risk alert")
	}
}

// 托管卡片的“仅记录/告警放行”覆盖不了管理员配成阻断的防护项、受限文件与 Skill 隔离
// （2.9.22 起这些都是配置结论，取严合并；默认配置的防护项只告警，见末尾）。
func TestGovernanceBehaviorManagedRecordDoesNotOverrideConfiguredProtection(t *testing.T) {
	restricted := protectionFinding(restrictedFileReason, "/srv/key.pem", "high", nil)
	restricted.RestrictedFileMatched = true
	secret := protectionFinding(reasonHighConfidenceSecretOut, "https://upload.example.net", "critical", nil)
	for _, raw := range []Decision{
		secret,
		restricted,
		{RawDecision: DecisionBlock, Reason: reasonSkillVersionRevoked, ConfiguredEnforcement: true, RiskLevel: "critical"},
	} {
		for _, action := range []string{"record", "alert_allow"} {
			policy := governanceManagedPolicy(action)
			policy.Protections = protection.Settings{"agent.secret_egress": {Action: protection.ActionBlock}}
			policy.RestrictedFiles = &RestrictedFilePolicy{Patterns: []string{"*.pem"}, Action: "block"}
			got := ApplyEffectivePolicy(raw, PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Policy: policy, CallerMode: ModeStrict})
			if got.EffectiveDecision != DecisionBlock {
				t.Fatalf("configured block lost with %s: %+v", action, got)
			}
		}
	}
	for _, action := range []string{"record", "alert_allow"} {
		got := ApplyEffectivePolicy(secret, PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Policy: governanceManagedPolicy(action), CallerMode: ModeStrict})
		if got.EffectiveDecision != DecisionAudit || !got.NotificationRequired {
			t.Fatalf("default secret_egress setting must alert and allow with %s: %+v", action, got)
		}
	}
}

func TestGovernanceBehaviorBroadExplicitCategoryBlockRemainsBroad(t *testing.T) {
	policy := governanceManagedPolicy("block")
	policy.Rules[0].Action = DecisionBlock
	got := ApplyEffectivePolicy(Decision{RawDecision: DecisionAllow, RiskLevel: "low"}, PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Policy: policy, CallerMode: ModeStrict})
	if got.EffectiveDecision != DecisionBlock {
		t.Fatalf("existing broad policy silently relaxed: %+v", got)
	}
}

func TestGovernanceBehaviorMetadataRoundTripsAndLegacyRulesRemainCompatible(t *testing.T) {
	for _, raw := range []string{`{"id":"legacy","tool_pattern":"system.*","action":"audit"}`, `{"id":"policy-center-system_command","tool_pattern":"system.*","action":"audit","policy_center_action":"alert_allow"}`} {
		var rule PolicyRule
		if err := json.Unmarshal([]byte(raw), &rule); err != nil {
			t.Fatal(err)
		}
		if !rule.Enabled {
			t.Fatal("legacy missing enabled became disabled")
		}
		if rule.ID == "policy-center-system_command" && rule.PolicyCenterAction != "alert_allow" {
			t.Fatalf("metadata lost: %+v", rule)
		}
	}
}
