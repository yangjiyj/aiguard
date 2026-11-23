package agentguard

import (
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func TestHardeningFManagedBehaviorUsesPolicyMarkerForCustomRuleID(t *testing.T) {
	for _, id := range []string{"tenant-network-record", "imported-behavior-42"} {
		for _, action := range []string{"record", "alert_allow"} {
			t.Run(id+"/"+action, func(t *testing.T) {
				policy := &EffectivePolicy{Mode: ModeStrict, Rules: []PolicyRule{{ID: id, ToolPattern: "system.*", Action: DecisionAudit, PolicyCenterAction: action, Enabled: true}}}
				raw := Decision{RawDecision: DecisionConfirm, Reason: reasonCommandNotAllowlisted, RiskLevel: "high"}
				got := ApplyEffectivePolicy(raw, PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Policy: policy, CallerMode: ModeStrict})
				if got.EffectiveDecision != DecisionAudit || got.NotificationRequired != (action == "alert_allow") {
					t.Fatalf("policy marker must carry managed behavior independently of rule id: %+v", got)
				}
			})
		}
	}
	if got := managedBehaviorAction(PolicyRule{ID: "policy-center-system_command", Action: DecisionAudit}); got != "" {
		t.Fatalf("an identifier alone must not mark managed behavior: %q", got)
	}
}

func TestHardeningFEmptyExceptionRuleCannotDowngradeUnrelatedRule(t *testing.T) {
	for _, id := range []string{"", " \t "} {
		t.Run(id, func(t *testing.T) {
			// 2.9.22：高风险结论按 agent.high_risk_without_rule，这里配成阻断来观察例外是否误放。
			policy := &EffectivePolicy{Mode: ModeStrict, Exceptions: []PolicyException{{ID: "invalid-scope", RuleID: id, TargetPattern: "example.test", Decision: DecisionAllow, ExpiresAt: time.Now().Add(time.Hour)}},
				Protections: protection.Settings{"agent.high_risk_without_rule": {Action: protection.ActionBlock}}}
			raw := Decision{RawDecision: DecisionBlock, Reason: "destructive_sql", Evidence: []Evidence{{RuleID: "destructive_sql"}}}
			got := ApplyEffectivePolicy(raw, PolicyEvaluationInput{ToolName: "database.query", ToolType: "database", Target: "example.test", Policy: policy, CallerMode: ModeStrict})
			if got.EffectiveDecision != DecisionBlock {
				t.Fatalf("empty rule id must not grant a wildcard exception: %+v", got)
			}
			policy.Protections = nil
			if byDefault := ApplyEffectivePolicy(raw, PolicyEvaluationInput{ToolName: "database.query", ToolType: "database", Target: "example.test", Policy: policy, CallerMode: ModeStrict}); byDefault.EffectiveDecision != DecisionAudit {
				t.Fatalf("empty rule id must not downgrade the default alert to allow: %+v", byDefault)
			}
		})
	}
}
