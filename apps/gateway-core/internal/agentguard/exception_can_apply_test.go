package agentguard

import (
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 2.9.22 起没有“网关忽略例外”的底线：原来 ExceptionCanApply 对底线返回 false，
// 现在指向某一防护项（原因码或项键）的例外总能放开该项，其他结论照旧按通用例外处理。
func TestProtectionExceptionsApplyToTheItemTheyName(t *testing.T) {
	restricted := protectionFinding(restrictedFileReason, "/vault/guarded.pdf", "high", nil)
	restricted.RestrictedFileMatched = true
	cases := []struct {
		name     string
		raw      Decision
		settings protection.Settings
		ruleID   string
	}{
		{"ordinary high risk", Decision{RawDecision: DecisionBlock, Reason: "tainted_irreversible_network_egress", RiskLevel: "high"},
			protection.Settings{"agent.high_risk_without_rule": {Action: protection.ActionBlock}}, "tainted_irreversible_network_egress"},
		{"loopback protection item", protectionFinding(targetReasonLoopbackOrPrivate, "http://127.0.0.1/admin", "high", nil),
			protection.Settings{"agent.private_network": {Action: protection.ActionBlock}}, targetReasonLoopbackOrPrivate},
		{"loopback by item key", protectionFinding(targetReasonLoopbackOrPrivate, "http://127.0.0.1/admin", "high", nil),
			protection.Settings{"agent.private_network": {Action: protection.ActionBlock}}, "agent.private_network"},
		{"restricted file", restricted, nil, restrictedFileReason},
		{"skill admission unavailable", protectionFinding(reasonSkillAdmissionUnavail, "", "high", nil),
			protection.Settings{"skill.admission_unavailable": {Action: protection.ActionBlock}}, reasonSkillAdmissionUnavail},
	}
	for _, tc := range cases {
		policy := &EffectivePolicy{Mode: ModeStrict, Protections: tc.settings,
			RestrictedFiles: &RestrictedFilePolicy{Patterns: []string{"*.pdf"}, Action: "block"}}
		input := PolicyEvaluationInput{ToolName: "fetch", ToolType: "network", Policy: policy, CallerMode: ModeStrict}
		if got := ApplyEffectivePolicy(tc.raw, input); got.EffectiveDecision != DecisionBlock {
			t.Fatalf("%s: precondition, configured block must block: %+v", tc.name, got)
		}
		policy.Exceptions = []PolicyException{{ID: "e", RuleID: tc.ruleID, Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}}
		if got := ApplyEffectivePolicy(tc.raw, input); got.EffectiveDecision != DecisionAudit {
			t.Errorf("%s: an exception naming it must apply, got %+v", tc.name, got)
		}
	}
	// 只审计的命中本来就不拦，例外照样可套用。
	audit := ApplyEffectivePolicy(protectionFinding(targetReasonLoopbackOrPrivate, "", "high", nil), PolicyEvaluationInput{
		ToolName: "fetch", ToolType: "network", CallerMode: ModeStrict,
		Policy: &EffectivePolicy{Mode: ModeStrict, Exceptions: []PolicyException{{ID: "e", RuleID: targetReasonLoopbackOrPrivate, Decision: DecisionAllow, ExpiresAt: time.Now().Add(time.Hour)}}},
	})
	if audit.EffectiveDecision == DecisionBlock || audit.NotificationRequired || len(audit.ProtectionExceptionIDs()) != 1 {
		t.Fatalf("audit only: an allow exception must silence the alert, got %+v", audit)
	}
}
