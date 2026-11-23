package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// 2.9.22 批次 2B：通用结论与破坏性结论的取严从 handler 的 preserveIndependentToolControl
// 移进 ApplyEffectivePolicy 的破坏性分支（PolicyEvaluationInput.General）。两条用例的断言不变，
// 只把被测入口换成 ApplyEffectivePolicy。
func recordingDestructiveWithGeneral(general agentguard.Decision) agentguard.Decision {
	raw := agentguard.Decision{RawDecision: agentguard.DecisionBlock, RiskCategory: agentguard.DestructiveRiskCategory,
		Evidence: []agentguard.Evidence{{RuleID: "destructive_fixture"}}}
	return agentguard.ApplyEffectivePolicy(raw, agentguard.PolicyEvaluationInput{
		ToolName: "Bash", ToolType: "system", CallerMode: agentguard.ModeStrict,
		RiskCategory: agentguard.DestructiveRiskCategory, HighConfidence: true, General: &general,
		Policy: &agentguard.EffectivePolicy{Destructive: &agentguard.DestructivePolicy{Mode: agentguard.ModeAudit, Action: agentguard.DestructiveActionRecord}},
	})
}

// 2.9.22：内网/元数据是防护项，配成阻断时 base 带 ConfiguredEnforcement；删除与破坏的
// “仅记录”抹不掉它。没有配置标记的阻断（原底线）不再保留，见下一个用例。
func TestStructuredToolHardeningRetainsConfiguredNetworkBlock(t *testing.T) {
	for _, reason := range []string{"blocked_loopback_or_private_ip", "blocked_cloud_metadata", "blocked_cloud_metadata_hostname"} {
		base := agentguard.Decision{RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionBlock, Reason: reason,
			ConfiguredEnforcement: true, ProtectionAction: "block"}
		got := recordingDestructiveWithGeneral(base)
		if got.EffectiveDecision != agentguard.DecisionBlock || got.Reason != reason {
			t.Fatalf("destructive record weakened independent network protection: %+v", got)
		}
		if len(got.Evidence) != 1 || got.Evidence[0].RuleID != "destructive_fixture" {
			t.Fatalf("merge lost destructive evidence: %+v", got)
		}
	}
}

func TestStructuredToolHardeningMatchedRuleIDDoesNotGrantEnforcement(t *testing.T) {
	base := agentguard.Decision{RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionBlock, MatchedRuleID: "metadata_only"}
	if got := recordingDestructiveWithGeneral(base); got.EffectiveDecision != agentguard.DecisionAudit {
		t.Fatalf("rule metadata alone was treated as configured enforcement: %+v", got)
	}
}
