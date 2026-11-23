package agentguard

import (
	"context"
	"testing"
	"time"
)

// 审查意见 2：Skill 防护项的三件套——默认告警放行、配成阻断照拦（见 skill_test.go 已有用例）、
// 加例外放开。

func conflictingSkillCall(policy *EffectivePolicy) ToolCallAnalysisInput {
	return ToolCallAnalysisInput{
		ToolName: "use_skill", ToolType: ToolTypeSkill, Mode: ModeStrict, Policy: policy,
		Arguments: map[string]any{
			"skill": "approved", "version": "1.0.0",
			"bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"input":       map[string]any{"skill": "actual"},
		},
		SkillAdmission: SkillAdmissionApproved,
	}
}

func dangerousSkillCall(policy *EffectivePolicy) ToolCallAnalysisInput {
	return ToolCallAnalysisInput{
		ToolName: "use_skill", ToolType: ToolTypeSkill, Mode: ModeStrict, Policy: policy,
		Arguments: map[string]any{
			"skill": "ops", "version": "1.0.0",
			"bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"input":       map[string]any{"command": "rm -rf /"},
		},
		SkillAdmission: SkillAdmissionApproved,
	}
}

func withSkillException(ruleID string) *EffectivePolicy {
	policy := skillBlockingPolicy()
	policy.Exceptions = []PolicyException{{ID: "e-" + ruleID, RuleID: ruleID, ExpiresAt: time.Now().Add(time.Hour)}}
	return policy
}

func TestSkillIdentityInvalid2922DefaultAlertsAndExceptionReleases(t *testing.T) {
	byDefault := AnalyzeToolCall(context.Background(), conflictingSkillCall(&EffectivePolicy{Mode: ModeStrict}))
	if byDefault.EffectiveDecision != DecisionAudit || !byDefault.NotificationRequired || byDefault.ProtectionItem != "skill.identity_invalid" {
		t.Fatalf("Skill identity issue alerts and allows by default: %+v", byDefault)
	}
	if blocked := AnalyzeToolCall(context.Background(), conflictingSkillCall(skillBlockingPolicy())); blocked.EffectiveDecision != DecisionBlock {
		t.Fatalf("fixture: configured block blocks: %+v", blocked)
	}
	for _, ruleID := range []string{"skill.identity_invalid", "skill_identity_conflict"} {
		got := AnalyzeToolCall(context.Background(), conflictingSkillCall(withSkillException(ruleID)))
		if got.EffectiveDecision == DecisionBlock || len(got.ProtectionExceptionIDs()) != 1 {
			t.Fatalf("an exception naming %s must release it: %+v", ruleID, got)
		}
	}
	other := AnalyzeToolCall(context.Background(), conflictingSkillCall(withSkillException("skill.dangerous_command")))
	if other.EffectiveDecision != DecisionBlock {
		t.Fatalf("an exception for another Skill item must not release the identity issue: %+v", other)
	}
}

func TestSkillDangerousCommand2922ExceptionReleases(t *testing.T) {
	if blocked := AnalyzeToolCall(context.Background(), dangerousSkillCall(skillBlockingPolicy())); blocked.EffectiveDecision != DecisionBlock || blocked.ProtectionItem != "skill.dangerous_command" {
		t.Fatalf("fixture: configured block blocks: %+v", blocked)
	}
	for _, ruleID := range []string{"skill.dangerous_command", "skill_dangerous_command"} {
		got := AnalyzeToolCall(context.Background(), dangerousSkillCall(withSkillException(ruleID)))
		if got.EffectiveDecision == DecisionBlock || len(got.ProtectionExceptionIDs()) != 1 {
			t.Fatalf("an exception naming %s must release it: %+v", ruleID, got)
		}
	}
}
