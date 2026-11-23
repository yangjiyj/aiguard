package agentguard

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// Hotfix 2.9.11-skill-admission: unverified / unknown admission state and incomplete
// skill identity (e.g. Claude Code Skill tool passes only {skill,args}) are recorded
// (audit) but must never confirm/block a user's skill call. Quarantined and revoked
// skills remain enforceable.
func TestSkillAdmissionUnverifiedAndIncompleteAreRecordOnly(t *testing.T) {
	for _, admission := range []SkillAdmissionStatus{SkillAdmissionUnverified, SkillAdmissionUnknown, SkillAdmissionApproved} {
		for _, complete := range []bool{false, true} {
			if admission == SkillAdmissionApproved && complete {
				continue
			}
			for _, confirm := range []bool{false, true} {
				args := map[string]any{"skill": "pdf"}
				if complete {
					args["version"] = "1"
					args["bundle_hash"] = strings.Repeat("a", 64)
				}
				decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
					ToolName: "use_skill", ToolType: ToolTypeSkill, Arguments: args,
					SkillAdmission: admission, Mode: ModeStrict, ConfirmChannelEnabled: confirm,
				})
				if decision.ConfiguredEnforcement || decision.EffectiveDecision == DecisionBlock || decision.EffectiveDecision == DecisionConfirm {
					t.Fatalf("admission=%s complete=%v confirm=%v must be record-only: %+v", admission, complete, confirm, decision)
				}
			}
		}
	}
}

func TestSkillAdmissionQuarantinedAndRevokedStillEnforce(t *testing.T) {
	args := map[string]any{"skill": "pdf", "version": "1", "bundle_hash": strings.Repeat("a", 64)}
	for _, admission := range []SkillAdmissionStatus{SkillAdmissionQuarantined, SkillAdmissionRevoked} {
		decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
			ToolName: "use_skill", ToolType: ToolTypeSkill, Arguments: args,
			SkillAdmission: admission, Mode: ModeStrict,
		})
		if decision.EffectiveDecision != DecisionBlock {
			t.Fatalf("admission=%s must still block: %+v", admission, decision)
		}
	}
}

// 准入查询本身失败（控制面不可用）是另一回事：它是防护项 skill.admission_unavailable 的命中，
// 不能因为"未验证版本只记录"而一并当成未命中。2.9.22 起没有拦截底线：配成确认时按确认处理
// （无确认通道按 agent.confirm_without_channel，这里配成阻断），默认告警放行。
// Claude Code 这类只带 {skill,args} 的调用不做查询，身份不完整时永远只记录。
func TestSkillAdmissionLookupUnavailableEnforcesWhenConfigured(t *testing.T) {
	args := map[string]any{"skill": "pdf", "version": "1", "bundle_hash": strings.Repeat("a", 64)}
	for _, confirm := range []bool{false, true} {
		decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
			ToolName: "use_skill", ToolType: ToolTypeSkill, Arguments: args,
			SkillAdmission: SkillAdmissionUnavailable, Mode: ModeStrict, ConfirmChannelEnabled: confirm,
			Policy: &EffectivePolicy{Mode: ModeStrict, ConfirmChannelEnabled: confirm, Protections: protection.Settings{
				"skill.admission_unavailable":   {Action: protection.ActionConfirm},
				"agent.confirm_without_channel": {Action: protection.ActionBlock},
			}},
		})
		want := DecisionBlock
		if confirm {
			want = DecisionConfirm
		}
		if decision.EffectiveDecision != want || decision.ProtectionItem != "skill.admission_unavailable" || !decision.ConfiguredEnforcement {
			t.Fatalf("confirm=%v configured lookup failure must be enforced: %+v", confirm, decision)
		}
		byDefault := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
			ToolName: "use_skill", ToolType: ToolTypeSkill, Arguments: args,
			SkillAdmission: SkillAdmissionUnavailable, Mode: ModeStrict, ConfirmChannelEnabled: confirm,
		})
		if byDefault.EffectiveDecision != DecisionAudit || !byDefault.NotificationRequired || byDefault.ProtectionItem != "skill.admission_unavailable" {
			t.Fatalf("confirm=%v default lookup failure must alert and allow: %+v", confirm, byDefault)
		}
	}
	// 身份不完整（Claude Code 的 Skill 工具）即使状态是 unavailable 也只记录。
	decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
		ToolName: "Skill", ToolType: ToolTypeSkill,
		Arguments:      map[string]any{"skill": "npu300-debug", "args": "x"},
		SkillAdmission: SkillAdmissionUnavailable, Mode: ModeStrict, ConfirmChannelEnabled: true,
	})
	if decision.EffectiveDecision == DecisionBlock || decision.EffectiveDecision == DecisionConfirm || decision.ConfiguredEnforcement || len(decision.ProtectionHits) > 0 {
		t.Fatalf("incomplete identity must stay record-only even when lookup is unavailable: %+v", decision)
	}
}
