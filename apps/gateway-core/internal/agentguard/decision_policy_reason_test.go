package agentguard

import (
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 防护模式下的人工确认会把 EffectiveReason 改写成 confirm_channel_available，
// 阻断记录因此丢失「为什么要确认」。PolicyReason 保留执行模式改写之前的原因。
func TestStrictConfirmKeepsTheReasonThatRequiredConfirmation(t *testing.T) {
	// 2.9.22：原“准入兜底”改为防护项 skill.admission_unavailable，配成确认时原因是防护项。
	confirmPolicy := &EffectivePolicy{Protections: protection.Settings{"skill.admission_unavailable": {Action: protection.ActionConfirm}}}
	admissionRaw := resolveProtectionHits(protectionFinding(reasonSkillAdmissionUnavail, "", "high", nil), confirmPolicy)
	admission := ApplyPolicy(admissionRaw, PolicyContext{Mode: ModeStrict, ConfirmChannelEnabled: true})
	if admission.EffectiveDecision != DecisionConfirm || admission.EffectiveReason != effectiveReasonStrictConfirm {
		t.Fatalf("precondition: %+v", admission)
	}
	if admission.PolicyReason != effectiveReasonProtectionItem {
		t.Fatalf("防护项触发的确认应保留原因, got %q", admission.PolicyReason)
	}
	explicit := ApplyPolicy(Decision{RawDecision: DecisionAudit}, PolicyContext{Mode: ModeStrict, ConfirmChannelEnabled: true, ExplicitConfirm: true, MatchedRuleID: "policy-center-system_command"})
	if explicit.PolicyReason != effectiveReasonExplicitConfirm {
		t.Fatalf("规则配置的确认应保留原因, got %q", explicit.PolicyReason)
	}
	// 原“安全底线拦截”：现在是防护项配成阻断时的拦截，依据为防护项。
	blockPolicy := &EffectivePolicy{Protections: protection.Settings{"agent.ssh_private_key": {Action: protection.ActionBlock}}}
	floorRaw := resolveProtectionHits(protectionFinding(targetReasonSSHPrivateKey, "~/.ssh/id_rsa", "critical", nil), blockPolicy)
	floor := ApplyPolicy(floorRaw, PolicyContext{Mode: ModeStrict, ExplicitAudit: true})
	if floor.EffectiveDecision != DecisionBlock || floor.EffectiveReason != effectiveReasonProtectionItem || floor.PolicyReason != effectiveReasonProtectionItem {
		t.Fatalf("防护项阻断: %+v", floor)
	}
	// 默认配置（告警放行）下同一输入不拦。
	defaultRaw := resolveProtectionHits(protectionFinding(targetReasonSSHPrivateKey, "~/.ssh/id_rsa", "critical", nil), nil)
	if got := ApplyPolicy(defaultRaw, PolicyContext{Mode: ModeStrict, ExplicitAudit: true}); got.EffectiveDecision != DecisionAudit || !got.ProtectionAlert() {
		t.Fatalf("默认配置应告警放行: %+v", got)
	}
}
