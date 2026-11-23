package agentguard

import (
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func TestStrictModeExplicitConfirmWithoutChannelFailsClosed(t *testing.T) {
	raw := Decision{
		RawDecision: DecisionConfirm,
		Reason:      "untrusted_source_sensitive_target",
	}

	// 2.9.22：需要确认但无确认通道按 agent.confirm_without_channel 处理，配成阻断才 fail-closed。
	decision := ApplyPolicy(raw, PolicyContext{
		Mode:                  ModeStrict,
		ConfirmChannelEnabled: false,
		ExplicitConfirm:       true,
		PolicyVersion:         "v1",
		TraceID:               "trace-1",
		ConfirmFallback:       protection.ActionBlock,
	})

	if decision.RawDecision != DecisionConfirm {
		t.Fatalf("raw decision changed: got %q", decision.RawDecision)
	}
	if decision.EffectiveDecision != DecisionBlock {
		t.Fatalf("strict confirm without channel should block, got %q", decision.EffectiveDecision)
	}
	if decision.EffectiveReason != "confirm_without_channel_fail_closed" {
		t.Fatalf("unexpected effective reason: %q", decision.EffectiveReason)
	}
	if decision.PolicyVersion != "v1" || decision.TraceID != "trace-1" {
		t.Fatalf("policy metadata was not propagated: %#v", decision)
	}

	// 默认（告警放行）：不拦，记审计并要求通知；仅记录：不拦也不通知。
	byDefault := ApplyPolicy(raw, PolicyContext{Mode: ModeStrict, ExplicitConfirm: true})
	if byDefault.EffectiveDecision != DecisionAudit || !byDefault.NotificationRequired || byDefault.EffectiveReason != effectiveReasonConfirmFallbackAudit {
		t.Fatalf("default fallback must alert and allow, got %#v", byDefault)
	}
	recorded := ApplyPolicy(raw, PolicyContext{Mode: ModeStrict, ExplicitConfirm: true, ConfirmFallback: protection.ActionRecord})
	if recorded.EffectiveDecision != DecisionAudit || recorded.NotificationRequired {
		t.Fatalf("record fallback must only record, got %#v", recorded)
	}
}

func TestAuditModeConfirmRecordsWouldConfirm(t *testing.T) {
	raw := Decision{
		RawDecision: DecisionConfirm,
		Reason:      "untrusted_source_sensitive_target",
	}

	decision := ApplyPolicy(raw, PolicyContext{Mode: ModeAudit})

	if decision.RawDecision != DecisionConfirm {
		t.Fatalf("raw decision changed: got %q", decision.RawDecision)
	}
	if decision.EffectiveDecision != DecisionAudit {
		t.Fatalf("audit mode confirm should audit, got %q", decision.EffectiveDecision)
	}
	if decision.EffectiveReason != "would-confirm" {
		t.Fatalf("unexpected effective reason: %q", decision.EffectiveReason)
	}
}

func TestExplicitAllowOverridesAnalyzerDefault(t *testing.T) {
	raw := Decision{
		RawDecision: DecisionBlock,
		Reason:      "analyzer_default",
	}

	decision := ApplyPolicy(raw, PolicyContext{
		Mode:          ModeStrict,
		ExplicitAllow: true,
	})

	if decision.EffectiveDecision != DecisionAllow {
		t.Fatalf("explicit allow should override analyzer default, got %q", decision.EffectiveDecision)
	}
	if decision.EffectiveReason != "explicit_allow" {
		t.Fatalf("unexpected effective reason: %q", decision.EffectiveReason)
	}
}

func TestObserveModeRecordsWouldBlock(t *testing.T) {
	raw := Decision{
		RawDecision: DecisionBlock,
		Reason:      "destructive_tool",
	}

	decision := ApplyPolicy(raw, PolicyContext{Mode: ModeObserve})

	if decision.EffectiveDecision != DecisionAudit {
		t.Fatalf("observe mode should not enforce analyzer block, got %q", decision.EffectiveDecision)
	}
	if decision.EffectiveReason != "would-block" {
		t.Fatalf("unexpected effective reason: %q", decision.EffectiveReason)
	}
}

// An analyzer's own confirm has no console rule behind it: it must be
// recorded as an alert, never enforced, while RawDecision keeps the judgment.
// W5 5.6 (D3): a block-level verdict is enforced in protect mode instead, see
// TestWS5StrictModeAnalyzerHighRiskFollowsSetting.
func TestStrictModeUnconfiguredAnalyzerVerdictIsAlertOnly(t *testing.T) {
	for _, raw := range []DecisionAction{DecisionConfirm} {
		for _, channel := range []bool{false, true} {
			decision := ApplyPolicy(Decision{RawDecision: raw, Reason: "untrusted_source_sensitive_target"}, PolicyContext{
				Mode:                  ModeStrict,
				ConfirmChannelEnabled: channel,
			})
			if decision.RawDecision != raw {
				t.Fatalf("raw decision changed: got %q want %q", decision.RawDecision, raw)
			}
			if decision.EffectiveDecision != DecisionAudit || decision.EffectiveReason != effectiveReasonAnalyzerAlertOnly {
				t.Fatalf("raw %q channel %t must be alert-only, got %q/%q", raw, channel, decision.EffectiveDecision, decision.EffectiveReason)
			}
		}
	}
}

func TestStrictModeConfiguredAnalyzerVerdictIsEnforced(t *testing.T) {
	decision := ApplyPolicy(Decision{RawDecision: DecisionBlock, ConfiguredEnforcement: true}, PolicyContext{Mode: ModeStrict})
	if decision.EffectiveDecision != DecisionBlock {
		t.Fatalf("a verdict carrying a configured action must be enforced, got %#v", decision)
	}
}

func TestStrictModeConfiguredDefaultActionIsEnforced(t *testing.T) {
	decision := ApplyPolicy(Decision{}, PolicyContext{Mode: ModeStrict, GlobalDefault: DecisionBlock})
	if decision.EffectiveDecision != DecisionBlock {
		t.Fatalf("the policy's configured default action must be enforced, got %#v", decision)
	}
}

// 2.9.22：没有准入底线。配成确认的防护项不被显式放行覆盖；没有确认通道时按
// agent.confirm_without_channel 处理（配成阻断才拦，默认告警放行）。管理员的隔离
// 是配置的阻断，显式放行同样覆盖不了。
func TestConfiguredConfirmAndQuarantineOverrideExplicitAllow(t *testing.T) {
	policy := &EffectivePolicy{Protections: protection.Settings{"skill.admission_unavailable": {Action: protection.ActionConfirm}}}
	raw := resolveProtectionHits(protectionFinding(reasonSkillAdmissionUnavail, "", "high", nil), policy)
	decision := ApplyPolicy(raw, PolicyContext{Mode: ModeStrict, ExplicitAllow: true, ConfirmFallback: protection.ActionBlock})
	if decision.EffectiveDecision != DecisionBlock || decision.EffectiveReason != effectiveReasonConfirmFailClosed {
		t.Fatalf("a configured confirmation must fail closed when confirm_without_channel=block, got %#v", decision)
	}
	byDefault := ApplyPolicy(raw, PolicyContext{Mode: ModeStrict, ExplicitAllow: true})
	if byDefault.EffectiveDecision != DecisionAudit || !byDefault.NotificationRequired {
		t.Fatalf("without a channel the default fallback alerts and allows, got %#v", byDefault)
	}
	configured := ApplyPolicy(Decision{RawDecision: DecisionBlock, Reason: reasonSkillVersionQuarantined, ConfiguredEnforcement: true}, PolicyContext{Mode: ModeStrict, ExplicitAllow: true, ConfirmChannelEnabled: true})
	if configured.EffectiveDecision != DecisionBlock {
		t.Fatalf("an administrator's quarantine is not loosened by an explicit allow, got %#v", configured)
	}
}
