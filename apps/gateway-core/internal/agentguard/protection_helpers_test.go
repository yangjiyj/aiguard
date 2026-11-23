package agentguard

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// blockingProtections 把给定分组里允许阻断的防护项全部配成阻断（2.9.22 起没有内置底线，
// 用例要“照拦”必须显式配置）。
func blockingProtections(groups ...protection.Group) protection.Settings {
	settings := protection.Settings{}
	for _, item := range protection.All() {
		for _, group := range groups {
			if item.Group == group && item.Allows(protection.ActionBlock) {
				settings[item.Key] = protection.Setting{Action: protection.ActionBlock}
			}
		}
	}
	return settings
}

// requireConfiguredBlockDefaultAlert：同一输入在 settings 下被阻断，在默认配置（不下发
// 防护项）下告警放行——生效为审计、要求通知、命中同一防护项。in.Policy 为基础策略
// （为空时用防护模式的空策略），两次分别替换其中的 Protections。
func requireConfiguredBlockDefaultAlert(t *testing.T, label string, in ToolCallAnalysisInput, settings protection.Settings) (blocked, byDefault Decision) {
	t.Helper()
	base := EffectivePolicy{Mode: ModeStrict}
	if in.Policy != nil {
		base = *in.Policy
	}
	configured, plain := base, base
	configured.Protections, plain.Protections = settings, nil
	in.Policy = &configured
	blocked = AnalyzeToolCall(context.Background(), in)
	if blocked.EffectiveDecision != DecisionBlock || blocked.ProtectionItem == "" {
		t.Fatalf("%s: configured protection must block: effective=%s/%s reason=%s item=%q",
			label, blocked.EffectiveDecision, blocked.EffectiveReason, blocked.Reason, blocked.ProtectionItem)
	}
	in.Policy = &plain
	byDefault = AnalyzeToolCall(context.Background(), in)
	if byDefault.EffectiveDecision != DecisionAudit || !byDefault.NotificationRequired || byDefault.ProtectionItem != blocked.ProtectionItem {
		t.Fatalf("%s: default settings must alert and allow on %q: effective=%s/%s notify=%v item=%q",
			label, blocked.ProtectionItem, byDefault.EffectiveDecision, byDefault.EffectiveReason, byDefault.NotificationRequired, byDefault.ProtectionItem)
	}
	return blocked, byDefault
}
