package agentguard

import (
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// stageItem 描述一个阶段项（没有原因码的防护项）：它产生的结论怎么认出来，指向它的
// 例外怎么放开它（只把该阶段项换成仅记录，其余结论不变）。
type stageItem struct {
	key     string
	matches func(Decision) bool
	relax   func(*PolicyContext)
}

var stageItems = []stageItem{
	{
		key: protectionKeyHighRiskWithoutRule,
		// 配成确认且有确认通道时 EffectiveReason 是 confirm_channel_available，
		// 原因只在 PolicyReason 上。
		matches: func(d Decision) bool {
			return d.EffectiveReason == effectiveReasonAnalyzerHighRisk || d.PolicyReason == effectiveReasonAnalyzerHighRisk
		},
		relax: func(ctx *PolicyContext) { ctx.HighRiskAction = protectionExceptionAction },
	},
	{
		key:     protectionKeyConfirmWithoutChannel,
		matches: func(d Decision) bool { return d.EffectiveReason == effectiveReasonConfirmFailClosed },
		relax:   func(ctx *PolicyContext) { ctx.ConfirmFallback = protectionExceptionAction },
	},
}

func stageItemFor(ruleID string) (stageItem, bool) {
	ruleID = strings.TrimSpace(ruleID)
	for _, item := range stageItems {
		if item.key == ruleID {
			return item, true
		}
	}
	return stageItem{}, false
}

// configuredStageAction 取租户为阶段项保存的动作；没配或动作不合法时返回空串，
// 由 ApplyPolicy 统一取注册表默认值（默认值只在那一层处理）。
func configuredStageAction(settings protection.Settings, key string) protection.Action {
	setting, ok := settings[key]
	if !ok {
		return ""
	}
	if item, known := protection.Lookup(key); !known || !item.Allows(setting.Action) {
		return ""
	}
	return setting.Action
}

// protectionContextAction 是阶段项默认值的唯一处理点：空值取注册表默认值。
func protectionContextAction(configured protection.Action, key string) protection.Action {
	if configured != "" {
		return configured
	}
	return protection.Settings(nil).ActionFor(key)
}

// markProtectionAlert 落实规则 10：防护项结论为告警放行、生效结论是审计、调用方不是
// 只记录姿态时要求通知。同一次调用里更严的命中（确认、阻断）被显式规则降成放行时，
// 其余告警放行的命中照样要求通知，不被它盖掉；被例外放开的命中动作已不是告警放行。
func markProtectionAlert(decision *Decision, callerMode Mode) {
	if decision.EffectiveDecision != DecisionAudit || callerModeIsRecordOnly(callerMode) {
		return
	}
	if decision.ProtectionAlert() || anyProtectionHitAlerts(decision.ProtectionHits) {
		decision.NotificationRequired = true
	}
}

func anyProtectionHitAlerts(hits []ProtectionHit) bool {
	for _, hit := range hits {
		if protection.Action(hit.Action) == protection.ActionAlertAllow {
			return true
		}
	}
	return false
}
