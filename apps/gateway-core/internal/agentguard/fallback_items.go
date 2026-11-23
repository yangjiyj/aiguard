package agentguard

import "github.com/yangjiyj/aiguard/packages/shared-go/protection"

const protectionKeyBurst = protection.KeyBurst

// behaviorVerdictItems 是“行为结论”类防护项：配成确认或阻断时按管理员配置的分析器结论
// 处理（2.9.21 语义：非托管的显式规则胜过它，托管卡片不参与匹配），不作为更宽规则放不开
// 的下限。其余防护项的确认/阻断都是下限。
var behaviorVerdictItems = map[string]bool{protectionKeyBurst: true}

// protectionFloor 是防护项结论里作为下限的确认/阻断：已定动作的命中里，行为结论类以外
// 动作最严的那条。没有命中明细的结论（手工合并的结论）按摘要字段取。
func protectionFloor(decision Decision) DecisionAction {
	if len(decision.ProtectionHits) == 0 {
		if behaviorVerdictItems[decision.ProtectionItem] {
			return DecisionAllow
		}
		return protectionEnforcement(decision)
	}
	floor := DecisionAllow
	for _, hit := range decision.ProtectionHits {
		item, ok := protection.ItemForReason(hit.Reason)
		if hit.Action == "" || !ok || behaviorVerdictItems[item.Key] {
			continue
		}
		if action := protectionEnforcement(Decision{ProtectionAction: hit.Action}); decisionRank(action) > decisionRank(floor) {
			floor = action
		}
	}
	return floor
}

// behaviorVerdictConfigured 表示决定结论的是配成确认或阻断的行为结论类防护项：这类结论与
// 2.9.21 的配置行为结论一样，托管卡片不参与匹配。
func behaviorVerdictConfigured(resolved Decision) bool {
	return behaviorVerdictItems[resolved.ProtectionItem] && protectionEnforcement(resolved) != DecisionAllow
}

// legacyBurstAliasKinds 是 2.9.21 各突发原因码对应的调用类别。
var legacyBurstAliasKinds = map[string]BehaviorKind{
	"behavior_file_read_burst":       BehaviorFileRead,
	"behavior_file_delete_burst":     BehaviorFileDelete,
	"behavior_network_egress_burst":  BehaviorNetworkEgress,
	"behavior_command_execute_burst": BehaviorCommandExecute,
}

// legacyAliasCoversHit 判断旧原因码例外是否覆盖这条命中：旧突发原因码只放开同一调用类别的突发，
// 其他旧码别名不再细分。
func legacyAliasCoversHit(ruleID string, hit ProtectionHit) bool {
	if kind, ok := legacyBurstAliasKinds[ruleID]; ok {
		return hit.Subtype == string(kind)
	}
	return true
}

// DecidingProtectionItem 是决定这次处置的防护项键（写进拦截记录供控制台定位）：阶段项按处置
// 原因认；处置原因是防护项时取命中里动作最严的那一项；显式规则、默认动作、Skill 隔离/撤销
// 决定的处置不归防护项。其余（行为结论类防护项的确认/阻断、告警放行）在防护项的动作与生效
// 结论一致时归它。都不是时为空。
func DecidingProtectionItem(decision Decision) string {
	cause := decision.EffectiveReason
	if cause == effectiveReasonStrictConfirm || cause == "" {
		cause = decision.PolicyReason
	}
	switch cause {
	case effectiveReasonAnalyzerHighRisk:
		return protectionKeyHighRiskWithoutRule
	case effectiveReasonConfirmFailClosed, effectiveReasonConfirmFallbackAudit:
		return protectionKeyConfirmWithoutChannel
	case effectiveReasonProtectionItem:
		return decision.ProtectionItem
	case effectiveReasonExplicitBlock, effectiveReasonExplicitConfirm, effectiveReasonExplicitAudit, effectiveReasonExplicitAllow,
		effectiveReasonGlobalDefault, effectiveReasonSkillAdministrator:
		return ""
	}
	if enforcement := protectionEnforcement(decision); enforcement != DecisionAllow && enforcement == decision.EffectiveDecision {
		return decision.ProtectionItem
	}
	if decision.EffectiveDecision == DecisionAudit && decision.ProtectionAlert() {
		return decision.ProtectionItem
	}
	return ""
}
