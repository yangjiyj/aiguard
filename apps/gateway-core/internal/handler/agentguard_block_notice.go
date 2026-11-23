package handler

import (
	"context"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

var destructiveSubcategoryLabels = map[string]string{
	"filesystem_delete":          "删除文件",
	"filesystem_overwrite":       "覆盖文件",
	"storage_destroy":            "销毁存储卷或磁盘",
	"block_device_destroy":       "破坏块设备",
	"vcs_destroy":                "丢弃版本库改动",
	"container_destroy":          "删除容器",
	"cluster_destroy":            "删除集群资源",
	"infrastructure_destroy":     "销毁基础设施",
	"cloud_resource_destroy":     "删除云资源",
	"resource_destroy":           "删除资源",
	"database_destroy":           "删除数据库对象",
	"database_unscoped_mutation": "无条件批量修改数据库",
}

var destructiveConfigSourceLabels = map[agentguard.ConfigSource]string{
	agentguard.ConfigSourceTenantPolicy:      "租户策略",
	agentguard.ConfigSourceApplicationPolicy: "应用策略",
	agentguard.ConfigSourceAgentPolicy:       "智能体策略",
	agentguard.ConfigSourceModePreset:        "模式预设",
	agentguard.ConfigSourceSystemDefault:     "系统默认",
}

// agentGuardBlockOperation explains a blocked tool call in console terms: the
// behaviour the administrator configured, and what the call was about to do.
func agentGuardBlockOperation(tc ToolCall, decision agentguard.Decision) blockOperation {
	tool := strings.TrimSpace(tc.Function.Name)
	operation := blockOperation{OperationID: decision.OperationID, ProtectionItem: agentguard.DecidingProtectionItem(decision)}
	switch {
	case restrictedFileBlocked(decision):
		operation.Layer = "restricted_file"
		operation.Reason = "访问了受限文件"
		operation.RuleID = decision.RestrictedFilePattern
		operation.RuleName = "受限文件"
		operation.Basis = "策略中心「智能体行为 → 读取敏感资源 → 额外禁止访问的文件」动作为阻断"
		operation.Detail = joinNoticeParts(tool, decision.NormalizedTarget)
	case !destructiveCardDecided(decision):
		// 防护项下限、通用路径上配置的规则胜出的删除与破坏调用：归因到防护项或那条规则。
		operation.Layer = "agent_tool"
		operation.Detail = joinNoticeParts(tool, decision.NormalizedTarget)
		explainAgentToolOperation(&operation, decision)
	case isDestructiveGateDecision(decision) || decision.RiskCategory == agentguard.DestructiveRiskCategory:
		label := destructiveSubcategoryLabels[decision.RiskSubcategory]
		operation.Layer = "destructive_operation"
		operation.Reason = "模型准备调用删除或破坏性工具"
		if label != "" {
			operation.Reason += "（" + label + "）"
		}
		operation.RuleID = "destructive_operation"
		operation.ManagedBehavior = "destructive_operation"
		operation.RuleName = "删除与破坏"
		operation.Basis = "策略中心「智能体行为 → 删除与破坏」动作为阻断"
		if source := destructiveConfigSourceLabels[decision.ConfigSource]; source != "" {
			operation.Basis += "（" + source + "）"
		}
		if decision.EffectiveReason == protection.CauseConfirmWithoutChannelFailClosed {
			operation.Basis = "删除与破坏策略要求人工确认，当前客户端不支持确认；策略中心 → 智能体行为 → " +
				protectionItemLabel(protection.KeyConfirmWithoutChannel) + " 动作为阻断"
		}
		// 与告警证据同源：子类中文 + 触发段命令骨架（拿不到触发段时写目标数），不再露出 filesystem_delete:1-targets 这类内部码。
		operation.Detail = joinNoticeParts(tool, agentGuardFindingEvidence(decision))
	default:
		operation.Layer = "agent_tool"
		operation.Detail = joinNoticeParts(tool, decision.NormalizedTarget)
		explainAgentToolOperation(&operation, decision)
	}
	return operation
}

// destructiveCardDecided 判断删除与破坏调用的结论是不是卡片自己给出的。先看结论原因：是防护项、
// 配置的规则等（不是 destructive_*、确认无通道兜底阻断，也不是空）时，是下限或通用结论胜出，
// FinalAction 虽然也是阻断/确认，说明不能写成“删除与破坏动作为阻断”。确认无通道兜底阻断时再看
// PolicyReason：要求确认的是防护项或显式规则，同样归因到它。
// 不是删除与破坏的调用也返回 true（交给后面的判断）。
func destructiveCardDecided(decision agentguard.Decision) bool {
	if !isDestructiveGateDecision(decision) && decision.RiskCategory != agentguard.DestructiveRiskCategory {
		return true
	}
	cause := agentGuardBlockCause(decision)
	if cause == protection.CauseConfirmWithoutChannelFailClosed {
		return !confirmRequiredByItemOrRule(decision)
	}
	return cause == "" || strings.HasPrefix(cause, "destructive_")
}

// confirmRequiredByItemOrRule：要求确认的是防护项或显式规则（PolicyReason），不是删除与破坏卡片。
func confirmRequiredByItemOrRule(decision agentguard.Decision) bool {
	return decision.PolicyReason == "protection_item" || strings.HasPrefix(decision.PolicyReason, "explicit_")
}

// agentBehaviorLabels 是策略中心「智能体行为」托管规则（policy-center-<key>）在策略页上的中文名，
// 与控制面 policy_center_agent_behaviors.go 的定义一致。
var agentBehaviorLabels = map[string]string{
	"destructive_operation": "删除与破坏",
	"system_command":        "系统命令",
	"sensitive_resource":    "敏感资源访问",
	"network_egress":        "网络外联",
	"database_change":       "数据库变更",
	"external_tool":         "外部工具（MCP）",
}

// agentGuardBlockCause 是这次阻断/确认的真实原因。防护模式下的人工确认把 EffectiveReason
// 改写成 confirm_channel_available，此时取执行模式改写前的 PolicyReason。
func agentGuardBlockCause(decision agentguard.Decision) string {
	if decision.EffectiveReason == "confirm_channel_available" || decision.EffectiveReason == "" {
		if decision.PolicyReason != "" {
			return decision.PolicyReason
		}
	}
	return decision.EffectiveReason
}

// explainAgentToolOperation 用策略页上能找到的名字写规则名与依据，不外露内部代号。
// 规则命中但动作不是阻断、由防护项配置拦下的调用，不能写成「规则动作为阻断」。
func explainAgentToolOperation(operation *blockOperation, decision agentguard.Decision) {
	cause := agentGuardBlockCause(decision)
	operation.Cause = cause
	operation.RiskReason = decision.Reason
	operation.Reason = "智能体工具调用被行为策略阻断"
	action := decisionActionLabel(decision.EffectiveDecision)
	behavior := ""
	if key, ok := strings.CutPrefix(decision.MatchedRuleID, "policy-center-"); ok {
		behavior = agentBehaviorLabels[key]
		if behavior != "" {
			operation.ManagedBehavior = key
		}
	}
	if cause == protection.CauseAnalyzerHighRisk || cause == "protection_item" {
		// 2.9.22 起网关不再忽略例外：高风险判定可被指向规则/原因码的例外改变，
		// 防护项可被指向该项（原因码或项键）的例外改变。
		eligible := true
		operation.ExceptionEligible = &eligible
	}
	if behavior == "" {
		operation.RuleID = decision.MatchedRuleID
	}
	configured := func() {
		switch {
		case behavior != "":
			operation.RuleName = behavior
			operation.Basis = "策略中心 → 智能体行为 → " + behavior + " 动作为" + action
		case decision.MatchedRuleID != "":
			operation.RuleName = decision.MatchedRuleID
			operation.Basis = "智能体行为高级规则「" + decision.MatchedRuleID + "」动作为" + action
		default:
			operation.RuleName = "智能体行为策略"
			operation.Basis = "智能体行为策略配置的动作为" + action
		}
	}
	switch cause {
	case "protection_item":
		// 只有防护项确实是决定确认/阻断的一方时才写防护项显示名。
		if label := agentguard.ProtectionItemLabel(decision); label != "" {
			operation.RuleID = ""
			operation.RuleName = label
			operation.Reason = "智能体工具调用触及「" + label + "」"
			operation.Basis = "策略中心 → 智能体行为 → " + label + " 动作为" + action
		} else {
			configured()
		}
	case "skill_administrator_action":
		operation.RuleID = ""
		operation.RuleName = "Skill 准入"
		operation.Reason = "调用的 Skill 版本已被管理员隔离或撤销"
		operation.Basis = "Skill 管理中该版本已隔离或已撤销，规则动作覆盖不了"
	case protection.CauseAnalyzerHighRisk:
		label := protectionItemLabel(protection.KeyHighRiskWithoutRule)
		operation.RuleID = ""
		operation.RuleName = label
		operation.Reason = "智能体工具调用被判定为高风险"
		operation.Basis = "策略中心 → 智能体行为 → " + label + " 动作为" + action
	case protection.CauseConfirmWithoutChannelFailClosed:
		fallback := "策略中心 → 智能体行为 → " + protectionItemLabel(protection.KeyConfirmWithoutChannel) + " 动作为阻断"
		if label := agentguard.ProtectionItemLabel(decision); decision.PolicyReason == "protection_item" && label != "" {
			// 要求确认的是防护项：写它的显示名。
			operation.RuleID = ""
			operation.RuleName = label
			operation.Reason = "智能体工具调用触及「" + label + "」，需人工确认，但客户端不支持确认"
			operation.Basis = "策略中心 → 智能体行为 → " + label + " 动作为确认，当前客户端不支持确认；" + fallback
			break
		}
		configured()
		operation.Reason = "需人工确认，但客户端不支持确认"
		operation.Basis = "策略要求人工确认，当前客户端不支持确认；" + fallback
	case "global_default":
		operation.RuleName = "智能体行为默认动作"
		operation.Basis = "智能体行为策略的默认动作为" + action
	default:
		configured()
	}
	if decision.EffectiveDecision == agentguard.DecisionConfirm && !strings.Contains(operation.Reason, "确认") {
		operation.Reason = "智能体工具调用需人工确认"
	}
}

func protectionItemLabel(key string) string {
	if item, ok := protection.Lookup(key); ok {
		return item.Label
	}
	return key
}

func decisionActionLabel(action agentguard.DecisionAction) string {
	switch action {
	case agentguard.DecisionConfirm:
		return "人工确认"
	case agentguard.DecisionBlock:
		return "阻断"
	case agentguard.DecisionAudit:
		return "告警"
	default:
		return string(action)
	}
}

func joinNoticeParts(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " · ")
}

// destructiveBlockNoticeText replaces a withheld destructive tool call. The
// notice comes from the tool_attempt_blocked event persisted for the call, so
// its block and operation numbers are searchable in the console.
func (h *ChatCompletionsHandler) destructiveBlockNoticeText(ctx context.Context, envelope *modelrouter.RequestEnvelope, decision agentguard.Decision) string {
	if !blockRecorded(ctx) {
		return destructiveSafetyMessage(decision)
	}
	return h.securityBlockNotice(ctx, envelope, "").Text
}
