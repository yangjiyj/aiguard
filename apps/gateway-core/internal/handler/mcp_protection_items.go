package handler

import (
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpadmission"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// mcpTenantContext 是 MCP 判定要用到的租户配置：防护项动作与例外（取自 AgentGuard 有效策略），
// 以及服务名（例外目标 mcp:<服务名>/<工具名>）。零值即注册表默认、没有例外。
type mcpTenantContext struct {
	ServerName  string
	Protections protection.Settings
	Exceptions  []agentguard.PolicyException
}

func newMCPTenantContext(serverName string, policy *agentguard.EffectivePolicy) mcpTenantContext {
	tenant := mcpTenantContext{ServerName: serverName}
	if policy != nil {
		tenant.Protections, tenant.Exceptions = policy.Protections, policy.Exceptions
	}
	return tenant
}

// mcpExceptionTarget 是 MCP 调用在例外里的目标写法。
func mcpExceptionTarget(serverName, toolName string) string {
	return "mcp:" + strings.TrimSpace(serverName) + "/" + strings.TrimSpace(toolName)
}

// mcpGenericSupplyChainReasons 只说明“服务/工具处于隔离或撤销”，不说明为什么；具体原因紧随其后。
var mcpGenericSupplyChainReasons = map[string]bool{
	"mcp_server_quarantined": true, "mcp_tool_quarantined": true,
	"mcp_server_revoked": true, "mcp_tool_revoked": true,
}

// mcpSupplyChainFindings 把控制面下发的结构性准入结论拆成两类：管理员手动隔离、撤销（照拦，按处置
// 来源判断、不看原因文字，见 mcpAdministratorAdmission），或可配置的 mcp.* 防护项命中。系统隔离的
// 原因没登记时按管理员处置，不比 2.9.21 宽。
func mcpSupplyChainFindings(policy *MCPEffectivePolicy, target string) (adminBlock bool, hits []agentguard.ProtectionHit) {
	if policy == nil || !policy.StructuralBlock {
		return false, nil
	}
	reasons := policy.SupplyChainReasons
	for i, reason := range reasons {
		var status, source string
		switch reason {
		case "mcp_server_revoked", "mcp_server_quarantined":
			status, source = strings.TrimPrefix(reason, "mcp_server_"), policy.ServerAdmissionSource
		case "mcp_tool_revoked", "mcp_tool_quarantined":
			status, source = strings.TrimPrefix(reason, "mcp_tool_"), policy.ToolAdmissionSource
		default:
			continue
		}
		if mcpAdministratorAdmission(status, source) {
			return true, nil
		}
		// 系统隔离：紧随其后的是隔离原因（见控制面 resolveMCPSupplyChainState），没登记就照拦。
		if i+1 >= len(reasons) || mcpGenericSupplyChainReasons[reasons[i+1]] {
			return true, nil
		}
		if _, ok := protection.ItemForReason(reasons[i+1]); !ok {
			return true, nil
		}
	}
	seen := map[string]bool{}
	for _, reason := range reasons {
		if mcpGenericSupplyChainReasons[reason] || seen[reason] {
			continue
		}
		if _, ok := protection.ItemForReason(reason); !ok {
			continue
		}
		seen[reason] = true
		hits = append(hits, agentguard.ProtectionHit{Reason: reason, Target: target, RiskLevel: "high", Confidence: 1})
	}
	if len(hits) == 0 {
		// 结构性结论里没有任何已登记的原因：照 2.9.21 拦。
		return true, nil
	}
	return false, hits
}

// mcpAdministratorAdmission 是网关里唯一判断“管理员手动处置”的地方：撤销一律算，隔离看来源不是系统。
// 调用路径（mcpSupplyChainFindings）和 tools/list（mcpListedDropReasons、judgeMCPListedTool）都用它。
func mcpAdministratorAdmission(status, source string) bool {
	return mcpadmission.AdministratorBlock(status, source)
}

// mcpHitsNeedStrictMode 判断这些命中里是否有配成确认或阻断的项：MCP 策略未命中时模式是
// audit，要像红线阻断那样抬到 strict 才能执行（仍受 callerMode 钳制，记录模式不拦）。
func mcpHitsNeedStrictMode(hits []agentguard.ProtectionHit, settings protection.Settings) bool {
	for _, hit := range hits {
		item, ok := protection.ItemForReason(hit.Reason)
		if !ok {
			continue
		}
		switch settings.ActionFor(item.Key) {
		case protection.ActionBlock, protection.ActionConfirm:
			return true
		}
	}
	return false
}

// mcpReplayDriftTolerable：批准后重放时，只有“环境变化”这一项本身才交给 mcp.replay_changed 处置；
// 管理员手动隔离、撤销不算环境变化，已配置为阻断的结论照拦。
func mcpReplayDriftTolerable(policy *MCPEffectivePolicy, decision agentguard.Decision) bool {
	if adminBlock, _ := mcpSupplyChainFindings(policy, ""); adminBlock {
		return false
	}
	return decision.EffectiveDecision != agentguard.DecisionBlock
}

// mcpFallbackAction 是 MCP 故障类防护项（确认单建不出来、批准后重放时环境变化或策略拉不到）按租户设置
// 定出的动作，与其他防护项同口径套例外：rule_id 指向该项或原因码、目标覆盖 mcp:<服务>/<工具> 的例外把它
// 降为仅记录，返回套用的例外。
func mcpFallbackAction(item protection.Item, reason string, tenant mcpTenantContext, toolName string) (protection.Action, string) {
	target := mcpExceptionTarget(tenant.ServerName, toolName)
	if exc := agentguard.MatchingMCPException(tenant.Exceptions, []string{item.Key, reason}, target, time.Now()); exc != nil {
		return protection.ActionRecord, exc.ID
	}
	return tenant.Protections.ActionFor(item.Key), ""
}

// mcpProtectionFallback 给 MCP 链路上的运行故障（确认单建不出来、批准后重放时环境变化或策略
// 拉不到）按对应 mcp.* 防护项定动作。设为阻断（且没有例外）时返回 enforce=true，调用方照 2.9.21 拦，
// 结论归因到该项；其余把结论降为放行并记一条命中（告警放行时发通知，观察留痕下不发；例外放开时
// 只记录）。
func mcpProtectionFallback(decision agentguard.Decision, reason string, tenant mcpTenantContext, toolName string, auditOnly bool) (agentguard.Decision, bool) {
	item, ok := protection.ItemForReason(reason)
	if !ok {
		return decision, true
	}
	if decision.EffectiveDecision == agentguard.DecisionBlock {
		// 别的结论（管理员配置、AgentGuard 已配置为阻断等）已经要拦：fallback 只管这一项本身，不放开。
		return decision, true
	}
	action, exceptionID := mcpFallbackAction(item, reason, tenant, toolName)
	hit := agentguard.ProtectionHit{Reason: reason, RiskLevel: "high", Confidence: 1, Action: string(action), ExceptionID: exceptionID}
	decision.ProtectionHits = append(decision.ProtectionHits, hit)
	decision.ProtectionItem, decision.ProtectionAction = item.Key, string(action)
	if action == protection.ActionBlock {
		return decision, true
	}
	decision.EffectiveDecision = agentguard.DecisionAudit
	decision.EffectiveReason = reason
	decision.ConfiguredEnforcement = false
	decision.NotificationRequired = action == protection.ActionAlertAllow && !auditOnly
	decision.Evidence = append(decision.Evidence, agentguard.Evidence{RuleID: reason, Category: "mcp_protection_item"})
	return decision, false
}
