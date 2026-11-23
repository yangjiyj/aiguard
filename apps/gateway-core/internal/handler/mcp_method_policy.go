package handler

// W1 1.2：tools/call 之外的方法同样进入策略判定。
//   resources/read → 按 uri（target_kind=resource）
//   prompts/get    → 按 prompt 名（target_kind=prompt）
// Unknown methods keep their exact names; known governed methods are canonical.
// 管理员配了 block 才拦；没配就放行 + 记录（总原则，不新增默认拒绝）。
// 协议生命周期方法（initialize/ping/notifications/*）与客户端对服务端请求的响应不判定。

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// mcpPolicyTarget 返回消息的策略目标；judged=false 表示协议生命周期消息，不查策略。
func mcpPolicyTarget(msg mcpRPCMessage) (kind, name string, judged bool) {
	switch canonicalMCPMethod(msg.Method) {
	case "":
		// 客户端对服务端请求（sampling/elicitation/roots）的响应，归 1.8 处理。
		return "", "", false
	case "tools/call":
		return mcpTargetTool, strings.TrimSpace(msg.Params.Name), true
	case "resources/read":
		return mcpTargetResource, msg.Params.URI, true
	case "prompts/get":
		return mcpTargetPrompt, msg.Params.Name, true
	case "initialize", "ping":
		return "", "", false
	}
	if strings.HasPrefix(msg.Method, "notifications/") {
		return "", "", false
	}
	return mcpTargetMethod, msg.Method, true
}

// Known methods use one spelling for parsing, policy lookup, and forwarding.
func canonicalMCPMethod(method string) string {
	switch lower := strings.ToLower(method); lower {
	case "tools/call", "tools/list", "resources/read", "prompts/get", "initialize", "ping":
		return lower
	default:
		return method
	}
}

// mcpTargetAuditName 是非工具目标在审计里的展示名（tool_call_logs.tool_name）。
func mcpTargetAuditName(serverName, kind, name string) string {
	switch kind {
	case mcpTargetResource:
		return serverName + "__resource:" + name
	case mcpTargetPrompt:
		return serverName + "__prompt:" + name
	default:
		return serverName + "__method:" + name
	}
}

// Non-tool targets include tenant policy, supply-chain admission, and argument
// redlines. Confirmation replay is only available for tools/call.
func (h *MCPProxyHandler) decideMCPNonToolTarget(ctx context.Context, envelope *modelrouter.RequestEnvelope, server *mcpServerRoute, msg mcpRPCMessage, kind, name string, callerMode agentguard.Mode) mcpToolCallDecision {
	policy := h.toolRiskClient.GetMCPTargetPolicy(ctx, envelope, server.ID, kind, name)
	if policy.StructuralBlock && kind != mcpTargetTool {
		// 供应链准入按工具建档；非工具目标没有准入记录，「未知工具」类结构阻断不适用。
		// 只保留服务器级的隔离/撤销。
		policy = mcpNonToolStructuralPolicy(policy)
	}
	argsJSON := ""
	switch kind {
	case mcpTargetResource:
		encoded, _ := json.Marshal(map[string]string{"uri": msg.Params.URI})
		argsJSON = string(encoded)
	case mcpTargetPrompt:
		argsJSON = string(msg.Params.Arguments)
	}
	var redlineActions map[string]string
	if len(matchMCPRedlines(argsJSON)) > 0 {
		redlineActions = h.mcpRedlineActions(ctx, envelope.TenantID)
	}
	analysisPolicy, policyErr := h.toolRiskClient.GetAgentGuardPolicy(ctx, envelope)
	decision := synthesizeMCPDecisionForTenant(policy, name, argsJSON, callerMode, false, redlineActions, newMCPTenantContext(server.Name, analysisPolicy))
	if argsJSON != "" {
		var args map[string]interface{}
		if json.Unmarshal([]byte(argsJSON), &args) == nil && args != nil {
			analyzed := h.analyzeMCPCallArguments(ctx, envelope, structuredToolCallInput{
				ToolName: msg.Method, ToolType: agentguard.ToolTypeMCP, Arguments: args,
				RawArguments: argsJSON, Mode: callerMode, Policy: analysisPolicy, ConfirmSupported: false,
				ExceptionScope: mcpExceptionTarget(server.Name, name),
			}, policyErr)
			if analyzed.ConfiguredEnforcement {
				decision = mergeMCPToolDecisions(decision, analyzed)
			} else {
				decision.Evidence = append(decision.Evidence, analyzed.Evidence...)
			}
		}
	}
	decision.TraceID = envelope.TraceID
	decision.OperationID = operationID(destructiveOperationIdentity{
		TenantID: envelope.TenantID, Protocol: "mcp", RequestID: envelope.RequestID,
		OutputItemID: "mcp:" + server.ID, ToolCallID: mcpToolCallID(msg.ID), ToolName: kind + ":" + name,
	})
	return mcpToolCallDecision{
		Message:             msg,
		ToolName:            name,
		TargetKind:          kind,
		Qualified:           mcpTargetAuditName(server.Name, kind, name),
		ArgsJSON:            argsJSON,
		PolicyID:            policy.PolicyID,
		Decision:            decision,
		MCPServerID:         server.ID,
		SupplyChainRevision: policy.SupplyChainRevision,
		ServerRouteHash:     policy.RouteHash,
		OutcomeStatus:       "proposed",
	}
}

// mcpNonToolStructuralPolicy：只保留服务器级 quarantined/revoked 结构阻断，
// 去掉工具级（unknown/removed/tool_*、schema 绑定）原因；其余降为普通策略。
func mcpNonToolStructuralPolicy(policy *MCPEffectivePolicy) *MCPEffectivePolicy {
	serverLevel := false
	var reasons []string
	for i, reason := range policy.SupplyChainReasons {
		switch {
		case strings.HasPrefix(reason, "mcp_server_"), reason == "route_binding_mismatch", reason == "gateway_route_binding_mismatch":
			serverLevel = true
			reasons = append(reasons, reason)
			// 服务被隔离、撤销时紧随其后的是服务自己的原因（如 rug_pull_manifest_changed），一并保留：
			// 系统隔离时按它对应的 mcp.* 项处置。是不是管理员处置看 ServerAdmissionSource（随策略复制）。
			if (reason == "mcp_server_quarantined" || reason == "mcp_server_revoked") && i+1 < len(policy.SupplyChainReasons) &&
				!strings.HasPrefix(policy.SupplyChainReasons[i+1], "mcp_tool_") && !mcpGenericSupplyChainReasons[policy.SupplyChainReasons[i+1]] {
				reasons = append(reasons, policy.SupplyChainReasons[i+1])
			}
		}
	}
	copied := cloneMCPEffectivePolicy(policy)
	if serverLevel {
		copied.SupplyChainReasons = reasons
		return copied
	}
	copied.StructuralBlock = false
	copied.SupplyChainStatus = "not_applicable"
	copied.SupplyChainReasons = nil
	if !copied.Matched {
		copied.Mode, copied.Action = "audit", "audit"
	}
	return copied
}

// synthesizeMCPTargetDecision serves targets without inspectable arguments.
func synthesizeMCPTargetDecision(policy *MCPEffectivePolicy, name string, callerMode agentguard.Mode, confirmSupported bool) agentguard.Decision {
	decision := synthesizeMCPDecisionWithConfirm(policy, name, "", callerMode, confirmSupported)
	return decision
}
