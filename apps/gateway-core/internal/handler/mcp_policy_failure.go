package handler

import (
	"os"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

func (c *ToolRiskClient) markMCPPolicyUnavailable(policy *MCPEffectivePolicy) *MCPEffectivePolicy {
	copied := cloneMCPEffectivePolicy(policy)
	// 按调用读取：控制台的 mcp_policy_fail_mode 优先，没存时用 MCP_POLICY_FAIL_MODE 初值（2.9.22）。
	failMode := normalizeMCPPolicyFailMode(os.Getenv("MCP_POLICY_FAIL_MODE"))
	if c != nil {
		failMode = c.currentMCPPolicyFailMode()
	}
	copied.policyUnavailable = true
	copied.policyFailClosed = failMode == "closed"
	return copied
}

func applyMCPPolicyFailureDecision(policy *MCPEffectivePolicy, decision agentguard.Decision, mode agentguard.Mode) agentguard.Decision {
	if policy == nil || !policy.policyUnavailable {
		return decision
	}
	outcome := securityexit.DecideWithPolicy(securityexit.ModeFromAuditOnly(mode != agentguard.ModeStrict), "block", securityexit.DetectionFailure,
		securityexit.Policy{FailClosedOnDetectionFailure: policy.policyFailClosed})
	if outcome.Gap {
		decision.Evidence = append(decision.Evidence, agentguard.Evidence{
			RuleID: mcpPolicyUnavailableReason, Category: "coverage_gap", SourceField: "mcp_policy",
		})
	}
	if outcome.Enforce {
		decision.RawDecision = agentguard.DecisionBlock
		decision.EffectiveDecision = agentguard.DecisionBlock
		decision.ConfiguredEnforcement = true
		decision.Reason = mcpPolicyUnavailableReason
		decision.EffectiveReason = "policy_fail_closed"
		decision.Mode = mode
		decision.RiskLevel = "high"
	}
	return decision
}

// mcpPolicyGapReleased 标出“MCP 策略读取失败、按 mcp_policy_fail_mode=open 放行”的决策：
// 有覆盖缺口证据但没被拦（2.9.22 审查第 3 项，用来记一条运行告警）。
func mcpPolicyGapReleased(decision agentguard.Decision) bool {
	if decision.EffectiveDecision == agentguard.DecisionBlock || decision.EffectiveDecision == agentguard.DecisionConfirm {
		return false
	}
	for _, evidence := range decision.Evidence {
		if evidence.RuleID == mcpPolicyUnavailableReason && evidence.Category == "coverage_gap" {
			return true
		}
	}
	return false
}
