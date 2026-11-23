package handler

import "github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"

const toolNamePolicyBlockReason = "tool_name_policy_block"

// A tool mapping can add a named deny, but allow/audit cannot erase a behavior,
// destructive-operation, restricted-file, DLP or supply-chain decision.
func applyConfiguredToolCallPolicy(decision agentguard.Decision, result *ToolCheckResult, mode agentguard.Mode) agentguard.Decision {
	if result == nil || result.Config == nil || !result.Blocked {
		return decision
	}
	decision.Evidence = append(decision.Evidence, agentguard.Evidence{RuleID: result.Config.ID, Category: "tool_name_policy", SourceField: "tool_name"})
	if decision.EffectiveDecision == agentguard.DecisionBlock {
		return decision
	}
	decision.MatchedRuleID = result.Config.ID
	decision.MatchedPolicyID = result.Config.ID
	decision.MatchedPolicyName = "Tool invocation policy"
	decision.ConfiguredEnforcement = true
	decision.EffectiveReason = toolNamePolicyBlockReason
	decision.Mode = mode
	if mode == agentguard.ModeStrict {
		decision.EffectiveDecision = agentguard.DecisionBlock
	} else {
		decision.EffectiveDecision = agentguard.DecisionAudit
		decision.EffectiveReason = "would-block:" + toolNamePolicyBlockReason
	}
	return decision
}
