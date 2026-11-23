package handler

import (
	"context"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

const agentGuardHighRiskRecordedReason = "analyzer_high_risk_recorded"
const agentGuardToolRecordedReason = "tool_policy_recorded"

// gateAgentGuardHighRiskExit also clamps configured and floor decisions at the
// final tool exit, since the runtime posture may have changed during analysis.
func (h *ChatCompletionsHandler) gateAgentGuardHighRiskExit(ctx context.Context, decision agentguard.Decision) agentguard.Decision {
	if !securityexit.Blocks(string(decision.EffectiveDecision)) && decision.EffectiveDecision != agentguard.DecisionConfirm {
		return decision
	}
	if securityexit.Decide(h.outputExitMode(ctx), string(agentguard.DecisionBlock), securityexit.ToolPolicy).Enforce {
		return decision
	}
	analyzerHighRisk := agentguard.IsAnalyzerHighRiskBlock(decision)
	decision.EffectiveDecision = agentguard.DecisionAudit
	decision.EffectiveReason = agentGuardToolRecordedReason
	if analyzerHighRisk {
		decision.EffectiveReason = agentGuardHighRiskRecordedReason
	}
	return decision
}
