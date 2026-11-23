package handler

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// 热修复：写 tool_attempt_blocked 事件时 finding 的置信度必须取决策本身的置信度，
// 不能是零值。零置信度的 finding 会被告警桥的置信度闸当成低信号压掉。
func TestToolAttemptBlockedFindingCarriesDecisionConfidence(t *testing.T) {
	h, audit, _ := governanceRuntimeHandler(t, "block", "", false)
	var findings []SecurityFinding
	audit.OnSecurityEvent = func(action string, fs []SecurityFinding) {
		for _, f := range fs {
			if f.Type == "tool_attempt_blocked" {
				findings = append(findings, f)
			}
		}
	}
	decision, err := h.applyAgentGuardToolDecisionResult(context.Background(), governanceEnvelope(), governanceCall(), nil, &AuditResult{}, 0)
	if err == nil || decision.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("scenario must block: %+v err=%v", decision, err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one tool_attempt_blocked finding, got %+v", findings)
	}
	if decision.Confidence <= 0 {
		t.Fatalf("scenario must carry a positive decision confidence to be meaningful: %+v", decision)
	}
	if findings[0].Confidence != decision.Confidence {
		t.Fatalf("finding confidence=%v, want decision confidence %v (zero confidence gets the alert suppressed)", findings[0].Confidence, decision.Confidence)
	}
}
