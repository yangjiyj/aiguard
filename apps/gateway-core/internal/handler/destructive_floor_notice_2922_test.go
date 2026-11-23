package handler

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 复审：删除与破坏卡片仅记录、同一调用触及 SSH 私钥（防护项配成阻断）时，是防护项拦下的调用：
// 拦截说明归因到防护项，不写成“删除与破坏动作为阻断”；下限要求确认时工具日志是待确认。
func destructiveFloorDecision2922(t *testing.T, action protection.Action, general *agentguard.Decision) agentguard.Decision {
	t.Helper()
	raw := agentguard.Decision{RawDecision: agentguard.DecisionBlock, Reason: "deterministic_destructive_operation", RiskLevel: "high",
		RiskCategory: agentguard.DestructiveRiskCategory, RiskSubcategory: "filesystem_delete", NormalizedTarget: "~/.ssh/id_rsa",
		OperationID: "op_floor"}
	if action != "" {
		raw.ProtectionHits = []agentguard.ProtectionHit{{Reason: "blocked_ssh_private_key_path", Target: "~/.ssh/id_rsa",
			MatchTarget: "~/.ssh/id_rsa", RiskLevel: "critical", Confidence: 0.95}}
	}
	policy := &agentguard.EffectivePolicy{ID: "p", Mode: agentguard.ModeStrict, ConfirmChannelEnabled: true,
		Destructive: &agentguard.DestructivePolicy{Mode: agentguard.ModeAudit, Action: agentguard.DestructiveActionRecord}}
	if action != "" {
		policy.Protections = protection.Settings{"agent.ssh_private_key": {Action: action}}
	}
	return agentguard.ApplyEffectivePolicy(raw, agentguard.PolicyEvaluationInput{ToolName: "Bash", ToolType: "system",
		Target: "~/.ssh/id_rsa", Policy: policy, CallerMode: agentguard.ModeStrict, RiskCategory: agentguard.DestructiveRiskCategory,
		HighConfidence: true, DestructiveConfirmChannel: true, General: general})
}

func TestDestructiveFloor2922BlockNoticeNamesTheProtectionItem(t *testing.T) {
	decision := destructiveFloorDecision2922(t, protection.ActionBlock, nil)
	if decision.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("fixture: the SSH private key item blocks: %+v", decision)
	}
	operation := agentGuardBlockOperation(ToolCall{Function: ToolCallFunc{Name: "Bash"}}, decision)
	if operation.Layer != "agent_tool" || operation.RuleName != "SSH 私钥" || operation.ProtectionItem != "agent.ssh_private_key" ||
		strings.Contains(operation.Basis, "删除与破坏") || !strings.Contains(operation.Basis, "SSH 私钥") {
		t.Fatalf("the notice must name the protection item, not the recording destructive card: %+v", operation)
	}
}

func TestDestructiveFloor2922ConfirmLogsWaitingConfirmation(t *testing.T) {
	decision := destructiveFloorDecision2922(t, protection.ActionConfirm, nil)
	if decision.EffectiveDecision != agentguard.DecisionConfirm {
		t.Fatalf("fixture: the SSH private key item requires confirmation: %+v", decision)
	}
	payloads := buildAgentGuardToolAuditPayloads(ToolCall{ID: "call_1", Function: ToolCallFunc{Name: "Bash"}}, decision, map[string]interface{}{"command": "rm ~/.ssh/id_rsa"})
	if len(payloads) == 0 || payloads[0].Status != "waiting_confirmation" || payloads[0].FinalAction != string(agentguard.DestructiveActionConfirm) {
		t.Fatalf("a floor that requires confirmation is logged as waiting for confirmation: %+v", payloads)
	}
}

func TestDestructiveFloor2922GeneralVerdictNoticeNamesTheRule(t *testing.T) {
	general := agentguard.Decision{RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionBlock,
		EffectiveReason: "explicit_block", PolicyReason: "explicit_block", ConfiguredEnforcement: true, MatchedRuleID: "custom-block"}
	decision := destructiveFloorDecision2922(t, "", &general)
	if decision.EffectiveDecision != agentguard.DecisionBlock || decision.FinalAction != agentguard.DestructiveActionBlock {
		t.Fatalf("fixture: the explicit rule blocks: %+v", decision)
	}
	operation := agentGuardBlockOperation(ToolCall{Function: ToolCallFunc{Name: "Bash"}}, decision)
	if operation.Layer != "agent_tool" || operation.RuleName != "custom-block" || strings.Contains(operation.Basis, "删除与破坏") {
		t.Fatalf("the notice must name the explicit rule that blocked the call: %+v", operation)
	}
}
