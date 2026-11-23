package handler

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 复审：结论原因是“确认无通道兜底阻断”时再看 PolicyReason：要求确认的是防护项或显式规则，就归因到它，
// 不写成删除与破坏卡片。
func TestDestructiveNoChannel2922NoticeNamesWhatRequiredConfirmation(t *testing.T) {
	raw := agentguard.Decision{RawDecision: agentguard.DecisionBlock, Reason: "deterministic_destructive_operation", RiskLevel: "high",
		RiskCategory: agentguard.DestructiveRiskCategory, RiskSubcategory: "filesystem_delete", NormalizedTarget: "~/.ssh/id_rsa",
		OperationID: "op_nochan",
		ProtectionHits: []agentguard.ProtectionHit{{Reason: "blocked_ssh_private_key_path", Target: "~/.ssh/id_rsa",
			MatchTarget: "~/.ssh/id_rsa", RiskLevel: "critical", Confidence: 0.95}}}
	policy := &agentguard.EffectivePolicy{ID: "p", Mode: agentguard.ModeStrict,
		Destructive: &agentguard.DestructivePolicy{Mode: agentguard.ModeAudit, Action: agentguard.DestructiveActionRecord},
		Protections: protection.Settings{
			"agent.ssh_private_key":         {Action: protection.ActionConfirm},
			"agent.confirm_without_channel": {Action: protection.ActionBlock},
		}}
	input := agentguard.PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Target: "~/.ssh/id_rsa", Policy: policy,
		CallerMode: agentguard.ModeStrict, RiskCategory: agentguard.DestructiveRiskCategory, HighConfidence: true}
	floor := agentguard.ApplyEffectivePolicy(raw, input)
	if floor.EffectiveDecision != agentguard.DecisionBlock || floor.EffectiveReason != "confirm_without_channel_fail_closed" || floor.PolicyReason != "protection_item" {
		t.Fatalf("fixture: the SSH private key item requires confirmation, no channel blocks: %+v", floor)
	}
	operation := agentGuardBlockOperation(ToolCall{Function: ToolCallFunc{Name: "Bash"}}, floor)
	if operation.Layer != "agent_tool" || operation.RuleName != "SSH 私钥" || strings.Contains(operation.Basis, "删除与破坏") ||
		!strings.Contains(operation.Basis, "SSH 私钥") || !strings.Contains(operation.Basis, protectionItemLabel("agent.confirm_without_channel")) {
		t.Fatalf("a protection item requiring confirmation without a channel is named in the notice: %+v", operation)
	}

	general := agentguard.Decision{RawDecision: agentguard.DecisionConfirm, EffectiveDecision: agentguard.DecisionBlock,
		EffectiveReason: "confirm_without_channel_fail_closed", PolicyReason: "explicit_confirm", ConfiguredEnforcement: true, MatchedRuleID: "custom-confirm"}
	raw.ProtectionHits = nil
	input.General = &general
	input.Policy.Protections = nil
	rule := agentguard.ApplyEffectivePolicy(raw, input)
	if rule.EffectiveDecision != agentguard.DecisionBlock || rule.MatchedRuleID != "custom-confirm" {
		t.Fatalf("fixture: the explicit confirm rule blocks without a channel: %+v", rule)
	}
	operation = agentGuardBlockOperation(ToolCall{Function: ToolCallFunc{Name: "Bash"}}, rule)
	if operation.Layer != "agent_tool" || operation.RuleName != "custom-confirm" || strings.Contains(operation.Basis, "删除与破坏") {
		t.Fatalf("an explicit confirm rule without a channel is named in the notice: %+v", operation)
	}
}
