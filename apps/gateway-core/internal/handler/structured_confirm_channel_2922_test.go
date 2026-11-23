package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 复审第 4 项：同一次调用里，删除与破坏分支按 structuredConfirmAllowed（MCP 走确认扩展）判断确认通道，
// 解析失败、身份异常分支却按策略的 confirm_channel_enabled，两边口径不一。统一按这次调用实际的通道。
func TestStructuredRejection2922UsesTheCallsConfirmChannel(t *testing.T) {
	evaluate := func(protocol string, confirmSupported, policyChannel bool, parseRejected bool) agentguard.Decision {
		key := "agent.identity_rejected"
		input := structuredToolCallInput{TenantID: "t", Protocol: protocol, SessionID: "s", OutputItemID: "o", ToolCallID: "c",
			ToolName: "read_file", ToolType: "file", Arguments: map[string]interface{}{"path": "/repo/a.go"},
			ProtocolIdentityRejected: true, Mode: agentguard.ModeStrict, ConfirmSupported: confirmSupported,
			BaseDecision: agentguard.Decision{RawDecision: agentguard.DecisionAllow, EffectiveDecision: agentguard.DecisionAllow}}
		if parseRejected {
			key = "agent.parse_rejected"
			input.ProtocolIdentityRejected = false
			input.ToolName, input.ToolType, input.Arguments = "Bash", "system", nil
			input.RawArguments, input.ArgumentsParseRejected = `{"command": "rm -rf /data`, true
		}
		input.Policy = &agentguard.EffectivePolicy{ID: "p", Mode: agentguard.ModeStrict, RuleMode: agentguard.ModeStrict,
			DefaultAction: agentguard.DecisionAudit, ConfirmChannelEnabled: policyChannel,
			Protections: protection.Settings{key: {Action: protection.ActionConfirm}}}
		return evaluateStructuredToolCall(input).Decision
	}
	for _, branch := range []struct {
		name          string
		parseRejected bool
	}{{"identity", false}, {"parse", true}} {
		for _, tc := range []struct {
			name                           string
			protocol                       string
			confirmSupported, policyChanel bool
			wantConfirm                    bool
		}{
			{"mcp with the confirm extension", "mcp", true, false, true},
			{"mcp without the confirm extension", "mcp", false, true, false},
			{"chat with the policy channel", "chat", false, true, true},
			{"chat without the policy channel", "chat", true, false, false},
		} {
			t.Run(branch.name+"/"+tc.name, func(t *testing.T) {
				got := evaluate(tc.protocol, tc.confirmSupported, tc.policyChanel, branch.parseRejected)
				if (got.EffectiveDecision == agentguard.DecisionConfirm) != tc.wantConfirm {
					t.Fatalf("confirm=%v want %v: %+v", got.EffectiveDecision == agentguard.DecisionConfirm, tc.wantConfirm, got)
				}
			})
		}
	}
}
