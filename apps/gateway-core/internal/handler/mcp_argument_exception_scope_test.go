package handler

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// MCP 参数里读 ~/.ssh/id_rsa：agent.ssh_private_key=block 照拦；rule_id 指向该项、目标 mcp:fs/read_file
// 的例外放开；换服务名不放开。
func TestMCPArgumentProtectionExceptionScopedToServerAndTool(t *testing.T) {
	run := func(pattern string) agentguard.Decision {
		policy := &agentguard.EffectivePolicy{Mode: agentguard.ModeStrict,
			Protections: protection.Settings{"agent.ssh_private_key": {Action: protection.ActionBlock}}}
		if pattern != "" {
			policy.Exceptions = []agentguard.PolicyException{{ID: "exc_ssh", RuleID: "agent.ssh_private_key", TargetPattern: pattern,
				Decision: agentguard.DecisionAllow, ExpiresAt: time.Now().Add(time.Hour)}}
		}
		h := &MCPProxyHandler{}
		envelope := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t"}
		permission := agentguard.Decision{RawDecision: agentguard.DecisionAllow, EffectiveDecision: agentguard.DecisionAllow}
		return h.evaluateMCPAgentGuardToolCall(context.Background(), envelope, "fs__read_file", structuredToolCallInput{
			RequestID: "r", TenantID: "t", Protocol: "mcp", ToolName: "read_file", ToolType: agentguard.ToolTypeMCP,
			Arguments: map[string]interface{}{"path": "~/.ssh/id_rsa"}, RawArguments: `{"path":"~/.ssh/id_rsa"}`,
			Policy: policy, Mode: agentguard.ModeStrict, ConfirmSupported: true, BaseDecision: permission,
			ExceptionScope: mcpExceptionTarget("fs", "read_file"),
		}, permission, nil)
	}
	if d := run(""); d.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("ssh key read must block when the item is block: %+v", d)
	}
	if d := run("mcp:fs/read_file"); d.EffectiveDecision == agentguard.DecisionBlock {
		t.Fatalf("exception scoped to mcp:fs/read_file must release: %+v", d)
	}
	if d := run("mcp:fs"); d.EffectiveDecision == agentguard.DecisionBlock {
		t.Fatalf("exception scoped to the whole server must release: %+v", d)
	}
	if d := run("mcp:other/read_file"); d.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("exception for another server must not release: %+v", d)
	}
}
