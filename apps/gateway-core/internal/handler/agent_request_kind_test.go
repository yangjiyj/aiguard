package handler

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

func securityMonitorMessages() []Message {
	return []Message{
		{Role: "system", Content: jsonQuote("You are a security monitor for autonomous AI coding agents. Classify the next action.")},
		{Role: "user", Content: jsonQuote("<transcript>cat ../../data/input.csv</transcript>")},
	}
}

func TestSecurityMonitorKindReachesTheEngineContext(t *testing.T) {
	messages := securityMonitorMessages()
	plan := gatewayInputInspectionPlan(messages, inspectionscope.Default())
	plan.agentRequestKind = agentRequestKindForMessages("claude-code", messages)
	if plan.agentRequestKind != aimsg.AgentRequestKindClaudeCodeSecurityMonitor {
		t.Fatalf("kind = %q", plan.agentRequestKind)
	}
	ctx := context.WithValue(context.Background(), inputInspectionPlanKey{}, plan)
	ctx = context.WithValue(ctx, inputInspectionTargetKey{}, plan.targets[1])
	wire := buildInputCheckRequest(ctx, &modelrouter.RequestEnvelope{AgentType: "claude-code"},
		messageText(messages[1].Content), 1, "user", "user")
	if wire.Context["agent_request_kind"] != aimsg.AgentRequestKindClaudeCodeSecurityMonitor {
		t.Fatalf("agent_request_kind missing: %+v", wire.Context)
	}
	if wire.Context["content_source"] != "user" {
		t.Fatalf("source must stay user: %+v", wire.Context["content_source"])
	}
}

func TestOrdinarySessionCarriesNoAgentRequestKind(t *testing.T) {
	messages := []Message{
		{Role: "system", Content: jsonQuote("You are Claude Code, Anthropic's official CLI.")},
		{Role: "user", Content: jsonQuote("cat ../../data/input.csv")},
	}
	if kind := agentRequestKindForMessages("claude-code", messages); kind != "" {
		t.Fatalf("kind = %q", kind)
	}
	if kind := agentRequestKindForMessages("cursor", securityMonitorMessages()); kind != "" {
		t.Fatalf("other client kind = %q", kind)
	}
	plan := gatewayInputInspectionPlan(messages, inspectionscope.Default())
	ctx := context.WithValue(context.Background(), inputInspectionPlanKey{}, plan)
	ctx = context.WithValue(ctx, inputInspectionTargetKey{}, plan.targets[1])
	wire := buildInputCheckRequest(ctx, &modelrouter.RequestEnvelope{AgentType: "claude-code"},
		messageText(messages[1].Content), 1, "user", "user")
	if _, ok := wire.Context["agent_request_kind"]; ok {
		t.Fatalf("ordinary session must not carry agent_request_kind: %+v", wire.Context)
	}
}

func TestSecurityMonitorKindSeparatesFingerprintScopes(t *testing.T) {
	env := &modelrouter.RequestEnvelope{TenantID: "t", UserID: "u", ProjectID: "p", AgentType: "claude-code"}
	target := inputInspectionTarget{source: "user", role: "user", path: "/messages/1", latest: true}
	historyTarget := inputInspectionTarget{source: "user_history", role: "user", path: "/messages/1", history: true}
	scope := func(kind string, target inputInspectionTarget) string {
		plan := inputInspectionPlan{policy: inspectionscope.Default(), userTask: "same text", agentRequestKind: kind}
		ctx := context.WithValue(context.Background(), inputInspectionPlanKey{}, plan)
		ctx = context.WithValue(ctx, inputInspectionTargetKey{}, target)
		return inspectionFingerprintScope(ctx, env, target.source, "")
	}
	if scope("", target) == scope(aimsg.AgentRequestKindClaudeCodeSecurityMonitor, target) {
		t.Fatal("latest-turn scope must differ between session and security monitor")
	}
	if scope("", historyTarget) == scope(aimsg.AgentRequestKindClaudeCodeSecurityMonitor, historyTarget) {
		t.Fatal("history scope must differ between session and security monitor")
	}
}
