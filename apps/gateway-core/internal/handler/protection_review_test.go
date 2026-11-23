package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 规格审查补测（handler 侧）。

// 读 pkg/secrets/manager.go 命中“名字像敏感文件”（默认告警放行），真正要求确认的是配置的
// 读突发：提示不能写成“名字像敏感文件 动作为人工确认”。卡片不带 policy_center_action
// （老卡片、自建规则）时按 2.9.21 由显式规则决定，不确认；托管卡片不参与匹配，突发确认生效。
func TestBehaviorConfirmNoticeIsNotAttributedToAlertingProtectionItem(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule *agentguard.PolicyRule
		want agentguard.DecisionAction
	}{
		{"no rule", nil, agentguard.DecisionConfirm},
		{"managed record card", &agentguard.PolicyRule{ID: "policy-center-sensitive_resource", ToolPattern: "file.*", Action: agentguard.DecisionAudit, Enabled: true, PolicyCenterAction: "record"}, agentguard.DecisionConfirm},
		{"card without policy_center_action", &agentguard.PolicyRule{ID: "policy-center-sensitive_resource", ToolPattern: "file.*", Action: agentguard.DecisionAudit, Enabled: true}, agentguard.DecisionAudit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 2.9.22 批次 2B：突发的动作来自防护项 agent.burst，这里配成确认（原先靠租户阈值本身）。
			policy := &agentguard.EffectivePolicy{Mode: agentguard.ModeStrict, ConfirmChannelEnabled: true,
				Behavior:    &agentguard.BehaviorThresholds{FileReadBurst: 1},
				Protections: protection.Settings{"agent.burst": {Action: protection.ActionConfirm}}}
			if tc.rule != nil {
				policy.Rules = []agentguard.PolicyRule{*tc.rule}
			}
			decision := agentguard.AnalyzeToolCall(context.Background(), agentguard.ToolCallAnalysisInput{
				ToolName: "Read", ToolType: agentguard.ToolTypeFile, Arguments: map[string]any{"file_path": "/repo/pkg/secrets/manager.yaml"},
				Mode: agentguard.ModeStrict, ActorKey: "tenant/p/u", Policy: policy,
				Behavior: agentguard.NewBehaviorWindow(10*time.Second, agentguard.BehaviorThresholds{}),
			})
			// 防护项摘要取动作最严的命中：配成确认的 agent.burst（原断言是告警放行的 agent.sensitive_name）。
			if decision.EffectiveDecision != tc.want || decision.ProtectionItem != "agent.burst" || !hasHitWithAction(decision, "sensitive_name_hint", "alert_allow") {
				t.Fatalf("effective=%s want %s (burst confirm alongside an alerting protection item): %+v", decision.EffectiveDecision, tc.want, decision)
			}
			if tc.want != agentguard.DecisionConfirm {
				return
			}
			operation := agentGuardBlockOperation(ToolCall{Function: ToolCallFunc{Name: "Read"}}, decision)
			if strings.Contains(operation.Basis, "名字像敏感文件") || strings.Contains(operation.RuleName, "名字像敏感文件") || operation.Cause == "protection_item" {
				t.Fatalf("behavior confirmation attributed to the alerting protection item: %+v", operation)
			}
		})
	}
}

// 规则 10 在破坏性路径：命中告警放行的防护项时也要告警，而且只发一条。
func TestDestructiveCallHittingAlertingProtectionItemAlertsOnce(t *testing.T) {
	const sitePolicy = `{"id":"p","name":"现场","policy_version":"v1","mode":"audit","default_action":"audit","fail_policy":"open","confirm_channel_enabled":true,` +
		`"rules":[{"id":"policy-center-sensitive_resource","tool_pattern":"file.*","action":"audit","enabled":true},{"id":"policy-center-system_command","tool_pattern":"system.*","action":"audit","enabled":true}],"exceptions":[]}`
	for _, command := range []string{"rm -f ~/.ssh/id_rsa", "cat ~/.aws/credentials > ./creds.txt"} {
		t.Run(command, func(t *testing.T) {
			h, audit := blockFieldsHandler(t, sitePolicy)
			envelope := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "tenant-1", UserID: "user-1", SessionID: "session-1"}
			call := ToolCall{ID: "call-1", Type: "function", Function: ToolCallFunc{Name: "Bash", Arguments: `{"command":` + string(jsonQuote(command)) + `}`}}
			decision, err := h.applyAgentGuardToolDecisionResult(context.Background(), envelope, call, nil, &AuditResult{}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !isDestructiveGateDecision(decision) || !decision.ProtectionAlert() || !decision.NotificationRequired || decision.EffectiveDecision != agentguard.DecisionAudit {
				t.Fatalf("destructive call with an alerting protection item must require notification: %+v", decision)
			}
			alerts := 0
			for _, event := range audit.SecurityEventWrites {
				if event.ActionTaken == "alert" {
					alerts++
				}
			}
			if alerts != 1 {
				t.Fatalf("want exactly one alert event, got %d: %+v", alerts, audit.SecurityEventWrites)
			}
		})
	}
}

// MCP 审计风险等级：准入类原因按白名单判断，不靠证据类别推断。
func TestMCPAdmissionCriticalUsesReasonWhitelist(t *testing.T) {
	for _, tc := range []struct {
		decision agentguard.Decision
		want     bool
	}{
		{agentguard.Decision{Reason: "policy_runtime_unavailable"}, true},
		{agentguard.Decision{Reason: "mcp_supply_chain:quarantined", ConfiguredEnforcement: true}, true},
		{agentguard.Decision{Reason: "approval_context_drift", ConfiguredEnforcement: true}, true},
		{agentguard.Decision{Reason: "skill_version_revoked", ConfiguredEnforcement: true}, true},
		{agentguard.Decision{Reason: "skill_admission_unavailable"}, false},
		{agentguard.Decision{Reason: "mcp_redline_block:cloud_metadata", ConfiguredEnforcement: true,
			Evidence: []agentguard.Evidence{{Category: "mcp_supply_chain"}}}, false},
	} {
		if got := mcpAdmissionCritical(tc.decision); got != tc.want {
			t.Errorf("reason=%s configured=%t: got %t want %t", tc.decision.Reason, tc.decision.ConfiguredEnforcement, got, tc.want)
		}
	}
}

func hasHitWithAction(decision agentguard.Decision, reason, action string) bool {
	for _, hit := range decision.ProtectionHits {
		if hit.Reason == reason && hit.Action == action {
			return true
		}
	}
	return false
}
