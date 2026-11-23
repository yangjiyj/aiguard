package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 批次 2B（chat 路径）：工具连续失败的窗口和次数取 agent.tool_failure_loop，动作按该项，
// 并带着策略与确认通道判定（2.9.21 升级路径只带模式重算，命中确认规则时变成无通道确认被拦）。
func failureLoopHandler(t *testing.T, policyJSON string) (*ChatCompletionsHandler, *modelrouter.RequestEnvelope) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":` + policyJSON + `}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client := NewToolRiskClient(server.URL, "internal")
	setToolGuardTestPosture(t, client, false, false)
	h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client, auditWriter: &MockAuditWriter{},
		agentGuardToolFailures: agentguard.NewToolFailureWindow(10*time.Minute, 5)}
	return h, &modelrouter.RequestEnvelope{TenantID: "t1", ProjectID: "p1", UserID: "u1", SessionID: "s1", RequestID: "r1"}
}

func failTwice(h *ChatCompletionsHandler, envelope *modelrouter.RequestEnvelope) {
	var history []Message
	for round := 1; round <= 2; round++ {
		id := "call-" + strings.Repeat("x", round)
		history = append(history, assistantCall(id, "Read"), toolResult(id, toolFailedContent))
		h.recordToolResultFailures(context.Background(), envelope, history)
	}
}

func TestToolFailureLoop2922FollowsTenantParamsAndConfirmChannel(t *testing.T) {
	read := ToolCall{ID: "call-next", Type: "function", Function: ToolCallFunc{Name: "Read", Arguments: `{"file_path":"/repo/main.go"}`}}
	for _, tc := range []struct {
		name, policy string
		want         agentguard.DecisionAction
	}{
		{"default threshold 5 is not reached", `{"id":"p","mode":"strict","confirm_channel_enabled":true,"rules":[],"exceptions":[]}`, agentguard.DecisionAllow},
		{"tenant threshold 2 alerts by default", `{"id":"p","mode":"strict","confirm_channel_enabled":true,"rules":[],"exceptions":[],"protections":{"agent.tool_failure_loop":{"action":"alert_allow","params":{"threshold":2}}}}`, agentguard.DecisionAudit},
		{"configured block blocks", `{"id":"p","mode":"strict","confirm_channel_enabled":true,"rules":[],"exceptions":[],"protections":{"agent.tool_failure_loop":{"action":"block","params":{"threshold":2}}}}`, agentguard.DecisionBlock},
		{"confirm rule with a channel stays confirm", `{"id":"p","mode":"strict","confirm_channel_enabled":true,"rules":[{"id":"confirm-read","tool_pattern":"read","action":"confirm","enabled":true}],"exceptions":[],"protections":{"agent.tool_failure_loop":{"action":"confirm","params":{"threshold":2}}}}`, agentguard.DecisionConfirm},
		{"exception releases", `{"id":"p","mode":"strict","confirm_channel_enabled":true,"rules":[],"exceptions":[{"id":"e-loop","rule_id":"agent.tool_failure_loop","target_pattern":"","decision":"audit","expires_at":"2099-01-01T00:00:00Z"}],"protections":{"agent.tool_failure_loop":{"action":"block","params":{"threshold":2}}}}`, agentguard.DecisionAudit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, envelope := failureLoopHandler(t, tc.policy)
			failTwice(h, envelope)
			decision, _, err := h.analyzeAgentGuardToolCall(context.Background(), envelope, read, nil)
			if err != nil {
				t.Fatal(err)
			}
			if decision.EffectiveDecision != tc.want {
				t.Fatalf("effective=%s want %s: %+v", decision.EffectiveDecision, tc.want, decision)
			}
			if tc.want != agentguard.DecisionAllow && decision.ProtectionItem != "agent.tool_failure_loop" {
				t.Fatalf("the failure loop must be attributed to its protection item: %+v", decision)
			}
		})
	}
}

// 批次 2B：Skill 准入服务不可用加例外放开（默认告警放行、配成阻断照拦见 TestSkillAdmissionFailureModesAndAuditLock）。
func TestSkillAdmissionUnavailable2922ExceptionReleases(t *testing.T) {
	const policy = `{"id":"p","mode":"strict","default_action":"audit","rules":[],"exceptions":[{"id":"e-adm","rule_id":"skill.admission_unavailable","target_pattern":"","decision":"audit","expires_at":"2099-01-01T00:00:00Z"}],"protections":{"skill.admission_unavailable":{"action":"block","params":{}}}}`
	server := skillAdmissionFailureServer(t, policy)
	client := NewToolRiskClient(server.URL, "internal")
	setToolGuardTestPosture(t, client, false, false)
	h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client, auditWriter: &MockAuditWriter{}}
	call := ToolCall{ID: "call", Type: "function", Function: ToolCallFunc{
		Name: "use_skill", Arguments: `{"skill":"pdf","version":"1","bundle_hash":"` + strings.Repeat("a", 64) + `"}`,
	}}
	decision, _, _ := h.analyzeAgentGuardToolCall(context.Background(), &modelrouter.RequestEnvelope{TenantID: "tenant", RequestID: "request"}, call, nil)
	if decision.EffectiveDecision == agentguard.DecisionBlock || len(decision.ProtectionExceptionIDs()) != 1 {
		t.Fatalf("an exception naming skill.admission_unavailable must release it: %+v", decision)
	}
}
