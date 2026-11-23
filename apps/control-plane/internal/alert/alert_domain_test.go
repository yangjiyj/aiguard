package alert

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// domainEvent 用最小字段构造一条用于域归类的安全事件。
func domainEvent(eventType string, summary map[string]any) *repository.SecurityEvent {
	if summary == nil {
		summary = map[string]any{}
	}
	ev := sampleSecEvent("evt-domain")
	ev.EventType = eventType
	ev.MatchedSummary = summary
	return ev
}

func TestAlertDomainForSecurityEvent(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		summary   map[string]any
		want      string
	}{
		{name: "skill prefix maps to skill", eventType: "skill_invocation_risk", want: "skill"},
		{name: "skill admission maps to skill", eventType: "skill_admission_changed", want: "skill"},
		{name: "mcp prefix maps to mcp", eventType: "mcp_policy_hit", want: "mcp"},
		{name: "gateway_mcp source overrides tool prefix", eventType: "tool_attempt_blocked", summary: map[string]any{"source": "gateway_mcp", "server_id": "srv-1"}, want: "mcp"},
		{name: "server_id maps to mcp", eventType: "tool_execution_risk", summary: map[string]any{"server_id": "srv-1"}, want: "mcp"},
		{name: "mcp_server_id maps to mcp", eventType: "security_check", summary: map[string]any{"mcp_server_id": "srv-1"}, want: "mcp"},
		{name: "gateway tool event maps to tool", eventType: "tool_attempt_blocked", summary: map[string]any{"source": "gateway"}, want: "tool"},
		{name: "tool destructive intent maps to tool", eventType: "tool_destructive_intent", summary: map[string]any{"source": "gateway"}, want: "tool"},
		{name: "access denial maps to access", eventType: "access_denied", want: "access"},
		{name: "proxy auth denial maps to access", eventType: "proxy_auth_denied", want: "access"},
		{name: "model policy maps to access", eventType: "model_policy", want: "access"},
		{name: "runtime fault maps to system", eventType: "security_check_failed", want: "system"},
		{name: "security mode change maps to system", eventType: "security_mode_changed", want: "system"},
		{name: "proxy event maps to content", eventType: "proxy_input_block", want: "content"},
		{name: "semantic event maps to content", eventType: "semantic_attack", want: "content"},
		{name: "data security maps to content", eventType: "data_security", want: "content"},
		{name: "nil event maps to content", eventType: "", want: "content"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ev *repository.SecurityEvent
			if tt.eventType != "" {
				ev = domainEvent(tt.eventType, tt.summary)
			}
			if got := alertDomainForSecurityEvent(ev); got != tt.want {
				t.Fatalf("alertDomainForSecurityEvent(%q) = %q, want %q", tt.eventType, got, tt.want)
			}
		})
	}
}

func TestAlertGroupTitleToolContextSuffix(t *testing.T) {
	lc := lifecycleFields{effectiveSeverity: "high", dispositionClass: "action_required", classKey: "destructive_change", stage: "tool"}

	tests := []struct {
		name      string
		eventType string
		summary   map[string]any
		wantSub   string
		wantFull  string
	}{
		{
			name:      "tool event with tool name appends suffix",
			eventType: "tool_destructive_intent",
			summary:   map[string]any{"rule_name": "exec"},
			wantFull:  "安全事件【高危】破坏性操作意图（exec） · 处置：已阻断",
		},
		{
			name:      "mcp-style tool_name wins over rule_name",
			eventType: "tool_attempt_blocked",
			summary:   map[string]any{"tool_name": "mcp__fs__rm", "rule_name": "ignored"},
			wantFull:  "安全事件【高危】工具尝试已阻断（mcp__fs__rm） · 处置：已阻断",
		},
		{
			name:      "agent type joins tool name",
			eventType: "tool_execution_risk",
			summary:   map[string]any{"agent_type": "openai-codex", "tool_name": "exec"},
			wantFull:  "安全事件【高危】工具执行风险（openai-codex · exec） · 处置：已阻断",
		},
		{
			name:      "no tool identity adds no suffix",
			eventType: "tool_attempt_blocked",
			summary:   map[string]any{},
			wantSub:   "）",
		},
		{
			name:      "non tool event gets no suffix",
			eventType: "data_security",
			summary:   map[string]any{"tool_name": "exec"},
			wantSub:   "（exec）",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := domainEvent(tt.eventType, tt.summary)
			ev.ActionTaken = "block"
			got := alertGroupTitle(ev, lc)
			if tt.wantFull != "" && got != tt.wantFull {
				t.Fatalf("alertGroupTitle = %q, want %q", got, tt.wantFull)
			}
			if tt.wantSub != "" && strings.Contains(got, tt.wantSub) {
				t.Fatalf("alertGroupTitle = %q, must not contain %q", got, tt.wantSub)
			}
		})
	}
}
