package alert

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 热修复：数据面实际执法（拦截/等待确认）的事件，即使 finding 置信度为 0 也必须出告警。
// 线上事故：Skill 进入确认流程，网关写 tool_attempt_blocked 事件、动作 confirm、finding
// 置信度 0，被置信度闸当成低信号压掉，管理员在告警中心看不到。
func enforcedToolEvent(id, action string, confidence float64) *repository.SecurityEvent {
	ev := secEventWithFindings(id, action, map[string]any{
		"type": "tool_attempt_blocked", "category": "skill_supply_chain",
		"severity": "high", "confidence": confidence, "action": "block",
	})
	ev.EventType = "tool_attempt_blocked"
	ev.Severity = "high"
	return ev
}

func runOnceSurfaced(t *testing.T, ev *repository.SecurityEvent) (alerted int, pushed int) {
	t.Helper()
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakePusher{}
	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	return n, len(pusher.pushedTypes)
}

func TestSecEventBridge_ToolConfirmWithZeroConfidenceSurfaces(t *testing.T) {
	n, pushed := runOnceSurfaced(t, enforcedToolEvent("tconf1", "confirm", 0))
	if n != 1 || pushed != 1 {
		t.Fatalf("a held (confirm) tool call with confidence 0 must surface, got alerted=%d pushed=%d", n, pushed)
	}
}

func TestSecEventBridge_ToolAttemptBlockedEventTypeSurfacesRegardlessOfAction(t *testing.T) {
	// 动作字段不是典型的执法词（审计/空），但事件类型本身说明工具调用被拦。
	for _, action := range []string{"audit", ""} {
		n, pushed := runOnceSurfaced(t, enforcedToolEvent("ttype-"+action, action, 0))
		if n != 1 || pushed != 1 {
			t.Fatalf("action=%q: tool_attempt_blocked must surface, got alerted=%d pushed=%d", action, n, pushed)
		}
	}
}

func TestSecEventBridge_EffectiveDecisionConfirmOrBlockSurfaces(t *testing.T) {
	for _, decision := range []string{"confirm", "block", "BLOCK"} {
		ev := secEventWithFindings("effdec-"+decision, "audit", finding(0))
		ev.MatchedSummary["effective_decision"] = decision
		n, pushed := runOnceSurfaced(t, ev)
		if n != 1 || pushed != 1 {
			t.Fatalf("effective_decision=%q must surface, got alerted=%d pushed=%d", decision, n, pushed)
		}
	}
}

func TestSecEventBridge_ToolBlockedBeatsTriageAndExceptionSuppression(t *testing.T) {
	// 执法优先于 LLM triage 误报压制：被拦的请求不能因为异步裁判认为"可能误报"而没有告警。
	ev := enforcedToolEvent("ttriage1", "confirm", 0)
	fs, _ := ev.MatchedSummary["findings"].([]any)
	fm := fs[0].(map[string]any)
	fm["triage"] = map[string]any{"verdict": "likely_false_positive", "review_state": "likely_false_positive"}
	n, pushed := runOnceSurfaced(t, ev)
	if n != 1 || pushed != 1 {
		t.Fatalf("an enforced event must not be hidden by triage suppression, got alerted=%d pushed=%d", n, pushed)
	}
}

func TestSecEventBridge_PlainAuditLowConfidenceStillSuppressed(t *testing.T) {
	// 没有任何执法信号的纯审计低置信度事件仍然可以被压掉。
	ev := secEventWithFindings("plainaudit1", "audit", finding(0))
	ev.EventType = "skill_invocation_risk"
	ev.Severity = "medium"
	n, pushed := runOnceSurfaced(t, ev)
	if n != 0 || pushed != 0 {
		t.Fatalf("a plain audit event below the confidence floor must stay suppressed, got alerted=%d pushed=%d", n, pushed)
	}
}

func TestSecEventBridge_EnforcementDoesNotRevivePipelineFailureTelemetry(t *testing.T) {
	// 运营遥测排除优先：检测管线故障事件即使带 effective_decision=block 也不进可处置收件箱。
	ev := secEventWithFindings("pipefail1", "security_check_failed", finding(0))
	ev.MatchedSummary["effective_decision"] = "block"
	n, pushed := runOnceSurfaced(t, ev)
	if n != 0 || pushed != 0 {
		t.Fatalf("pipeline failure telemetry must keep its exclusion, got alerted=%d pushed=%d", n, pushed)
	}
}
