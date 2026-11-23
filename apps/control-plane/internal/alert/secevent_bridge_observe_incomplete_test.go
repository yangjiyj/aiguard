package alert

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func breakerOpenObservationFindings() []map[string]any {
	return []map[string]any{
		{
			"type": "content_safety", "category": "content_profanity_abuse", "severity": "medium",
			"confidence": 0.97, "action": "allow", "counts_as_security_finding": false,
			"triage": map[string]any{"disposition": "observation", "disposition_reason": "quoted_profanity_reference"},
		},
		{
			"type": "semantic_telemetry", "category": "semantic_unavailable", "severity": "low",
			"confidence": 1.0, "action": "audit", "counts_as_security_finding": false,
			"triage": map[string]any{"semantic_status": "incomplete", "semantic_reason": "breaker_open"},
		},
	}
}

// 复审 I2：语义未完成（breaker_open）时写出的观察事件保留原类型，告警桥只作证据、不当 runtime_fault。
func TestSecEventBridge_ObservationDuringSemanticOutageIsNotRuntimeFault(t *testing.T) {
	ev := secEventWithFindings("observation-breaker", "security_audit", breakerOpenObservationFindings()...)
	ev.EventType = "content_safety"
	ev.MatchedSummary["semantic_status"] = "incomplete"
	ev.MatchedSummary["semantic_reason"] = "breaker_open"
	if got := alertTypeForSecurityEvent(ev); got == "runtime_fault" {
		t.Fatalf("观察事件不得被当成 runtime_fault")
	}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakePusher{}
	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(pusher.pushedTypes) != 0 {
		t.Fatalf("观察事件不得进收件箱, n=%d pushed=%v", n, pusher.pushedTypes)
	}

	// 对照：修复前网关会把它改写成 security_check_failed，告警桥据此判为 runtime_fault。
	rewritten := secEventWithFindings("observation-rewritten", "security_audit", breakerOpenObservationFindings()...)
	rewritten.EventType = "security_check_failed"
	if alertTypeForSecurityEvent(rewritten) != "runtime_fault" {
		t.Fatalf("对照前提不成立：security_check_failed 应判为 runtime_fault")
	}
}
