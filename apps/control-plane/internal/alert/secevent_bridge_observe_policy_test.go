package alert

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 网关为「仅记录」类观察（策略 智能分析命中时=仅记录、辱骂讨论类降级）写出的观察事件：
// action=security_audit，findings 全部 counts_as_security_finding=false。它只作证据，
// 不进收件箱、不出可处置告警，但仍标为已处理。
func TestSecEventBridge_PolicyObserveAndProfanityDiscussionStayEvidenceOnly(t *testing.T) {
	semanticObserve := secEventWithFindings("semantic-observe", "security_audit", map[string]any{
		"type": "semantic_attack", "category": "prompt_input_semantic_risk", "severity": "high",
		"confidence": 0.9, "action": "allow", "counts_as_security_finding": false,
		"triage": map[string]any{"disposition": "observation", "disposition_reason": "policy_semantic_observe"},
	})
	semanticObserve.EventType = "semantic_attack"
	profanityDiscussion := secEventWithFindings("profanity-discussion", "security_audit", map[string]any{
		"type": "content_safety", "category": "content_profanity_abuse", "severity": "medium",
		"confidence": 0.97, "action": "allow", "counts_as_security_finding": false,
		"triage": map[string]any{"disposition": "observation", "disposition_reason": "quoted_profanity_reference"},
	})
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{semanticObserve, profanityDiscussion}}
	pusher := &fakePusher{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(pusher.pushedTypes) != 0 {
		t.Fatalf("仅记录类观察事件不得进收件箱, n=%d pushed=%v", n, pusher.pushedTypes)
	}
	if len(src.markedIDs) != 1 || len(src.markedIDs[0]) != 2 {
		t.Fatalf("观察事件仍要标为已处理, got %v", src.markedIDs)
	}
}
