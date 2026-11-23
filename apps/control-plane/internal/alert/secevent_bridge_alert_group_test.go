package alert

import (
	"context"
	"errors"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeAlertGrouper struct {
	inputs   []repository.AlertGroupUpsertInput
	failNext bool
}

func (f *fakeAlertGrouper) UpsertOpen(ctx context.Context, input repository.AlertGroupUpsertInput) (*repository.AlertGroup, bool, error) {
	if f.failNext {
		f.failNext = false
		return nil, false, errors.New("alert group store down")
	}
	f.inputs = append(f.inputs, input)
	return &repository.AlertGroup{ID: "ag_test", TenantID: input.TenantID, GroupKey: input.GroupKey, Status: repository.AlertGroupStatusOpen, Severity: input.Severity, OccurrenceCount: len(f.inputs)}, len(f.inputs) == 1, nil
}

func TestSecEventBridgeWritesAlertGroupForSurfacedEvent(t *testing.T) {
	ev := secEventWithFindings("hi-group", "audit", findingSha(0.90, "sha_group"))
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	// 收件箱正文另存一份去掉原文的副本，不再与告警组入参共用同一个 map，这里直接看收件箱收到的正文。
	pusher := &rawCapturingPusher{}
	groups := &fakeAlertGrouper{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0.5).WithAlertGroups(groups).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 alert, got %d", n)
	}
	if len(groups.inputs) != 1 {
		t.Fatalf("expected 1 alert group upsert, got %d", len(groups.inputs))
	}
	input := groups.inputs[0]
	if input.TenantID != ev.TenantID || input.RequestID != ev.RequestID || input.RepresentativeEventID != ev.ID {
		t.Fatalf("alert group input lost event context: %+v", input)
	}
	if input.GroupKey == "" || input.Severity != "high" || input.AlertType != "security_event" {
		t.Fatalf("alert group input missing grouping fields: %+v", input)
	}
	if len(pusher.bodies) != 1 || pusher.bodies[0]["alert_group_id"] != "ag_test" {
		t.Fatalf("inbox body should carry alert_group_id, got %+v", pusher.bodies)
	}
}

func TestSecEventBridgeDoesNotGroupSuppressedEvent(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{secEventWithFindings("low-group", "audit", finding(0.10))}}
	pusher := &fakePusher{}
	groups := &fakeAlertGrouper{}

	n, err := gateBridge(src, pusher, &fakeNotifier{}, 0.5).WithAlertGroups(groups).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected suppressed event count 0, got %d", n)
	}
	if len(groups.inputs) != 0 {
		t.Fatalf("suppressed event should not upsert alert group: %+v", groups.inputs)
	}
}

func TestSecEventBridgeGroupsPassiveSemanticAsInformationalWithoutNotification(t *testing.T) {
	ev := secEventWithFindings("semantic-group", "security_audit_only",
		semanticFinding(0.90, "semantic_exfil_induce"))
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakePusher{}
	notifier := &fakeNotifier{}
	groups := &fakeAlertGrouper{}

	n, err := gateBridge(src, pusher, notifier, 0.5).
		WithAlertGroups(groups).
		RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(pusher.pushedTypes) != 0 || notifier.calls != 0 {
		t.Fatalf("passive semantic event must stay out of actionable delivery, n=%d pushed=%v notified=%d", n, pusher.pushedTypes, notifier.calls)
	}
	if len(groups.inputs) != 1 {
		t.Fatalf("passive semantic event should create one visible alert group, got %+v", groups.inputs)
	}
	input := groups.inputs[0]
	if input.DispositionClass != "informational" || input.ClassKey != "semantic_exfil_induce" {
		t.Fatalf("passive semantic group has wrong bucket/class: %+v", input)
	}
	if input.RequestID != ev.RequestID || input.RepresentativeEventID != ev.ID {
		t.Fatalf("passive semantic group lost event context: %+v", input)
	}
	if len(src.markedIDs) != 1 || len(src.markedIDs[0]) != 1 || src.markedIDs[0][0] != ev.ID {
		t.Fatalf("grouped semantic event must be marked processed, got %v", src.markedIDs)
	}
}

func TestSecEventBridgeGroupFailureLeavesEventUnalerted(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{secEventSha("group-fail", "sha_fail")}}
	pusher := &fakePusher{}
	groups := &fakeAlertGrouper{failNext: true}

	n, err := dedupBridge(src, pusher, &fakeNotifier{}, 0.5).WithAlertGroups(groups).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 alerts when group write fails, got %d", n)
	}
	if len(pusher.pushedTypes) != 0 || len(src.markedIDs) != 0 {
		t.Fatalf("group failure must not push inbox or mark alerted, pushed=%v marked=%v", pusher.pushedTypes, src.markedIDs)
	}
}
