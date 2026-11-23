package alert

import (
	"context"
	"errors"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// fakeSecEventSource emulates the security-event cursor: once a batch is marked
// alerted it stops returning those events, mirroring the alerted_at column.
type fakeSecEventSource struct {
	events    []*repository.SecurityEvent
	markedIDs [][]string
	fetchErr  error
	markErr   error
}

func (f *fakeSecEventSource) ListUnalerted(ctx context.Context, limit int) ([]*repository.SecurityEvent, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.events, nil
}

func (f *fakeSecEventSource) MarkAlerted(ctx context.Context, ids []string) error {
	if f.markErr != nil {
		return f.markErr
	}
	f.markedIDs = append(f.markedIDs, ids)
	f.events = nil // cursor advances: these rows are no longer unalerted
	return nil
}

type fakePusher struct {
	pushedTypes []string
	failNext    bool
}

func (f *fakePusher) Push(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL string) error {
	if f.failNext {
		f.failNext = false
		return errors.New("inbox down")
	}
	f.pushedTypes = append(f.pushedTypes, typ)
	return nil
}

// UpsertByGroup is the dedup-path entry point. This fake does not actually fold
// repeats (every call reports created=true), so the gate/legacy tests that drive
// distinct events through the default-on dedup path behave exactly as before:
// one recorded push per surfaced event. Dedup folding is exercised separately by
// fakeDedupPusher in secevent_bridge_dedup_test.go.
func (f *fakePusher) UpsertByGroup(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL, groupKey string) (bool, error) {
	if f.failNext {
		f.failNext = false
		return false, errors.New("inbox down")
	}
	f.pushedTypes = append(f.pushedTypes, typ)
	return true, nil
}

type fakeNotifier struct {
	calls     int
	lastErr   error
	lastTitle string
	lastBody  map[string]any
}

func (f *fakeNotifier) Dispatch(ctx context.Context, tenantID, severity, title string, body map[string]any) error {
	f.calls++
	f.lastTitle = title
	f.lastBody = body
	return f.lastErr
}

func sampleSecEvent(id string) *repository.SecurityEvent {
	return &repository.SecurityEvent{
		ID:             id,
		TenantID:       "tenant_x",
		ProjectID:      "proj_x",
		RequestID:      "req_" + id,
		EventType:      "prompt_injection",
		Severity:       "high",
		ActionTaken:    "block",
		MatchedSummary: map[string]interface{}{"rule": "pi-001"},
	}
}

func TestSecEventBridge_PushesInboxDispatchesAndMarksAlerted(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{sampleSecEvent("evt1")}}
	pusher := &fakePusher{}
	notifier := &fakeNotifier{}

	n, err := NewSecEventBridge(src, pusher, notifier).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 event alerted, got %d", n)
	}
	if len(pusher.pushedTypes) != 1 || pusher.pushedTypes[0] != "security_event" {
		t.Fatalf("expected inbox push of type security_event, got %v", pusher.pushedTypes)
	}
	if notifier.calls != 1 {
		t.Fatalf("expected 1 external dispatch, got %d", notifier.calls)
	}
	if len(src.markedIDs) != 1 || len(src.markedIDs[0]) != 1 || src.markedIDs[0][0] != "evt1" {
		t.Fatalf("expected evt1 marked alerted, got %v", src.markedIDs)
	}
}

func TestSecEventBridge_NoEventsIsNoop(t *testing.T) {
	src := &fakeSecEventSource{}
	pusher := &fakePusher{}
	notifier := &fakeNotifier{}

	n, err := NewSecEventBridge(src, pusher, notifier).RunOnce(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("expected noop, got n=%d err=%v", n, err)
	}
	if len(pusher.pushedTypes) != 0 || notifier.calls != 0 || len(src.markedIDs) != 0 {
		t.Fatalf("expected no side effects on empty batch")
	}
}

func TestSecEventBridge_InboxFailureLeavesEventUnalerted(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{sampleSecEvent("evt1")}}
	pusher := &fakePusher{failNext: true}
	notifier := &fakeNotifier{}

	n, err := NewSecEventBridge(src, pusher, notifier).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 alerted when inbox push fails, got %d", n)
	}
	if notifier.calls != 0 {
		t.Fatalf("expected no dispatch when inbox push failed, got %d", notifier.calls)
	}
	if len(src.markedIDs) != 0 {
		t.Fatalf("expected event NOT marked alerted when inbox fails, got %v", src.markedIDs)
	}
}

func TestSecEventBridge_DispatchFailureStillMarksAlerted(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{sampleSecEvent("evt1")}}
	pusher := &fakePusher{}
	notifier := &fakeNotifier{lastErr: errors.New("smtp down")}

	n, err := NewSecEventBridge(src, pusher, notifier).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected event still alerted despite dispatch failure, got %d", n)
	}
	if len(src.markedIDs) != 1 || src.markedIDs[0][0] != "evt1" {
		t.Fatalf("expected evt1 marked alerted, got %v", src.markedIDs)
	}
}

func TestSecEventBridge_FetchErrorPropagates(t *testing.T) {
	src := &fakeSecEventSource{fetchErr: errors.New("db down")}
	n, err := NewSecEventBridge(src, &fakePusher{}, &fakeNotifier{}).RunOnce(context.Background())
	if err == nil {
		t.Fatalf("expected error to propagate")
	}
	if n != 0 {
		t.Fatalf("expected 0 alerted on fetch error, got %d", n)
	}
}

func TestEventTypeLabelCN_Semantic(t *testing.T) {
	if eventTypeLabelCN("semantic_attack") != "语义攻击" {
		t.Fatal("semantic_attack 中文缺失")
	}
}
func TestActionLabelCN_SecurityAuditOnly(t *testing.T) {
	if actionLabelCN("security_audit_only") == "security_audit_only" {
		t.Fatal("security_audit_only 未中文化（标题会泄漏英文）")
	}
}
func TestActionLabelCN_SecurityOutputCheckFailed(t *testing.T) {
	if actionLabelCN("security_output_check_failed") == "security_output_check_failed" {
		t.Fatal("security_output_check_failed 未中文化（输出侧检测失败告警标题会泄漏英文）")
	}
}

func TestEventDisplayLabelUsesSpecificSemanticCategory(t *testing.T) {
	cases := map[string]string{
		"semantic_harassment":           "语义骚扰",
		"semantic_threat":               "语义威胁",
		"semantic_hate":                 "语义仇恨",
		"semantic_jailbreak":            "语义越狱",
		"semantic_roleplay":             "角色扮演绕过",
		"semantic_instruction_override": "指令覆盖",
		"semantic_exfil_induce":         "数据外泄诱导",
	}
	for category, want := range cases {
		event := &repository.SecurityEvent{
			EventType: "semantic_attack",
			MatchedSummary: map[string]any{
				"findings": []any{map[string]any{"category": category}},
			},
		}
		if got := eventDisplayLabelCN(event); got != want {
			t.Fatalf("category=%s label=%q want=%q", category, got, want)
		}
	}
	fallback := &repository.SecurityEvent{EventType: "semantic_attack", MatchedSummary: map[string]any{}}
	if got := eventDisplayLabelCN(fallback); got != "语义攻击" {
		t.Fatalf("fallback label=%q", got)
	}
}
