package alert

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func canaryFinding() map[string]any {
	return map[string]any{
		"confidence": 0.95,
		"category":   "agent_canary_token_leak",
		"type":       "content_safety",
	}
}

// M3：canary 组被人工处置为误报后，同组的真 canary 事件在 30 天有效期内也必须照常提升——
func TestRedline_CanaryPiercesFPSilence(t *testing.T) {
	ev := secEventWithFindings("canary_fp", "audit", canaryFinding())
	key := eventGroupKey(ev)
	fp := &fakeFPDispositions{keys: map[string]map[string]bool{"tenant_x": {key: true}}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakeDedupPusher{}

	n, err := fpBridge(src, pusher, &fakeNotifier{}, 30, fp).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || pusher.upserts != 1 {
		t.Fatalf("canary must pierce fp-disposition silence, got n=%d upserts=%d", n, pusher.upserts)
	}
}

// M3/G2：输出侧事件（stage=output，模型吐出内容）被处置为误报后，也必须照常提升——
// 输出侧是真泄露面，永不进抑制批次。
func TestRedline_OutputStagePiercesFPSilence(t *testing.T) {
	ev := secEventWithFindings("out_fp", "audit", findingSha(0.90, "sha_out"))
	ev.MatchedSummary["stage"] = "output"
	key := eventGroupKey(ev)
	fp := &fakeFPDispositions{keys: map[string]map[string]bool{"tenant_x": {key: true}}}
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakeDedupPusher{}

	n, err := fpBridge(src, pusher, &fakeNotifier{}, 30, fp).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || pusher.upserts != 0 {
		t.Fatalf("output-stage must remain suppressible without verified content, got n=%d upserts=%d", n, pusher.upserts)
	}
}

// M3：canary 即使其 category 被配置为基线抑制（shouldSurface 的 noise 闸），也必须照常提升。
func TestRedline_CanaryPiercesBaselineSuppression(t *testing.T) {
	ev := secEventWithFindings("canary_base", "audit", canaryFinding())
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakePusher{}

	b := catBridge(src, pusher, &fakeNotifier{}, 0.5, "agent_canary_token_leak")
	n, err := b.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(pusher.pushedTypes) != 1 {
		t.Fatalf("canary must pierce baseline suppression, got n=%d pushed=%v", n, pusher.pushedTypes)
	}
}

// 算入 UpsertOpen 入参。class_key = 最高严重度 finding 的 category（并列取高置信）。
func TestLifecycleFields_ComputedIntoUpsert(t *testing.T) {
	ev := secEventWithFindings("lc1", "audit",
		map[string]any{"confidence": 0.99, "": true, "category": "openai_key", "type": "secret", "severity": "critical"},
		map[string]any{"confidence": 0.85, "": false, "category": "env_file", "type": "code_config", "severity": "medium"},
	)
	ev.MatchedSummary["stage"] = "output"
	ev.Severity = "critical"
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	groups := &fakeAlertGrouper{}

	_, err := gateBridge(src, &fakePusher{}, &fakeNotifier{}, 0.5).WithAlertGroups(groups).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(groups.inputs) != 1 {
		t.Fatalf("expected 1 upsert, got %d", len(groups.inputs))
	}
	in := groups.inputs[0]
	if in.IsCanary {
		t.Errorf("IsCanary=true want false")
	}
	if in.Stage != "output" {
		t.Errorf("Stage=%q want output", in.Stage)
	}
	if in.ClassKey != "openai_key" {
		t.Errorf("ClassKey=%q want openai_key (dominant=critical secret)", in.ClassKey)
	}
	if in.EffectiveSeverity != "critical" {
		t.Errorf("EffectiveSeverity=%q want critical", in.EffectiveSeverity)
	}
	if in.DispositionClass != "action_required" {
		t.Errorf("DispositionClass=%q want action_required", in.DispositionClass)
	}
}

// canary 事件的 UpsertOpen 入参 IsCanary=true、class_key 为 canary 类别。
func TestLifecycleFields_CanaryFlag(t *testing.T) {
	ev := secEventWithFindings("lc_canary", "audit", canaryFinding())
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	groups := &fakeAlertGrouper{}

	_, err := gateBridge(src, &fakePusher{}, &fakeNotifier{}, 0.5).WithAlertGroups(groups).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(groups.inputs) != 1 || !groups.inputs[0].IsCanary {
		t.Fatalf("expected IsCanary=true on upsert, got %+v", groups.inputs)
	}
	if groups.inputs[0].ClassKey != "agent_canary_token_leak" {
		t.Errorf("ClassKey=%q want agent_canary_token_leak", groups.inputs[0].ClassKey)
	}
}
func TestDominantCategoryIgnoresObservationFindings(t *testing.T) {
	ev := secEventWithFindings("dominant-actionable", "audit",
		map[string]any{
			"confidence":                 0.99,
			"category":                   "phone_cn",
			"type":                       "pii",
			"severity":                   "critical",
			"counts_as_security_finding": false,
		},
		map[string]any{
			"confidence":                 0.80,
			"category":                   "openai_key",
			"type":                       "secret",
			"severity":                   "high",
			"counts_as_security_finding": true,
		},
	)

	if got := dominantCategory(ev); got != "openai_key" {
		t.Fatalf("dominantCategory=%q, want actionable openai_key", got)
	}
}

func TestDominantCategoryFallsBackWhenAllFindingsAreObservations(t *testing.T) {
	ev := secEventWithFindings("observation-only", "security_check",
		map[string]any{
			"confidence":                 0.99,
			"category":                   "phone_cn",
			"type":                       "pii",
			"severity":                   "critical",
			"counts_as_security_finding": false,
		},
	)

	if got := dominantCategory(ev); got != ev.EventType {
		t.Fatalf("dominantCategory=%q, want event type %q for observation-only event", got, ev.EventType)
	}
}

func TestRedline_SecretAndVerifiedPIIPierceFPSilence(t *testing.T) {
	cases := []map[string]any{
		{"type": "secret", "category": "openai_key", "confidence": 0.99},
		{"type": "data_leak", "category": "pii_id_card", "verified_fact": true, "confidence": 0.99},
	}
	for i, finding := range cases {
		ev := secEventWithFindings("redline-fp", "audit", finding)
		key := eventGroupKey(ev)
		src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
		pusher := &fakeDedupPusher{}
		n, err := fpBridge(src, pusher, &fakeNotifier{}, 30, &fakeFPDispositions{keys: map[string]map[string]bool{"tenant_x": {key: true}}}).RunOnce(context.Background())
		if err != nil || n != 1 || pusher.upserts != 1 {
			t.Fatalf("case %d must pierce FP silence: n=%d upserts=%d err=%v", i, n, pusher.upserts, err)
		}
	}
}
