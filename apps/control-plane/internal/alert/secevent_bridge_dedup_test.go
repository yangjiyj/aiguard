package alert

import (
	"context"
	"errors"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// fakeDedupPusher emulates the real UpsertByGroup folding: the first event for a
// group key opens a new alert (created=true); later events sharing that key are
// folded onto it (created=false). It records every call so tests can assert that
// repeats collapse onto one alert and that the legacy Push path is never taken.
type fakeDedupPusher struct {
	counts    map[string]int // group key -> occurrences folded in
	upserts   int            // total UpsertByGroup calls that succeeded
	pushCalls int            // legacy Push calls (should stay 0 on the dedup path)
	failNext  bool
}

func (f *fakeDedupPusher) Push(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL string) error {
	f.pushCalls++
	return nil
}

func (f *fakeDedupPusher) UpsertByGroup(ctx context.Context, tenantID, severity, typ, title string, body map[string]any, targetURL, groupKey string) (bool, error) {
	if f.failNext {
		f.failNext = false
		return false, errors.New("inbox down")
	}
	if f.counts == nil {
		f.counts = map[string]int{}
	}
	f.upserts++
	f.counts[groupKey]++
	created := f.counts[groupKey] == 1
	return created, nil
}

// findingSha builds a finding carrying the engine's content hash, which is what
// makes two events "the same leak" for grouping purposes.
func findingSha(confidence float64, sha string) map[string]any {
	return map[string]any{
		"confidence":                  confidence,
		"matched_text_preview_sha256": sha,
	}
}

func findingDataLeakRaw(confidence float64, raw string) map[string]any {
	return map[string]any{
		"type":         "data_leak",
		"category":     "classified_classified_en",
		"rule_id":      "rule_d40b2e17",
		"confidence":   confidence,
		"raw_evidence": raw,
	}
}

// secEventSha is a passive audit event whose single finding leaks the secret
// identified by sha, at a confidence safely above the test floor.
func secEventSha(id, sha string) *repository.SecurityEvent {
	return secEventWithFindings(id, "audit", findingSha(0.90, sha))
}

// dedupBridge builds a bridge with dedup explicitly on and a fixed confidence
// floor, independent of the environment.
func dedupBridge(src secEventSource, inbox secInboxPusher, notifier secNotifier, floor float64) *SecEventBridge {
	b := NewSecEventBridge(src, inbox, notifier)
	b.minConfidence = floor
	b.dedup = true
	return b
}

func TestSecEventBridge_DedupFoldsRepeatLeaks(t *testing.T) {
	// The same secret seen on three different requests must collapse onto ONE
	// inbox alert and notify exactly once — yet all three events are marked
	// alerted so none is re-scanned.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventSha("e1", "sha_aaa"),
		secEventSha("e2", "sha_aaa"),
		secEventSha("e3", "sha_aaa"),
	}}
	pusher := &fakeDedupPusher{}
	notifier := &fakeNotifier{}

	n, err := dedupBridge(src, pusher, notifier, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 new alert for 3 identical leaks, got %d", n)
	}
	if pusher.upserts != 3 {
		t.Fatalf("expected 3 upserts (3 events folded into one group), got %d", pusher.upserts)
	}
	if len(pusher.counts) != 1 {
		t.Fatalf("expected all events in one group, got %d groups", len(pusher.counts))
	}
	if notifier.calls != 1 {
		t.Fatalf("expected exactly 1 external notify (only the new alert), got %d", notifier.calls)
	}
	if pusher.pushCalls != 0 {
		t.Fatalf("dedup path must not use legacy Push, got %d calls", pusher.pushCalls)
	}
	if len(src.markedIDs) != 1 || len(src.markedIDs[0]) != 3 {
		t.Fatalf("expected all 3 events marked alerted in one batch, got %v", src.markedIDs)
	}
}

func TestSecEventBridge_DedupDistinctLeaksEachAlert(t *testing.T) {
	// Two genuinely different secrets must each open their own alert.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventSha("e1", "sha_aaa"),
		secEventSha("e2", "sha_bbb"),
	}}
	pusher := &fakeDedupPusher{}
	notifier := &fakeNotifier{}

	n, err := dedupBridge(src, pusher, notifier, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 new alerts for 2 distinct leaks, got %d", n)
	}
	if len(pusher.counts) != 2 {
		t.Fatalf("expected 2 distinct groups, got %d", len(pusher.counts))
	}
	if notifier.calls != 2 {
		t.Fatalf("expected 2 external notifies, got %d", notifier.calls)
	}
}

func TestEventGroupKeyUsesRawEvidenceForDataLeakWhenNoEngineHash(t *testing.T) {
	classified := eventGroupKey(secEventWithFindings("e-classified", "audit", findingDataLeakRaw(0.90, "classified")))
	confidential := eventGroupKey(secEventWithFindings("e-confidential", "audit", findingDataLeakRaw(0.90, "confidential")))
	repeat := eventGroupKey(secEventWithFindings("e-repeat", "audit", findingDataLeakRaw(0.90, " confidential ")))

	if classified == confidential {
		t.Fatalf("different classified evidence words must not collapse into one group: %s", classified)
	}
	if confidential != repeat {
		t.Fatalf("same raw evidence should still dedup after normalization: %s != %s", confidential, repeat)
	}
}

func TestSecEventBridge_DedupOffPushesPerEvent(t *testing.T) {
	// With dedup disabled, the legacy one-row-per-event path is restored even for
	// identical leaks.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventSha("e1", "sha_aaa"),
		secEventSha("e2", "sha_aaa"),
		secEventSha("e3", "sha_aaa"),
	}}
	pusher := &fakeDedupPusher{}
	notifier := &fakeNotifier{}

	b := dedupBridge(src, pusher, notifier, 0.5)
	b.dedup = false
	n, err := b.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 rows with dedup off, got %d", n)
	}
	if pusher.pushCalls != 3 {
		t.Fatalf("expected 3 legacy Push calls, got %d", pusher.pushCalls)
	}
	if pusher.upserts != 0 {
		t.Fatalf("expected no upserts when dedup is off, got %d", pusher.upserts)
	}
	if notifier.calls != 3 {
		t.Fatalf("expected 3 notifies (one per row) with dedup off, got %d", notifier.calls)
	}
}

func TestSecEventBridge_DedupUpsertFailureLeavesUnalerted(t *testing.T) {
	// A failed upsert must leave the event unalerted (retried next cycle) and not
	// notify.
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{secEventSha("e1", "sha_aaa")}}
	pusher := &fakeDedupPusher{failNext: true}
	notifier := &fakeNotifier{}

	n, err := dedupBridge(src, pusher, notifier, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 alerted when upsert fails, got %d", n)
	}
	if notifier.calls != 0 {
		t.Fatalf("expected no notify when upsert failed, got %d", notifier.calls)
	}
	if len(src.markedIDs) != 0 {
		t.Fatalf("expected event NOT marked alerted when upsert fails, got %v", src.markedIDs)
	}
}
