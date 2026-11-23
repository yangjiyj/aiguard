package alert

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// findingTriaged builds a finding carrying an LLM-triage verdict, mirroring the
// live jsonb shape written back by AnnotateTriage (matched_summary.findings[].triage).
func findingTriaged(verdict string) map[string]any {
	return map[string]any{
		"confidence": 0.9, "category": "semantic_jailbreak",
		"type":   "prompt_injection",
		"triage": map[string]any{"verdict": verdict},
	}
}

// gateBridgeForTriage builds a bridge with the gate open (minConfidence>0) so the
// per-finding evaluation runs; the triage gate is independent of the noise gate.
func gateBridgeForTriage() *SecEventBridge {
	return gateBridge(&fakeSecEventSource{}, &fakePusher{}, nil, 0.5)
}

func TestShouldSurface_SuppressesLikelyFalsePositive(t *testing.T) {
	b := gateBridgeForTriage()
	ev := secEventWithFindings("fp1", "audit", findingTriaged("likely_false_positive"))
	ok, reason := b.shouldSurface(ev)
	if ok {
		t.Fatalf("likely_false_positive triage must be suppressed, got surface=true")
	}
	if reason != "LLM triage: likely_false_positive" {
		t.Fatalf("reason = %q, want \"LLM triage: likely_false_positive\"", reason)
	}
}
func TestShouldSurface_ConfirmedRiskTriageStillSurfaces(t *testing.T) {
	b := gateBridgeForTriage()
	ev := secEventWithFindings("cr1", "audit", findingTriaged("confirmed_risk"))
	ok, _ := b.shouldSurface(ev)
	if !ok {
		t.Fatalf("confirmed_risk triage must NOT be suppressed")
	}
}

func TestShouldSurface_MixedFPandSignalSurfaces(t *testing.T) {
	b := gateBridgeForTriage()
	// 一条被压(likely_fp) + 一条高置信无 triage 信号 → 整事件仍提升（不能因一条 FP 藏掉真信号）。
	ev := secEventWithFindings("mix1", "audit",
		findingTriaged("likely_false_positive"),
		findingCat(0.95, "semantic_jailbreak"),
	)
	ok, _ := b.shouldSurface(ev)
	if !ok {
		t.Fatalf("event with a real signal finding must surface despite one FP finding")
	}
}

func TestRunOnce_CountsTriageSuppressed(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		secEventWithFindings("fp1", "audit", findingTriaged("likely_false_positive")),
	}}
	pusher := &fakePusher{}
	b := gateBridge(src, pusher, nil, 0.5)
	pushed, err := b.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce err: %v", err)
	}
	if pushed != 0 {
		t.Fatalf("likely_fp event must not be pushed, pushed=%d", pushed)
	}
	if len(pusher.pushedTypes) != 0 {
		t.Fatalf("inbox must stay empty for triage-suppressed event")
	}
}

func TestShouldSurface_AuditEvidenceIsNotInboxAlert(t *testing.T) {
	b := gateBridgeForTriage()
	ev := secEventWithFindings("audit-evidence", "security_audit", map[string]any{
		"type": "pii", "category": "pii_phone", "confidence": 0.95,
		"triage": map[string]any{"verdict": "audit_evidence", "review_state": "audit_evidence"},
	})
	if ok, _ := b.shouldSurface(ev); ok {
		t.Fatal("audit_evidence must remain evidence without an inbox alert")
	}
}

func TestShouldSurface_OutputLowConfidenceIsNotAutomaticRedline(t *testing.T) {
	b := gateBridge(&fakeSecEventSource{}, &fakePusher{}, nil, 0.5)
	ev := secEventWithFindings("output-no-redline", "security_audit", findingCat(0.2, "pii_phone"))
	ev.MatchedSummary["stage"] = "output"
	if ok, _ := b.shouldSurface(ev); ok {
		t.Fatal("output stage alone must not bypass low-confidence suppression")
	}
}

func TestRunOnce_ReviewPendingWaitsWithoutMarking(t *testing.T) {
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{
		func() *repository.SecurityEvent {
			ev := secEventWithFindings("pending", "security_audit", map[string]any{
				"type": "pii", "category": "pii_phone", "confidence": 0.95,
				"content_source": "verified_user_input", "review_state": "review_pending",
			})
			ev.CreatedAt = time.Now().UTC()
			return ev
		}(),
	}}
	n, err := gateBridge(src, &fakePusher{}, nil, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(src.markedIDs) != 0 {
		t.Fatalf("pending review must wait for triage, got n=%d marked=%v", n, src.markedIDs)
	}
}

func TestRunOnce_StaleReviewPendingSurfacesAsNeedsReview(t *testing.T) {
	ev := secEventWithFindings("stale-pending", "security_audit", map[string]any{
		"type": "pii", "category": "pii_phone", "confidence": 0.95,
		"content_source": "verified_user_input", "review_state": "review_pending",
	})
	ev.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	src := &fakeSecEventSource{events: []*repository.SecurityEvent{ev}}
	pusher := &fakeDedupPusher{}
	n, err := gateBridge(src, pusher, nil, 0.5).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || pusher.upserts != 1 || len(src.markedIDs) != 1 {
		t.Fatalf("stale pending must surface for manual review, n=%d upserts=%d marked=%v", n, pusher.upserts, src.markedIDs)
	}
}
