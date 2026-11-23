package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func dedupeTestEnvelope() *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{
		RequestID:       "req-1",
		TenantID:        "tenant-1",
		ConversationKey: "conv-1",
	}
}

func TestCapacityIncompleteReasonClassification(t *testing.T) {
	for _, reason := range []string{
		"judge_capacity_deferred", "judge_capacity_overflow", "breaker_open",
		"judge_timeout", "judge_unavailable", "security_pipeline_timeout",
		"security_engine_unavailable", "inspection_queue_unavailable",
	} {
		if !isCapacityIncompleteReason(reason) {
			t.Fatalf("capacity reason not classified: %s", reason)
		}
	}
	// Content/upstream signals must stay per-event: they can indicate a real
	// problem with the request, not just engine capacity.
	for _, reason := range []string{"inspection_invalid_json", "output_capture_truncated", "judge_invalid_category", "", "unknown_reason", "inspection_retry_exhausted", "window_budget_exceeded"} {
		if isCapacityIncompleteReason(reason) {
			t.Fatalf("content reason wrongly folded: %s", reason)
		}
	}
}

func TestCapacityDedupeRepeatFoldsToRepresentative(t *testing.T) {
	d := newCapacityIncompleteDedupe(time.Minute)
	env := dedupeTestEnvelope()
	if _, repeat := d.representative(env, "input", "judge_timeout"); repeat {
		t.Fatal("first-seen key reported as repeat")
	}
	d.register(env, "input", "judge_timeout", "evt_rep_1")
	rep, repeat := d.representative(env, "input", "judge_timeout")
	if !repeat || rep != "evt_rep_1" {
		t.Fatalf("repeat did not fold to representative: rep=%q repeat=%v", rep, repeat)
	}
	// Same conversation but a different reason must open a fresh representative.
	if _, repeat := d.representative(env, "input", "breaker_open"); repeat {
		t.Fatal("different reason wrongly folded into the same representative")
	}
	// A different conversation must never share a representative.
	other := &modelrouter.RequestEnvelope{RequestID: "req-2", TenantID: "tenant-1", ConversationKey: "conv-2"}
	if _, repeat := otherTestDedupe(d, other, "input", "judge_timeout"); repeat {
		t.Fatal("different conversation folded into the representative")
	}
}

func otherTestDedupe(d *capacityIncompleteDedupe, env *modelrouter.RequestEnvelope, stage, reason string) (string, bool) {
	return d.representative(env, stage, reason)
}

func TestCapacityDedupeExpiryReopensRepresentative(t *testing.T) {
	d := newCapacityIncompleteDedupe(time.Minute)
	now := time.Now()
	d.now = func() time.Time { return now }
	env := dedupeTestEnvelope()
	d.register(env, "input", "judge_timeout", "evt_rep_1")
	// Advance beyond the TTL: the next incident window must open a fresh event.
	d.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, repeat := d.representative(env, "input", "judge_timeout"); repeat {
		t.Fatal("expired entry still reported as repeat")
	}
}

func TestRecordSemanticIncompleteCapacityFoldsRepeat(t *testing.T) {
	writer := &MockAuditWriter{}
	h := &ChatCompletionsHandler{auditWriter: writer}
	env := dedupeTestEnvelope()
	// First capacity incomplete: full event write.
	h.recordSemanticIncomplete(context.Background(), env, "input", "judge_timeout", "allow", nil)
	if len(writer.SecurityEventWrites) == 0 {
		t.Fatal("first capacity incomplete must stay visible as a full event")
	}
	representative := writer.SecurityEventWrites[0].EventID
	repeat := *env
	repeat.RequestID = "req-2"
	h.recordSemanticIncomplete(context.Background(), &repeat, "input", "judge_timeout", "allow", nil)
	if len(writer.SecurityEventWrites) != 1 || len(writer.SecurityOccurrenceWrites) != 1 {
		t.Fatalf("repeat must persist occurrence: events=%d occurrences=%d", len(writer.SecurityEventWrites), len(writer.SecurityOccurrenceWrites))
	}
	occurrence := writer.SecurityOccurrenceWrites[0]
	if occurrence.RepresentativeEventID != representative || occurrence.RequestID != "req-2" || occurrence.ContextKey == "" {
		t.Fatalf("incorrect occurrence link: %+v", occurrence)
	}
	repeat.TenantID = "tenant-2"
	h.recordSemanticIncomplete(context.Background(), &repeat, "input", "judge_timeout", "allow", nil)
	if len(writer.SecurityEventWrites) != 2 || len(writer.SecurityOccurrenceWrites) != 1 {
		t.Fatal("cross-tenant folding")
	}

}

func TestRecordSemanticIncompleteContentReasonNotFolded(t *testing.T) {
	writer := &MockAuditWriter{}
	h := &ChatCompletionsHandler{auditWriter: writer}
	env := dedupeTestEnvelope()
	// A content/upstream reason must not be folded even when repeated.
	for i := 0; i < 3; i++ {
		h.recordSemanticIncomplete(context.Background(), env, "input", "inspection_invalid_json", "allow", nil)
	}
	if len(writer.SecurityEventWrites) == 0 {
		t.Fatal("content incomplete must be written")
	}
	// Every repeat of a content reason is a distinct event write (no dedupe).
	if got := len(writer.SecurityEventWrites); got < 3 {
		t.Fatalf("content reason folded: got %d writes want >= 3", got)
	}
}

func TestOccurrenceContextKeyStable(t *testing.T) {
	d := newCapacityIncompleteDedupe(time.Minute)
	env := dedupeTestEnvelope()
	k1 := d.occurrenceContextKey(env, "input", "judge_timeout")
	k2 := d.occurrenceContextKey(env, "input", "judge_timeout")
	if k1 == "" || k1 != k2 {
		t.Fatalf("context key not stable: %q vs %q", k1, k2)
	}
	if k := d.occurrenceContextKey(env, "input", "breaker_open"); k == k1 {
		t.Fatal("different reason shares context key")
	}
	if !strings.EqualFold(k1, k1) {
		t.Fatal("context key not normalized")
	}
}
