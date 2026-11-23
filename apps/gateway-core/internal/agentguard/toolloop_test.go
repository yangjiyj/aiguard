package agentguard

import (
	"testing"
	"time"
)

func TestToolFailureWindowThreshold(t *testing.T) {
	w := NewToolFailureWindow(10*time.Minute, 3)
	now := time.Now()
	actor := "actor-a"

	for i := 0; i < 2; i++ {
		count, reached := w.RecordFailure(ToolFailureEvent{ActorKey: actor, ToolName: "http_get", Now: now})
		if reached {
			t.Fatalf("threshold reached early at iteration %d", i)
		}
		if count != i+1 {
			t.Fatalf("count = %d, want %d", count, i+1)
		}
	}
	count, reached := w.RecordFailure(ToolFailureEvent{ActorKey: actor, ToolName: "http_get", Now: now})
	if !reached || count != 3 {
		t.Fatalf("third failure: count=%d reached=%v, want 3/true", count, reached)
	}
	if w.Count(actor, "http_get", now) != 3 {
		t.Fatalf("Count mismatch")
	}
	if w.Count(actor, "other_tool", now) != 0 {
		t.Fatalf("other tool should be isolated")
	}
}

func TestToolFailureWindowWindowExpiry(t *testing.T) {
	w := NewToolFailureWindow(1*time.Minute, 2)
	old := time.Now().Add(-2 * time.Minute)
	w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "t", Now: old})
	count, reached := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "t", Now: time.Now()})
	if reached || count != 1 {
		t.Fatalf("expired failure should not count: count=%d reached=%v", count, reached)
	}
}

func TestToolFailureWindowZeroValueNil(t *testing.T) {
	var w *ToolFailureWindow
	if count, reached := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "t", Now: time.Now()}); count != 0 || reached {
		t.Fatalf("nil window must be a no-op")
	}
	if w.Count("a", "t", time.Now()) != 0 {
		t.Fatalf("nil window Count must be 0")
	}
}

func TestToolResultLooksLikeFailure(t *testing.T) {
	positive := []string{
		`{"is_error": true, "content": "boom"}`,
		`Traceback (most recent call last):
  File "x.py", line 1
Error: something`,
		`{"status": "error", "message": "denied"}`,
		`Error: connection refused`,
		`Exception: timeout`,
		`{"success": false, "detail": "nope"}`,
		`{"error": "not found"}`,
	}
	negative := []string{
		`{"result": 42, "status": "ok"}`,
		`file read successfully: 1024 bytes`,
		``,
		`the word error appears here but not as a field or line prefix: no error seen`,
	}
	for _, c := range positive {
		if !ToolResultLooksLikeFailure(c) {
			t.Fatalf("expected failure detection for: %q", c)
		}
	}
	for _, c := range negative {
		if ToolResultLooksLikeFailure(c) {
			t.Fatalf("unexpected failure detection for: %q", c)
		}
	}
}

func TestToolFailureWindowCountsEachToolCallOnce(t *testing.T) {
	w := NewToolFailureWindow(10*time.Minute, 3)
	now := time.Now()
	for i := 0; i < 10; i++ {
		count, reached := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "call-1", Now: now})
		if count != 1 || reached {
			t.Fatalf("round %d: count=%d reached=%v, want 1/false", i, count, reached)
		}
	}
	w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "call-2", Now: now})
	count, reached := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "call-3", Now: now})
	if count != 3 || !reached {
		t.Fatalf("third distinct call: count=%d reached=%v, want 3/true", count, reached)
	}
	if count, reached := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "call-2", Now: now}); count != 3 || reached {
		t.Fatalf("replayed call: count=%d reached=%v, want 3/false", count, reached)
	}
	if got := w.Count("a", "Bash", now); got != 3 {
		t.Fatalf("Count=%d, want 3", got)
	}
}

func TestToolFailureWindowReportsThresholdOncePerEpisode(t *testing.T) {
	w := NewToolFailureWindow(10*time.Minute, 2)
	now := time.Now()
	w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "c1", Now: now})
	if _, reached := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "c2", Now: now}); !reached {
		t.Fatal("crossing the threshold must be reported")
	}
	if count, reached := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "c3", Now: now}); count != 3 || reached {
		t.Fatalf("failures beyond the threshold must not be reported again: count=%d reached=%v", count, reached)
	}
}

func TestToolFailureWindowDoesNotRecountReplayedHistoryAcrossWindows(t *testing.T) {
	w := NewToolFailureWindow(10*time.Minute, 3)
	t0 := time.Now()
	w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "c1", Now: t0})
	w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "c2", Now: t0})
	if _, reached := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "c3", Now: t0}); !reached {
		t.Fatal("third distinct call must reach the threshold")
	}
	for _, offset := range []time.Duration{11 * time.Minute, 22 * time.Minute, 60 * time.Minute} {
		at := t0.Add(offset)
		for _, target := range []string{"c1", "c2", "c3"} {
			count, reached := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: target, Now: at})
			if count != 0 || reached {
				t.Fatalf("replay of %s at +%s: count=%d reached=%v, want 0/false", target, offset, count, reached)
			}
		}
		if got := w.Count("a", "Bash", at); got != 0 {
			t.Fatalf("Count at +%s = %d, want 0", offset, got)
		}
	}
}

func TestToolFailureWindowReportsAgainForANewEpisodeAfterTheWindow(t *testing.T) {
	w := NewToolFailureWindow(10*time.Minute, 2)
	t0 := time.Now()
	w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "c1", Now: t0})
	if _, reached := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "c2", Now: t0}); !reached {
		t.Fatal("first episode must be reported")
	}
	later := t0.Add(11 * time.Minute)
	if count, reached := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "c3", Now: later}); count != 1 || reached {
		t.Fatalf("c3: count=%d reached=%v, want 1/false", count, reached)
	}
	if count, reached := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "c4", Now: later}); count != 2 || !reached {
		t.Fatalf("c4: count=%d reached=%v, want 2/true", count, reached)
	}
}

func TestToolFailureWindowIsolatesActorsAndToolsAndTrimsTargets(t *testing.T) {
	w := NewToolFailureWindow(10*time.Minute, 5)
	now := time.Now()
	if count, _ := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: "c1", Now: now}); count != 1 {
		t.Fatalf("a/Bash: count=%d, want 1", count)
	}
	if count, _ := w.RecordFailure(ToolFailureEvent{ActorKey: "b", ToolName: "Bash", Target: "c1", Now: now}); count != 1 {
		t.Fatalf("other actor: count=%d, want 1", count)
	}
	if count, _ := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Read", Target: "c1", Now: now}); count != 1 {
		t.Fatalf("other tool: count=%d, want 1", count)
	}
	if count, _ := w.RecordFailure(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: " c1 ", Now: now}); count != 1 {
		t.Fatalf("padded target must dedupe: count=%d, want 1", count)
	}
}
