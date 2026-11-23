package relay

import (
	"context"
	"testing"
	"time"
)

func TestCommitTrackerCannotRetryAfterFirstEvent(t *testing.T) {
	var tracker CommitTracker
	if err := tracker.Transition(CommitHeadersCommitted); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Transition(CommitFirstEventFlushed); err != nil {
		t.Fatal(err)
	}
	if tracker.CanRetry() {
		t.Fatal("retry must be disabled after first event flush")
	}
	if err := tracker.Transition(CommitNotStarted); err == nil {
		t.Fatal("commit state must be monotonic")
	}
}

func TestCommitTrackerRejectsInvalidAndTerminalTransitions(t *testing.T) {
	tests := []struct {
		name    string
		current CommitState
		next    CommitState
	}{
		{name: "completed cannot abort", current: CommitCompleted, next: CommitAborted},
		{name: "aborted cannot complete", current: CommitAborted, next: CommitCompleted},
		{name: "not started cannot abort", current: CommitNotStarted, next: CommitAborted},
		{name: "unknown state rejected", current: CommitNotStarted, next: CommitState("future_state")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := &CommitTracker{}
			if tt.current != CommitNotStarted {
				if err := tracker.Transition(CommitHeadersCommitted); err != nil {
					t.Fatal(err)
				}
				if err := tracker.Transition(CommitFirstEventFlushed); err != nil {
					t.Fatal(err)
				}
				if err := tracker.Transition(tt.current); err != nil {
					t.Fatal(err)
				}
			}
			if err := tracker.Transition(tt.next); err == nil {
				t.Fatalf("transition %s -> %s was accepted", tt.current, tt.next)
			}
			if got := tracker.State(); got != tt.current {
				t.Fatalf("state changed to %s, want %s", got, tt.current)
			}
		})
	}
}

func TestNormalizeOutputSecurityModeReturnsCanonicalValues(t *testing.T) {
	tests := map[string]OutputSecurityMode{
		"":                  OutputSecurityStreamEnforce,
		"STRICT_BUFFERED":   OutputSecurityStrictBuffered,
		" strict_buffered ": OutputSecurityStrictBuffered,
		"STREAM_ENFORCE":    OutputSecurityStreamEnforce,
		" stream_audit ":    OutputSecurityStreamAudit,
	}
	for input, want := range tests {
		if got := NormalizeOutputSecurityMode(input); got != want {
			t.Fatalf("NormalizeOutputSecurityMode(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestEventQueueAppliesBackpressure(t *testing.T) {
	queue := NewEventQueue(1)
	defer queue.Close()
	if err := queue.Push(context.Background(), StreamEvent{Type: EventTextDelta, Delta: "first"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := queue.Push(ctx, StreamEvent{Type: EventTextDelta, Delta: "second"}); err == nil {
		t.Fatal("a full queue must block instead of reading without bound")
	}
}
