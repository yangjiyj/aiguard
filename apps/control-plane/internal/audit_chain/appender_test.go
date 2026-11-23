package audit_chain

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type mockWriter struct {
	count         int64
	criticalCount int64
	criticalErr   error
	done          chan struct{}
}

func (m *mockWriter) AppendHeaderContractConflictOnce(_ context.Context, _, _ string, _ map[string]any) error {
	atomic.AddInt64(&m.criticalCount, 1)
	return m.criticalErr
}

func (m *mockWriter) Append(_ context.Context, _, _, _ string, _ map[string]any) error {
	atomic.AddInt64(&m.count, 1)
	select {
	case m.done <- struct{}{}:
	default:
	}
	return nil
}

func TestAppenderEnqueuesAndCalls(t *testing.T) {
	mock := &mockWriter{done: make(chan struct{}, 5)}
	a := NewAppender(mock, false)

	a.Enqueue("tenant1", "test_event", "evt_1", map[string]any{"x": 1})

	select {
	case <-mock.done:
	case <-time.After(2 * time.Second):
		t.Fatal("Append was not called within timeout")
	}

	if atomic.LoadInt64(&mock.count) != 1 {
		t.Fatalf("expected 1 call, got %d", atomic.LoadInt64(&mock.count))
	}
}

func TestAppenderDisabledSkips(t *testing.T) {
	mock := &mockWriter{done: make(chan struct{}, 5)}
	a := NewAppender(mock, true)

	a.Enqueue("tenant1", "test_event", "evt_2", map[string]any{"x": 2})

	// Give some time to ensure no call is made
	time.Sleep(200 * time.Millisecond)

	if atomic.LoadInt64(&mock.count) != 0 {
		t.Fatalf("expected 0 calls when disabled, got %d", atomic.LoadInt64(&mock.count))
	}
}

func TestAppenderMultipleEntries(t *testing.T) {
	mock := &mockWriter{done: make(chan struct{}, 10)}
	a := NewAppender(mock, false)

	for i := 0; i < 5; i++ {
		a.Enqueue("tenant1", "test_event", "evt_multi", map[string]any{"i": i})
	}

	// Wait for all 5
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt64(&mock.count) < 5 {
		if time.Now().After(deadline) {
			t.Fatalf("only got %d calls after timeout", atomic.LoadInt64(&mock.count))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAppenderAppendCriticalRequiresDurableAck(t *testing.T) {
	payload := map[string]any{"service": "control-plane.internal", "header_kind": "internal_token", "request_id": "req", "source_ip": ""}
	for _, tc := range []struct {
		name string
		a    *Appender
	}{
		{"nil", nil},
		{"disabled", NewAppender(&mockWriter{done: make(chan struct{}, 1)}, true)},
		{"missing-repo", NewAppender(nil, false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.a.AppendCritical(context.Background(), "", "event-id", payload); !errors.Is(err, ErrCriticalAuditUnavailable) {
				t.Fatalf("AppendCritical() error = %v", err)
			}
		})
	}

	mock := &mockWriter{done: make(chan struct{}, 1)}
	a := NewAppender(mock, false)
	if err := a.AppendCritical(context.Background(), "", "event-id", payload); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&mock.criticalCount); got != 1 {
		t.Fatalf("critical writes=%d, want 1", got)
	}
	if got := atomic.LoadInt64(&mock.count); got != 0 {
		t.Fatalf("critical append entered async writer: %d", got)
	}

	mock.criticalErr = errors.New("storage down")
	if err := a.AppendCritical(context.Background(), "", "event-id-2", payload); !errors.Is(err, ErrCriticalAuditUnavailable) {
		t.Fatalf("storage failure error=%v", err)
	}
}
