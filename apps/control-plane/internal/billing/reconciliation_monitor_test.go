package billing

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestReconciliationMonitorLifecycle(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	disabled := NewReconciliationMonitor(false)
	disabled.Start(now)
	disabled.Complete(now, ReconciliationResult{}, errors.New("ignored"))
	if got := disabled.Snapshot(now); got.Status != "disabled" || got.ReasonCode != "not_required" || got.Running {
		t.Fatalf("disabled worker = %+v", got)
	}
	m := NewReconciliationMonitor(true)
	if got := m.Snapshot(now); got.Status != "processing" || got.ReasonCode != "awaiting_first_run" {
		t.Fatalf("before startup = %+v", got)
	}
	m.Start(now)
	if got := m.Snapshot(now); got.Status != "processing" || !got.Running || !got.LastStartedAt.Equal(now) {
		t.Fatalf("first run = %+v", got)
	}
	completed := now.Add(time.Second)
	result := ReconciliationResult{Settled: 2, Released: 3, Pending: 4}
	m.Complete(completed, result, nil)
	if got := m.Snapshot(completed); got.Status != "healthy" || got.Running || got.Result != result || !got.LastCompletedAt.Equal(completed) {
		t.Fatalf("successful run (pending is not failure) = %+v", got)
	}
	if got := m.Snapshot(completed.Add(2 * time.Minute)); got.Status != "healthy" {
		t.Fatalf("fresh boundary = %+v", got)
	}
	if got := m.Snapshot(completed.Add(2*time.Minute + time.Nanosecond)); got.Status != "degraded" || got.ReasonCode != "heartbeat_stale" {
		t.Fatalf("stale heartbeat = %+v", got)
	}
	m.Start(completed.Add(time.Minute))
	if got := m.Snapshot(completed.Add(time.Minute)); got.Status != "processing" || !got.Running || got.Result != result {
		t.Fatalf("scheduled run retains prior result = %+v", got)
	}
	if got := m.Snapshot(completed.Add(3*time.Minute + time.Nanosecond)); got.Status != "degraded" || got.ReasonCode != "heartbeat_stale" || !got.Running {
		t.Fatalf("stuck run = %+v", got)
	}
	m.Stop()
	if got := m.Snapshot(completed); got.Status != "degraded" || got.ReasonCode != "worker_stopped" || got.Running {
		t.Fatalf("stopped = %+v", got)
	}
}

func TestReconciliationMonitorFailureAndRecovery(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		result ReconciliationResult
		err    error
		reason string
	}{
		{"query failure", ReconciliationResult{Pending: 1}, errors.New("postgres://private-secret"), "execution_failed"},
		{"isolated item failure", ReconciliationResult{Failed: 1}, nil, "items_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewReconciliationMonitor(true)
			m.Start(now)
			m.Complete(now.Add(time.Second), tc.result, tc.err)
			if got := m.Snapshot(now.Add(time.Second)); got.Status != "degraded" || got.ReasonCode != tc.reason || got.Result != tc.result {
				t.Fatalf("failure = %+v", got)
			}
			m.Start(now.Add(time.Minute))
			m.Complete(now.Add(time.Minute+time.Second), ReconciliationResult{}, nil)
			if got := m.Snapshot(now.Add(time.Minute + time.Second)); got.Status != "healthy" || got.ReasonCode != "" {
				t.Fatalf("recovery = %+v", got)
			}
		})
	}
}

func TestReconciliationMonitorConcurrentSnapshots(t *testing.T) {
	now := time.Now().UTC()
	m := NewReconciliationMonitor(true)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				m.Start(now)
				m.Complete(now, ReconciliationResult{Released: 1}, nil)
				_ = m.Snapshot(now)
			}
		}()
	}
	workers.Wait()
	if got := m.Snapshot(now); got.Status != "healthy" || got.Running || got.Result.Released != 1 {
		t.Fatalf("concurrent final snapshot = %+v", got)
	}
}
