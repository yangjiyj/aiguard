package billing

import (
	"sync"
	"time"
)

const reconciliationHeartbeatMaxAge = 2 * time.Minute

type ReconciliationWorkerSnapshot struct {
	Status          string
	ReasonCode      string
	LastStartedAt   time.Time
	LastCompletedAt time.Time
	Running         bool
	Result          ReconciliationResult
}

// ReconciliationMonitor records local worker activity without changing billing writes.
type ReconciliationMonitor struct {
	mu            sync.RWMutex
	required      bool
	stopped       bool
	failureReason string
	state         ReconciliationWorkerSnapshot
}

func NewReconciliationMonitor(required bool) *ReconciliationMonitor {
	return &ReconciliationMonitor{required: required}
}

func (m *ReconciliationMonitor) Start(at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.required {
		return
	}
	m.state.LastStartedAt = at.UTC()
	m.state.Running = true
	m.stopped = false
}

func (m *ReconciliationMonitor) Complete(at time.Time, result ReconciliationResult, err error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.required {
		return
	}
	m.state.LastCompletedAt = at.UTC()
	m.state.Result = result
	m.state.Running = false
	m.failureReason = ""
	if err != nil {
		m.failureReason = "execution_failed"
	} else if result.Failed > 0 {
		m.failureReason = "items_failed"
	}
}

func (m *ReconciliationMonitor) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopped = true
	m.state.Running = false
}

func (m *ReconciliationMonitor) Snapshot(now time.Time) ReconciliationWorkerSnapshot {
	if m == nil {
		return ReconciliationWorkerSnapshot{Status: "unknown", ReasonCode: "monitor_unavailable"}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	state := m.state
	switch {
	case !m.required:
		state.Status, state.ReasonCode = "disabled", "not_required"
	case m.stopped:
		state.Status, state.ReasonCode = "degraded", "worker_stopped"
	default:
		heartbeat := state.LastCompletedAt
		if state.LastStartedAt.After(heartbeat) {
			heartbeat = state.LastStartedAt
		}
		switch {
		case !heartbeat.IsZero() && now.Sub(heartbeat) > reconciliationHeartbeatMaxAge:
			state.Status, state.ReasonCode = "degraded", "heartbeat_stale"
		case state.Running:
			state.Status, state.ReasonCode = "processing", "running"
		case state.LastCompletedAt.IsZero():
			state.Status, state.ReasonCode = "processing", "awaiting_first_run"
		case m.failureReason != "":
			state.Status, state.ReasonCode = "degraded", m.failureReason
		default:
			state.Status, state.ReasonCode = "healthy", ""
		}
	}
	return state
}
