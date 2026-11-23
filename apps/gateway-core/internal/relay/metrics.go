package relay

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
)

var metricNames = []string{
	"requests",
	"status",
	"client_protocol",
	"upstream_protocol",
	"active_streams",
	"ttft_ms",
	"input_security_ms",
	"output_security_ms",
	"upstream_ms",
	"total_ms",
	"total_duration_ms",
	"upstream_duration_ms",
	"stream_events",
	"buffer_bytes",
	"backpressure",
	"client_cancel",
	"upstream_cancel",
	"route_ineligible",
	"provider_error",
	"retry",
	"fallback",
	"circuit",
	"snapshot_hit",
	"snapshot_miss",
	"hotpath_db_query",
	"billing_reserve",
	"billing_settle",
	"billing_release",
	"scan_cache_hit",
	"scan_cache_miss",
	"prompt_cache_hit",
	"prompt_cache_write",
	"output_scan_incomplete",
	"stream_aborted",
	"security_check_failed",
	"agent_endpoint_tool_audit_failed",
}

type Metrics struct {
	mu       sync.RWMutex
	counters map[string]*atomic.Uint64
	active   atomic.Int64
}

func NewMetrics() *Metrics {
	m := &Metrics{counters: make(map[string]*atomic.Uint64, len(metricNames))}
	for _, name := range metricNames {
		m.counters[name] = &atomic.Uint64{}
	}
	return m
}

func (m *Metrics) Inc(name string) {
	if m == nil {
		return
	}
	m.mu.RLock()
	counter := m.counters[name]
	m.mu.RUnlock()
	if counter != nil {
		counter.Add(1)
	}
}

func (m *Metrics) Add(name string, value uint64) {
	if m == nil {
		return
	}
	m.mu.RLock()
	counter := m.counters[name]
	m.mu.RUnlock()
	if counter != nil {
		counter.Add(value)
	}
}

func (m *Metrics) StreamStarted() {
	if m != nil {
		m.active.Add(1)
	}
}

func (m *Metrics) StreamFinished() {
	if m != nil {
		m.active.Add(-1)
	}
}

func (m *Metrics) Snapshot() map[string]uint64 {
	result := make(map[string]uint64, len(metricNames)+1)
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, name := range metricNames {
		result[name] = m.counters[name].Load()
	}
	active := m.active.Load()
	if active < 0 {
		active = 0
	}
	result["active_streams"] = uint64(active)
	return result
}

// Handler is intentionally internal-only. Empty secrets fail closed instead
// of making the endpoint accidentally public in a misconfigured deployment.
func (m *Metrics) Handler(secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("X-JJDGuard-Internal-Secret")
		if secret == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m.Snapshot())
	}
}
