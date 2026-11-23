package modelrouter

import (
	"context"
	"errors"
	"math"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	routeMetricsWindow = 15 * time.Minute
	maxRouteMetricKeys = 10000
	maxSamplesPerRoute = 2048
)

type routeMetricSample struct {
	at            time.Time
	success       bool
	latency, ttft time.Duration
}
type routeMetricSeries struct {
	samples     []routeMetricSample
	lastSeen    time.Time
	version     uint64
	evaluatedAt time.Time
}

// RouteMetricsStore keeps bounded, tenant-scoped observations and accepts only
// successful calls or genuine retryable upstream failures.
type RouteMetricsStore struct {
	mu     sync.Mutex
	now    func() time.Time
	series map[RouteKey]*routeMetricSeries
}

func NewRouteMetricsStore(clock func() time.Time) *RouteMetricsStore {
	if clock == nil {
		clock = time.Now
	}
	return &RouteMetricsStore{now: clock, series: make(map[RouteKey]*routeMetricSeries)}
}

func (s *RouteMetricsStore) Record(key RouteKey, result AttemptResult) {
	if !validRouteKey(key) || result.HealthNeutral || (!result.Success && !result.Retryable) {
		return
	}
	now := s.now()
	at := result.OccurredAt
	if at.IsZero() {
		at = now
	}
	if at.Before(now.Add(-routeMetricsWindow)) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if _, ok := s.series[key]; !ok && len(s.series) >= maxRouteMetricKeys {
		s.evictOldestLocked()
	}
	entry := s.series[key]
	if entry == nil {
		entry = &routeMetricSeries{}
		s.series[key] = entry
	}
	entry.samples = append(entry.samples, routeMetricSample{at: at, success: result.Success, latency: result.Latency, ttft: result.TTFT})
	entry.version++
	entry.evaluatedAt = now
	if len(entry.samples) > maxSamplesPerRoute {
		entry.samples = append([]routeMetricSample(nil), entry.samples[len(entry.samples)-maxSamplesPerRoute:]...)
	}
	if at.After(entry.lastSeen) {
		entry.lastSeen = at
	}
}

func (s *RouteMetricsStore) Snapshot(key RouteKey) RouteMetricsSnapshot {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	entry := s.series[key]
	if entry == nil || len(entry.samples) == 0 {
		return RouteMetricsSnapshot{}
	}
	latencies := make([]time.Duration, 0, len(entry.samples))
	ttfts := make([]time.Duration, 0, len(entry.samples))
	successes := 0
	for _, sample := range entry.samples {
		if sample.success {
			successes++
		}
		if sample.latency > 0 {
			latencies = append(latencies, sample.latency)
		}
		if sample.ttft > 0 {
			ttfts = append(ttfts, sample.ttft)
		}
	}
	return RouteMetricsSnapshot{SampleCount: len(entry.samples), SuccessRate: float64(successes) / float64(len(entry.samples)), P95Latency: percentile95(latencies), P95TTFT: percentile95(ttfts), Version: entry.version, EvaluatedAt: entry.evaluatedAt}
}

func (s *RouteMetricsStore) Snapshots(tenantID, modelName string, providerIDs []string) map[string]RouteMetricsSnapshot {
	result := make(map[string]RouteMetricsSnapshot, len(providerIDs))
	for _, providerID := range providerIDs {
		result[providerID] = s.Snapshot(RouteKey{TenantID: tenantID, ModelName: modelName, ProviderID: providerID})
	}
	return result
}

func (s *RouteMetricsStore) pruneLocked(now time.Time) {
	cutoff := now.Add(-routeMetricsWindow)
	for key, entry := range s.series {
		before := len(entry.samples)
		kept := entry.samples[:0]
		for _, sample := range entry.samples {
			if !sample.at.Before(cutoff) {
				kept = append(kept, sample)
			}
		}
		entry.samples = kept
		if len(entry.samples) != before {
			entry.version++
			entry.evaluatedAt = now
		}
		if len(entry.samples) == 0 {
			delete(s.series, key)
		}
	}
}
func (s *RouteMetricsStore) evictOldestLocked() {
	var key RouteKey
	var oldest time.Time
	first := true
	for candidate, entry := range s.series {
		if first || entry.lastSeen.Before(oldest) {
			first = false
			oldest = entry.lastSeen
			key = candidate
		}
	}
	if !first {
		delete(s.series, key)
	}
}
func percentile95(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	index := int(math.Ceil(.95*float64(len(values)))) - 1
	if index < 0 {
		index = 0
	}
	return values[index]
}
func validRouteKey(key RouteKey) bool {
	return key.TenantID != "" && key.ModelName != "" && key.ProviderID != ""
}

// IsRetryableRouteFailure excludes generic application errors and client
// cancellation. Security and validation failures arrive as ordinary errors or
// ordinary 4xx and therefore cannot degrade a provider.
func IsRetryableRouteFailure(statusCode int, err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	if err != nil && errors.As(err, &networkError) {
		return true
	}
	return statusCode == 429 || statusCode >= 500
}
