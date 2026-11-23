package modelrouter

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestRouteMetricsCalculatesFifteenMinuteSuccessAndP95(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	store := NewRouteMetricsStore(func() time.Time { return now })
	key := RouteKey{TenantID: "tenant-a", ModelName: "logical/model", ProviderID: "provider-a"}
	store.Record(key, AttemptResult{Success: true, Latency: 100 * time.Millisecond, TTFT: 20 * time.Millisecond, OccurredAt: now.Add(-14 * time.Minute)})
	store.Record(key, AttemptResult{Retryable: true, StatusCode: 503, Latency: time.Second, OccurredAt: now.Add(-time.Minute)})
	store.Record(key, AttemptResult{Success: true, Latency: 9 * time.Second, OccurredAt: now.Add(-16 * time.Minute)})
	store.Record(key, AttemptResult{StatusCode: 400, Latency: 2 * time.Second, OccurredAt: now}) // client error is not a route sample

	got := store.Snapshot(key)
	if got.SampleCount != 2 || got.SuccessRate != .5 {
		t.Fatalf("snapshot = %+v, want 2 samples and 50%% success", got)
	}
	if got.P95Latency != time.Second || got.P95TTFT != 20*time.Millisecond {
		t.Fatalf("P95 snapshot = %+v", got)
	}
}

func TestRouteMetricsKeepsLogicalModelsAndTenantsIsolated(t *testing.T) {
	now := time.Now()
	store := NewRouteMetricsStore(func() time.Time { return now })
	key := RouteKey{TenantID: "tenant-a", ModelName: "public-name", ProviderID: "provider-a"}
	store.Record(key, AttemptResult{Success: true, Latency: time.Second})
	if got := store.Snapshot(RouteKey{TenantID: "tenant-a", ModelName: "upstream-id", ProviderID: "provider-a"}); got.SampleCount != 0 {
		t.Fatalf("upstream model ID contaminated logical model metrics: %+v", got)
	}
	if got := store.Snapshot(RouteKey{TenantID: "tenant-b", ModelName: "public-name", ProviderID: "provider-a"}); got.SampleCount != 0 {
		t.Fatalf("cross-tenant metrics leak: %+v", got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

func TestRetryableFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		err    error
		want   bool
	}{
		{"timeout", 0, timeoutErr{}, true},
		{"deadline", 0, context.DeadlineExceeded, true},
		{"rate-limit", 429, nil, true},
		{"server", 503, nil, true},
		{"client", 400, nil, false},
		{"cancel", 0, context.Canceled, false},
		{"validation", 0, errors.New("invalid request"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsRetryableRouteFailure(tc.status, tc.err); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestRouteMetricsSnapshotVersionChangesOnlyWithEffectiveSamples(t *testing.T) {
	now := time.Now()
	store := NewRouteMetricsStore(func() time.Time { return now })
	key := RouteKey{TenantID: "t", ModelName: "m", ProviderID: "p"}
	store.Record(key, AttemptResult{StatusCode: 400})
	if got := store.Snapshot(key); got.Version != 0 {
		t.Fatalf("non-metric result changed version: %+v", got)
	}
	store.Record(key, AttemptResult{Success: true, Latency: time.Second})
	first := store.Snapshot(key)
	second := store.Snapshot(key)
	if first.Version == 0 || first.Version != second.Version || !first.EvaluatedAt.Equal(second.EvaluatedAt) {
		t.Fatalf("unstable snapshot version: first=%+v second=%+v", first, second)
	}
	store.Record(key, AttemptResult{Success: true, Latency: time.Second})
	if third := store.Snapshot(key); third.Version == first.Version {
		t.Fatalf("effective sample did not advance version: %+v", third)
	}
}

func TestRouteMetricsIgnoresHealthNeutralAttempts(t *testing.T) {
	store := NewRouteMetricsStore(time.Now)
	key := RouteKey{TenantID: "tenant-a", ModelName: "logical/model", ProviderID: "provider-a"}
	store.Record(key, AttemptResult{Retryable: true, HealthNeutral: true, StatusCode: 429, Latency: time.Second})
	if got := store.Snapshot(key); got.SampleCount != 0 || got.Version != 0 {
		t.Fatalf("health-neutral result contaminated route metrics: %+v", got)
	}
}
