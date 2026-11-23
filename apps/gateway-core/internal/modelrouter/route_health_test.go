package modelrouter

import (
	"sync"
	"testing"
	"time"
)

func TestRouteHealthOpensAfterThreeConsecutiveRetryableFailures(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	health := NewRouteHealth(func() time.Time { return now })
	key := RouteKey{TenantID: "t", ModelName: "m", ProviderID: "p"}
	for i := 0; i < 3; i++ {
		health.Record(key, AttemptResult{Retryable: true, OccurredAt: now})
	}
	if health.Allow(key) {
		t.Fatal("open circuit allowed a request")
	}
}

func TestRouteHealthNonRetryableAttemptBreaksConsecutiveFailures(t *testing.T) {
	for _, name := range []string{"ordinary_4xx", "security_rejection", "validation_error", "client_cancel"} {
		t.Run(name, func(t *testing.T) {
			health := NewRouteHealth(time.Now)
			key := RouteKey{TenantID: "t", ModelName: "m", ProviderID: name}
			health.Record(key, AttemptResult{Retryable: true, StatusCode: 503})
			health.Record(key, AttemptResult{Retryable: true, StatusCode: 503})
			health.Record(key, AttemptResult{Retryable: false, StatusCode: 400})
			health.Record(key, AttemptResult{Retryable: true, StatusCode: 503})
			if !health.Allow(key) {
				t.Fatal("a completed non-retryable attempt did not break the consecutive retryable-failure streak")
			}
		})
	}
}

func TestRouteHealthNonRetryableAttemptsDoNotDiluteLastTenWindow(t *testing.T) {
	health := NewRouteHealth(time.Now)
	key := RouteKey{TenantID: "t", ModelName: "m", ProviderID: "p"}
	// Ten counted outcomes with four retryable failures and no three failures
	// adjacent: S,F,S,F,S,F,S,F,S,S.
	for _, failed := range []bool{false, true, false, true, false, true, false, true, false, false} {
		health.Record(key, AttemptResult{Success: !failed, Retryable: failed})
	}
	for i := 0; i < 20; i++ {
		health.Record(key, AttemptResult{StatusCode: 400})
	}
	health.Record(key, AttemptResult{Retryable: true, StatusCode: 503})
	if health.Allow(key) {
		t.Fatal("non-retryable outcomes diluted the last-ten retryable failure window")
	}
}

func TestRouteHealthOpensAtHalfOfLastTenRetryableOutcomes(t *testing.T) {
	now := time.Now()
	health := NewRouteHealth(func() time.Time { return now })
	key := RouteKey{TenantID: "t", ModelName: "m", ProviderID: "p"}
	for i := 0; i < 5; i++ {
		health.Record(key, AttemptResult{Retryable: true})
		health.Record(key, AttemptResult{Success: true})
	}
	if health.Allow(key) {
		t.Fatal("50% retryable failure rate in last 10 should open")
	}
}

func TestRouteHealthHalfOpensAfterThirtySecondsExactlyOnce(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	health := NewRouteHealth(func() time.Time { return now })
	key := RouteKey{TenantID: "t", ModelName: "m", ProviderID: "p"}
	for i := 0; i < 3; i++ {
		health.Record(key, AttemptResult{Retryable: true})
	}
	now = now.Add(30 * time.Second)
	var wg sync.WaitGroup
	allowed := 0
	var mu sync.Mutex
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if health.Allow(key) {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 1 {
		t.Fatalf("half-open probes = %d, want 1", allowed)
	}
	health.Record(key, AttemptResult{Success: true})
	if !health.Allow(key) {
		t.Fatal("successful probe should close and reset")
	}
}

func TestRouteHealthFailedProbeReopensForThirtySeconds(t *testing.T) {
	now := time.Now()
	health := NewRouteHealth(func() time.Time { return now })
	key := RouteKey{TenantID: "t", ModelName: "m", ProviderID: "p"}
	for i := 0; i < 3; i++ {
		health.Record(key, AttemptResult{Retryable: true})
	}
	now = now.Add(30 * time.Second)
	if !health.Allow(key) {
		t.Fatal("probe not allowed")
	}
	health.Record(key, AttemptResult{Retryable: true})
	if health.Allow(key) {
		t.Fatal("failed probe did not re-open")
	}
}

func TestRouteHealthOpenPeriodUsesLocalClockNotEventTimestamp(t *testing.T) {
	for _, tc := range []struct {
		name     string
		occurred time.Time
	}{{"old", time.Unix(1, 0)}, {"future", time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
			health := NewRouteHealth(func() time.Time { return now })
			key := RouteKey{TenantID: "t", ModelName: "m", ProviderID: tc.name}
			for i := 0; i < 3; i++ {
				health.Record(key, AttemptResult{Retryable: true, OccurredAt: tc.occurred})
			}
			now = now.Add(29 * time.Second)
			if health.Available(key) {
				t.Fatal("circuit recovered before local 30 seconds")
			}
			now = now.Add(time.Second)
			if !health.Available(key) {
				t.Fatal("event timestamp distorted local 30 second open period")
			}
		})
	}
}

func TestPreferenceSwitchCountsEachMetricsVersionOnceUnderConcurrency(t *testing.T) {
	p := NewPreferenceSwitch(time.Now)
	key := RoutePreferenceKey{TenantID: "t", ModelName: "m"}
	p.SetBaseline(key, "a")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := p.ChooseVersioned(key, "a", .5, "b", 1, false, 1); got != "a" {
				t.Errorf("same version switched early: %s", got)
			}
		}()
	}
	wg.Wait()
	if got := p.ChooseVersioned(key, "a", .5, "b", 1, false, 2); got != "a" {
		t.Fatalf("second version switched early: %s", got)
	}
	if got := p.ChooseVersioned(key, "a", .5, "b", 1, false, 3); got != "b" {
		t.Fatalf("third distinct version did not switch: %s", got)
	}
}

func TestPreferenceSwitchRequiresFifteenPercentLeadThreeTimes(t *testing.T) {
	now := time.Now()
	switcher := NewPreferenceSwitch(func() time.Time { return now })
	key := RoutePreferenceKey{TenantID: "t", ModelName: "m"}
	for i := 0; i < 2; i++ {
		if got := switcher.Choose(key, "a", 0.8, "b", 0.93, false); got != "a" {
			t.Fatalf("cycle %d switched early to %s", i, got)
		}
	}
	if got := switcher.Choose(key, "a", 0.8, "b", 0.93, false); got != "b" {
		t.Fatalf("third lead did not switch: %s", got)
	}
}

func TestPreferenceSwitchHasFiveMinuteCooldownButCircuitFailoverIsImmediate(t *testing.T) {
	now := time.Now()
	switcher := NewPreferenceSwitch(func() time.Time { return now })
	key := RoutePreferenceKey{TenantID: "t", ModelName: "m"}
	for i := 0; i < 3; i++ {
		_ = switcher.Choose(key, "a", .8, "b", 1, false)
	}
	for i := 0; i < 3; i++ {
		if got := switcher.Choose(key, "b", .8, "a", 1, false); got != "b" {
			t.Fatalf("cooldown allowed switch-back: %s", got)
		}
	}
	if got := switcher.Choose(key, "b", .8, "a", 1, true); got != "a" {
		t.Fatalf("circuit failover blocked by cooldown: %s", got)
	}
	now = now.Add(5 * time.Minute)
	for i := 0; i < 3; i++ {
		_ = switcher.Choose(key, "a", .8, "b", 1, false)
	}
}

func TestRouteHealthReleaseReturnsHalfOpenProbeWithoutRecording(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	health := NewRouteHealth(func() time.Time { return now })
	key := RouteKey{TenantID: "tenant-a", ModelName: "logical/model", ProviderID: "provider-a"}
	for i := 0; i < 3; i++ {
		health.Record(key, AttemptResult{Retryable: true})
	}
	now = now.Add(circuitOpenPeriod + time.Second)
	if !health.Allow(key) {
		t.Fatal("expected first half-open claim")
	}
	health.Release(key)
	if !health.Opened(key) {
		t.Fatal("release must preserve the open circuit")
	}
	if !health.Allow(key) {
		t.Fatal("released half-open claim was not available again")
	}
}

func TestRouteHealthNeutralAttemptPreservesFailureHistory(t *testing.T) {
	health := NewRouteHealth(time.Now)
	key := RouteKey{TenantID: "tenant-a", ModelName: "logical/model", ProviderID: "provider-a"}
	health.Record(key, AttemptResult{Retryable: true, StatusCode: 503})
	health.Record(key, AttemptResult{Retryable: true, StatusCode: 503})
	health.Record(key, AttemptResult{Retryable: true, HealthNeutral: true, StatusCode: 429})
	health.Record(key, AttemptResult{Retryable: true, StatusCode: 503})
	if health.Allow(key) {
		t.Fatal("health-neutral result erased the consecutive route failures")
	}
}

func TestRouteHealthNeutralAttemptReleasesHalfOpenProbeOnly(t *testing.T) {
	now := time.Date(2026, 8, 18, 1, 0, 0, 0, time.UTC)
	health := NewRouteHealth(func() time.Time { return now })
	key := RouteKey{TenantID: "tenant-a", ModelName: "logical/model", ProviderID: "provider-a"}
	for i := 0; i < 3; i++ {
		health.Record(key, AttemptResult{Retryable: true, StatusCode: 503})
	}
	now = now.Add(circuitOpenPeriod)
	if !health.Allow(key) {
		t.Fatal("expected a half-open probe")
	}
	health.Record(key, AttemptResult{Retryable: true, HealthNeutral: true, StatusCode: 429})
	if !health.Opened(key) {
		t.Fatal("health-neutral result closed the existing circuit")
	}
	if !health.Allow(key) {
		t.Fatal("health-neutral result did not release the half-open probe")
	}
}
