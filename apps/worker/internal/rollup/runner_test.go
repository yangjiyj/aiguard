package rollup

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeTenantSource struct {
	ids []string
	err error
}

func (f fakeTenantSource) ActiveTenantIDs(ctx context.Context) ([]string, error) {
	return f.ids, f.err
}

type refreshCall struct {
	tenantID string
	from     time.Time
	to       time.Time
}

type fakeRefresher struct {
	calls     []refreshCall
	failFirst bool
}

func (f *fakeRefresher) Refresh(ctx context.Context, tenantID string, from, to time.Time) error {
	f.calls = append(f.calls, refreshCall{tenantID: tenantID, from: from, to: to})
	if f.failFirst && len(f.calls) == 1 {
		return errors.New("refresh failed")
	}
	return nil
}

func TestRunnerRunOnceRefreshesLookbackWindowForEachTenant(t *testing.T) {
	now := time.Date(2026, 6, 18, 13, 37, 0, 0, time.UTC)
	refresher := &fakeRefresher{}
	runner := NewRunner(fakeTenantSource{ids: []string{"tenant_a", "tenant_b"}}, refresher, Config{
		Interval: 5 * time.Minute,
		Lookback: 2 * time.Hour,
		Now:      func() time.Time { return now },
	})

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(refresher.calls) != 2 {
		t.Fatalf("expected 2 refresh calls, got %d", len(refresher.calls))
	}
	wantFrom := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	wantTo := time.Date(2026, 6, 18, 14, 0, 0, 0, time.UTC)
	for _, call := range refresher.calls {
		if !call.from.Equal(wantFrom) || !call.to.Equal(wantTo) {
			t.Fatalf("unexpected window for %s: %s - %s", call.tenantID, call.from, call.to)
		}
	}
}

func TestRunnerFailureDoesNotBlockNextRun(t *testing.T) {
	now := time.Date(2026, 6, 18, 13, 37, 0, 0, time.UTC)
	refresher := &fakeRefresher{failFirst: true}
	runner := NewRunner(fakeTenantSource{ids: []string{"tenant_a"}}, refresher, Config{
		Interval: time.Minute,
		Lookback: time.Hour,
		Now:      func() time.Time { return now },
	})

	if err := runner.RunOnce(context.Background()); err == nil {
		t.Fatal("expected first run to return refresh failure")
	}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("second run should continue after failure: %v", err)
	}
	if len(refresher.calls) != 2 {
		t.Fatalf("expected two attempts, got %d", len(refresher.calls))
	}
}

func TestRunnerDisabledWhenIntervalIsZero(t *testing.T) {
	refresher := &fakeRefresher{}
	runner := NewRunner(fakeTenantSource{ids: []string{"tenant_a"}}, refresher, Config{Interval: 0, Lookback: time.Hour})

	runner.Run(context.Background())
	if len(refresher.calls) != 0 {
		t.Fatalf("disabled runner should not refresh, got %d calls", len(refresher.calls))
	}
}
