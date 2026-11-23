package rollup

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeRefreshRepo struct {
	usageCalls  int
	accessCalls int
	failUsage   bool
}

func (f *fakeRefreshRepo) RefreshUsageHourly(ctx context.Context, win repository.RollupRefreshWindow) error {
	f.usageCalls++
	if f.failUsage {
		return errors.New("usage failed")
	}
	return nil
}

func (f *fakeRefreshRepo) RefreshAccessHourly(ctx context.Context, win repository.RollupRefreshWindow) error {
	f.accessCalls++
	return nil
}

func TestServiceRefreshValidatesWindowAndRunsBothRollups(t *testing.T) {
	repo := &fakeRefreshRepo{}
	svc := NewService(repo)
	win := repository.RollupRefreshWindow{TenantID: "tenant_1", From: time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC), To: time.Date(2026, 6, 18, 11, 0, 0, 0, time.UTC)}

	if err := svc.Refresh(context.Background(), win); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if repo.usageCalls != 1 || repo.accessCalls != 1 {
		t.Fatalf("expected both rollups once, got usage=%d access=%d", repo.usageCalls, repo.accessCalls)
	}
}

func TestServiceRefreshStopsWhenUsageFails(t *testing.T) {
	repo := &fakeRefreshRepo{failUsage: true}
	svc := NewService(repo)
	win := repository.RollupRefreshWindow{TenantID: "tenant_1", From: time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC), To: time.Date(2026, 6, 18, 11, 0, 0, 0, time.UTC)}

	if err := svc.Refresh(context.Background(), win); err == nil {
		t.Fatalf("expected usage failure")
	}
	if repo.accessCalls != 0 {
		t.Fatalf("access refresh should not run after usage failure")
	}
}

func TestServiceRefreshRejectsInvalidWindow(t *testing.T) {
	svc := NewService(&fakeRefreshRepo{})
	win := repository.RollupRefreshWindow{TenantID: "", From: time.Now(), To: time.Now().Add(-time.Hour)}

	if err := svc.Refresh(context.Background(), win); !errors.Is(err, ErrInvalidWindow) {
		t.Fatalf("expected ErrInvalidWindow, got %v", err)
	}
}
