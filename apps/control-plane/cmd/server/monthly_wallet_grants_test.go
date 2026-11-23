package main

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func TestMonthlyWalletWorkerStartsWithBoundedBatchAndStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := make(chan struct{}, 1)
	done := startMonthlyWalletGrants(ctx, func(runCtx context.Context, now time.Time, limit int) (billing.MonthlyWalletGrantResult, error) {
		deadline, ok := runCtx.Deadline()
		if !ok || time.Until(deadline) > 30*time.Second || now.IsZero() || limit != 500 {
			t.Errorf("unbounded or invalid grant batch: deadline=%v now=%v limit=%d", deadline, now, limit)
		}
		called <- struct{}{}
		return billing.MonthlyWalletGrantResult{}, nil
	})
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("startup grant was not called")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("monthly wallet worker did not stop")
	}
}
