package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func TestBillingReconciliationRecordsAttempt(t *testing.T) {
	monitor := billing.NewReconciliationMonitor(true)
	result := billing.ReconciliationResult{Released: 2, Settled: 3, Pending: 4, Failed: 1}
	reconcile := func(ctx context.Context, age time.Duration, limit int) (billing.ReconciliationResult, error) {
		if age != 15*time.Minute || limit != 100 {
			t.Fatalf("reconciliation policy changed: age=%s limit=%d", age, limit)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 29*time.Second || time.Until(deadline) > 30*time.Second {
			t.Fatalf("attempt deadline=%s present=%v", deadline, ok)
		}
		if got := monitor.Snapshot(time.Now()); !got.Running || got.LastStartedAt.IsZero() {
			t.Fatalf("attempt was not recorded before work: %+v", got)
		}
		return result, errors.New("private database details")
	}
	runBillingReconciliation(context.Background(), "test", reconcile, monitor)
	got := monitor.Snapshot(time.Now())
	if got.Status != "degraded" || got.ReasonCode != "execution_failed" || got.Running || got.LastCompletedAt.IsZero() || got.Result != result {
		t.Fatalf("failed result not recorded: %+v", got)
	}
	runBillingReconciliation(context.Background(), "recovery", func(context.Context, time.Duration, int) (billing.ReconciliationResult, error) {
		return billing.ReconciliationResult{Pending: 1}, nil
	}, monitor)
	if got := monitor.Snapshot(time.Now()); got.Status != "healthy" || got.Running || got.Result.Pending != 1 {
		t.Fatalf("recovery not recorded: %+v", got)
	}
}

func TestBillingReconciliationStartsAndStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	monitor := billing.NewReconciliationMonitor(true)
	started := make(chan struct{})
	done := startBillingReconciliationWorker(ctx, func(runCtx context.Context, age time.Duration, limit int) (billing.ReconciliationResult, error) {
		close(started)
		<-runCtx.Done()
		return billing.ReconciliationResult{Pending: 1}, runCtx.Err()
	}, monitor)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("startup reconciliation did not run")
	}
	if got := monitor.Snapshot(time.Now()); !got.Running {
		t.Errorf("startup not marked running: %+v", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker ignored process cancellation")
	}
	if got := monitor.Snapshot(time.Now()); got.Status != "degraded" || got.ReasonCode != "worker_stopped" || got.Running || got.LastCompletedAt.IsZero() || got.Result.Pending != 1 {
		t.Fatalf("worker shutdown not recorded: %+v", got)
	}
}
