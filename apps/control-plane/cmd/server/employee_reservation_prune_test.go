package main

import (
	"context"
	"testing"
	"time"
)

// 员工预占清理 worker：启动即跑一次、之后按间隔跑，随 ctx 结束；单次失败不影响后续轮次。
func TestEmployeeReservationPruneWorkerRunsOnStartAndOnTick(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := make(chan time.Duration, 8)
	done := startEmployeeReservationPruneWorker(ctx, 20*time.Millisecond, 35*time.Minute, func(_ context.Context, maxAge time.Duration, _ time.Time, limit int) (int64, bool, error) {
		calls <- maxAge
		if limit <= 0 {
			t.Errorf("limit must be positive, got %d", limit)
		}
		return 0, false, nil
	})
	for i := 0; i < 3; i++ {
		select {
		case maxAge := <-calls:
			if maxAge != 35*time.Minute {
				t.Fatalf("maxAge = %s", maxAge)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("prune did not run (round %d)", i)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not stop with the context")
	}
}

// 残留较多（Backlog）时同一轮内继续清，直到清完或达到轮内上限，避免每分钟只清一小批。
func TestEmployeeReservationPruneWorkerDrainsBacklogWithinOneRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remaining := 3
	rounds := make(chan struct{}, 16)
	done := startEmployeeReservationPruneWorker(ctx, time.Hour, 35*time.Minute, func(context.Context, time.Duration, time.Time, int) (int64, bool, error) {
		rounds <- struct{}{}
		remaining--
		return 1, remaining > 0, nil
	})
	for i := 0; i < 3; i++ {
		select {
		case <-rounds:
		case <-time.After(3 * time.Second):
			t.Fatalf("backlog was not drained in one run (round %d)", i)
		}
	}
	cancel()
	<-done
	if remaining != 0 {
		t.Fatalf("remaining=%d", remaining)
	}
}

func TestEmployeeReservationMaxAgeIsRequestDurationPlusFiveMinutes(t *testing.T) {
	t.Setenv("GATEWAY_REQUEST_TIMEOUT", "")
	if got := employeeReservationMaxAge(); got != 35*time.Minute {
		t.Fatalf("default = %s, want 35m (30m request + 5m)", got)
	}
	t.Setenv("GATEWAY_REQUEST_TIMEOUT", "10m")
	if got := employeeReservationMaxAge(); got != 15*time.Minute {
		t.Fatalf("10m request = %s, want 15m", got)
	}
	t.Setenv("GATEWAY_REQUEST_TIMEOUT", "garbage")
	if got := employeeReservationMaxAge(); got != 35*time.Minute {
		t.Fatalf("invalid value must fall back to the default: %s", got)
	}
}
