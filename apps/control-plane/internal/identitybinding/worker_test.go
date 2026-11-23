package identitybinding

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type workerOutbox struct {
	mu           sync.Mutex
	claimCalls   int
	cleanupCalls int
	claimErr     error
	cleanupErr   error
}

func (s *workerOutbox) ClaimNextInvalidation(context.Context, string) (*CacheInvalidationEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claimCalls++
	return nil, s.claimErr
}

func (*workerOutbox) MarkInvalidationProcessed(context.Context, string, string) error {
	return nil
}

func (*workerOutbox) MarkInvalidationFailed(context.Context, string, string, string, time.Time) error {
	return nil
}

func (s *workerOutbox) CleanupProcessedInvalidations(context.Context, time.Time, int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupCalls++
	return 0, s.cleanupErr
}

func TestReconcilerWorkerObservesSanitizedCleanupError(t *testing.T) {
	outbox := &workerOutbox{cleanupErr: errors.New("raw cleanup-sensitive-detail")}
	reconciler := NewReconciler(outbox, &countingPermissionInvalidator{}, &countingModelInvalidator{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stages []string
	var observedErrors []error
	err := reconciler.Run(ctx, WorkerConfig{
		FailureBackoff: time.Millisecond,
		ErrorObserver: func(stage string, err error) {
			stages = append(stages, stage)
			observedErrors = append(observedErrors, err)
			cancel()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 1 || stages[0] != WorkerErrorStageCleanup {
		t.Fatalf("stages=%v, want one %q", stages, WorkerErrorStageCleanup)
	}
	if len(observedErrors) != 1 || !errors.Is(observedErrors[0], ErrCacheInvalidation) {
		t.Fatalf("observed errors=%v", observedErrors)
	}
	if strings.Contains(observedErrors[0].Error(), "cleanup-sensitive-detail") {
		t.Fatalf("observer received unsanitized error: %v", observedErrors[0])
	}
}

func TestReconcilerWorkerObservesSanitizedProcessError(t *testing.T) {
	outbox := &workerOutbox{claimErr: errors.New("dsn=process-secret")}
	reconciler := NewReconciler(outbox, &countingPermissionInvalidator{}, &countingModelInvalidator{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stages []string
	var observedErrors []error
	err := reconciler.Run(ctx, WorkerConfig{
		FailureBackoff: time.Millisecond,
		ErrorObserver: func(stage string, err error) {
			stages = append(stages, stage)
			observedErrors = append(observedErrors, err)
			cancel()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 1 || stages[0] != WorkerErrorStageProcess {
		t.Fatalf("stages=%v, want one %q", stages, WorkerErrorStageProcess)
	}
	if len(observedErrors) != 1 || !errors.Is(observedErrors[0], ErrCacheInvalidation) {
		t.Fatalf("observed errors=%v", observedErrors)
	}
	if strings.Contains(observedErrors[0].Error(), "process-secret") {
		t.Fatalf("observer received unsanitized error: %v", observedErrors[0])
	}
}

func TestReconcilerWorkerRecoversObserverPanic(t *testing.T) {
	outbox := &workerOutbox{claimErr: errors.New("claim failed")}
	reconciler := NewReconciler(outbox, &countingPermissionInvalidator{}, &countingModelInvalidator{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observerCalls := 0
	err := reconciler.Run(ctx, WorkerConfig{
		FailureBackoff: time.Millisecond,
		ErrorObserver: func(string, error) {
			observerCalls++
			if observerCalls == 1 {
				panic("observer failed")
			}
			cancel()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if observerCalls != 2 {
		t.Fatalf("observer calls=%d, want 2", observerCalls)
	}
}

func TestReconcilerWorkerCancelsAndBacksOffEmptyQueue(t *testing.T) {
	outbox := &workerOutbox{}
	reconciler := NewReconciler(outbox, &countingPermissionInvalidator{}, &countingModelInvalidator{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- reconciler.Run(ctx, WorkerConfig{
			EmptyBackoff:    10 * time.Millisecond,
			FailureBackoff:  10 * time.Millisecond,
			CleanupInterval: 10 * time.Millisecond,
			ProcessedTTL:    7 * 24 * time.Hour,
			CleanupBatch:    100,
		})
	}()
	time.Sleep(35 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after context cancellation")
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if outbox.claimCalls < 2 || outbox.claimCalls > 8 {
		t.Fatalf("empty queue was not backed off: calls=%d", outbox.claimCalls)
	}
	if outbox.cleanupCalls == 0 {
		t.Fatal("processed cleanup did not run")
	}
}
