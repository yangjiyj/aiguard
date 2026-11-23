package identitybinding

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeInvalidationOutbox struct {
	mu          sync.Mutex
	event       *CacheInvalidationEvent
	status      string
	workerID    string
	lastError   string
	nextAttempt time.Time
}

func (s *fakeInvalidationOutbox) ClaimNextInvalidation(_ context.Context, workerID string) (*CacheInvalidationEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.event == nil || (s.status != "pending" && s.status != "failed") || time.Now().Before(s.nextAttempt) {
		return nil, nil
	}
	s.status = "processing"
	s.workerID = workerID
	event := *s.event
	event.AttemptCount++
	s.event.AttemptCount = event.AttemptCount
	return &event, nil
}

func (s *fakeInvalidationOutbox) MarkInvalidationProcessed(_ context.Context, eventID, workerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.event == nil || s.event.ID != eventID || s.status != "processing" || s.workerID != workerID {
		return ErrNotFound
	}
	s.status = "processed"
	return nil
}

func (s *fakeInvalidationOutbox) MarkInvalidationFailed(_ context.Context, eventID, workerID, safeError string, nextAttempt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.event == nil || s.event.ID != eventID || s.status != "processing" || s.workerID != workerID {
		return ErrNotFound
	}
	s.status = "failed"
	s.lastError = safeError
	s.nextAttempt = nextAttempt
	return nil
}

type countingPermissionInvalidator struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (i *countingPermissionInvalidator) InvalidateUserCache(context.Context, string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.calls++
	return i.err
}

type countingModelInvalidator struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (i *countingModelInvalidator) InvalidateUserModelAuthorizationCache(context.Context, string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.calls++
	return i.err
}

func pendingInvalidationOutbox() *fakeInvalidationOutbox {
	return &fakeInvalidationOutbox{
		event: &CacheInvalidationEvent{
			ID: "event-1", TenantID: "tenant-a", UserID: "user-a",
			OldDepartmentID: "dept-a", NewDepartmentID: "dept-b",
		},
		status: "pending",
	}
}

func TestReconcilerProcessesOnlyAfterBothInvalidatorsSucceed(t *testing.T) {
	outbox := pendingInvalidationOutbox()
	permission := &countingPermissionInvalidator{}
	model := &countingModelInvalidator{}
	reconciler := NewReconciler(outbox, permission, model)

	processed, err := reconciler.ProcessOne(context.Background())
	if err != nil || !processed {
		t.Fatalf("processed=%v err=%v", processed, err)
	}
	if outbox.status != "processed" || permission.calls != 1 || model.calls != 1 {
		t.Fatalf("status=%s permission=%d model=%d", outbox.status, permission.calls, model.calls)
	}
}

func TestReconcilerFailureRemainsRetryableWithSanitizedError(t *testing.T) {
	outbox := pendingInvalidationOutbox()
	permission := &countingPermissionInvalidator{err: errors.New("secret token=abcd")}
	model := &countingModelInvalidator{}
	reconciler := NewReconciler(outbox, permission, model)

	processed, err := reconciler.ProcessOne(context.Background())
	if err == nil || processed {
		t.Fatalf("processed=%v err=%v", processed, err)
	}
	if outbox.status != "failed" || outbox.nextAttempt.IsZero() {
		t.Fatalf("status=%s next=%v", outbox.status, outbox.nextAttempt)
	}
	if permission.calls != 1 || model.calls != 1 {
		t.Fatalf("both invalidators must be attempted: permission=%d model=%d", permission.calls, model.calls)
	}
	if strings.Contains(outbox.lastError, "secret") || strings.Contains(outbox.lastError, "abcd") ||
		outbox.lastError != "permission cache invalidation failed" {
		t.Fatalf("stored error is not sanitized: %q", outbox.lastError)
	}
}

func TestConcurrentReconcilersDoNotProcessOneEventTwice(t *testing.T) {
	outbox := pendingInvalidationOutbox()
	permission := &countingPermissionInvalidator{}
	model := &countingModelInvalidator{}
	const workers = 8
	var wait sync.WaitGroup
	start := make(chan struct{})
	processed := make(chan bool, workers)
	errs := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			ok, err := NewReconciler(outbox, permission, model).ProcessOne(context.Background())
			processed <- ok
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(processed)
	close(errs)
	count := 0
	for ok := range processed {
		if ok {
			count++
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatalf("unexpected concurrent reconciler error: %v", err)
		}
	}
	if count != 1 || permission.calls != 1 || model.calls != 1 || outbox.status != "processed" {
		t.Fatalf("processed=%d permission=%d model=%d status=%s", count, permission.calls, model.calls, outbox.status)
	}
}
