package backfill

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

type fakeStore struct {
	tasks       []*Task
	claimed     *Task
	result      BatchResult
	err         error
	completions int
	releases    int
}

func (f *fakeStore) Claim(context.Context, string, time.Duration) (*Task, error) {
	if f.claimed != nil {
		return f.claimed, nil
	}
	if len(f.tasks) == 0 {
		return nil, nil
	}
	f.claimed = f.tasks[0]
	f.tasks = f.tasks[1:]
	return f.claimed, nil
}

func (f *fakeStore) RunBatch(context.Context, *Task, string, time.Duration) (BatchResult, error) {
	return f.result, f.err
}

func (f *fakeStore) Complete(context.Context, *Task, string, BatchResult) error {
	f.completions++
	f.claimed = nil
	return nil
}

func (f *fakeStore) Release(context.Context, *Task, string, BatchResult, error) error {
	f.releases++
	f.claimed = nil
	return nil
}

func TestRunOnceCompletesFinishedTask(t *testing.T) {
	store := &fakeStore{
		tasks:  []*Task{{Name: CustomerContentProjectionTask, Version: 1, BatchSize: 500}},
		result: BatchResult{Scanned: 7, Updated: 3, Done: true},
	}
	runner := NewRunner(store, Config{Owner: "worker-a", Lease: time.Minute, Logger: slog.Default()})

	didWork, err := runner.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !didWork || store.completions != 1 || store.releases != 0 {
		t.Fatalf("unexpected completion state: didWork=%v completed=%d released=%d", didWork, store.completions, store.releases)
	}
}

func TestRunOnceReleasesLeaseAfterBoundedBatchFailure(t *testing.T) {
	store := &fakeStore{
		tasks:  []*Task{{Name: CustomerContentProjectionTask, Version: 1, BatchSize: 500}},
		result: BatchResult{Scanned: 5, Updated: 1, Skipped: 2},
		err:    errors.New("statement timeout"),
	}
	runner := NewRunner(store, Config{Owner: "worker-b", Lease: time.Minute})

	didWork, err := runner.RunOnce(context.Background())
	if err == nil || !didWork || store.releases != 1 || store.completions != 0 {
		t.Fatalf("unexpected failure state: didWork=%v err=%v completed=%d released=%d", didWork, err, store.completions, store.releases)
	}
}

func TestRunOnceRejectsUnregisteredTaskImplementation(t *testing.T) {
	store := &fakeStore{tasks: []*Task{{Name: "arbitrary_sql", Version: 1}}}
	runner := NewRunner(store, Config{Owner: "worker-c", Lease: time.Minute})

	_, err := runner.RunOnce(context.Background())
	if err == nil || store.releases != 1 {
		t.Fatalf("unregistered task must fail and release lease: err=%v releases=%d", err, store.releases)
	}
}
