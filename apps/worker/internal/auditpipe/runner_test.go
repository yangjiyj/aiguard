package auditpipe

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/worker/internal/notifyagent"
	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
	"github.com/yangjiyj/aiguard/packages/shared-go/outbox"
)

type fakeStore struct {
	events          []outbox.Event
	processedIDs    []string
	failedIDs       []string
	nextAvailableAt []time.Time
	maxAttempts     []int
}

func (f *fakeStore) Claim(ctx context.Context, consumer string, limit int) ([]outbox.Event, error) {
	return f.events, nil
}
func (f *fakeStore) MarkProcessed(ctx context.Context, id string) error {
	f.processedIDs = append(f.processedIDs, id)
	return nil
}
func (f *fakeStore) MarkFailed(ctx context.Context, id string, cause error, maxAttempts int, nextAvailableAt time.Time) error {
	f.failedIDs = append(f.failedIDs, id)
	f.nextAvailableAt = append(f.nextAvailableAt, nextAvailableAt)
	f.maxAttempts = append(f.maxAttempts, maxAttempts)
	return nil
}

type fakeProcessor struct {
	failIDs map[string]bool
}

func (f fakeProcessor) Process(ctx context.Context, event outbox.Event) error {
	if f.failIDs[event.ID] {
		return errors.New("process failed")
	}
	return nil
}

func TestRunnerMarksProcessedAndFailedEvents(t *testing.T) {
	now := time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC)
	store := &fakeStore{events: []outbox.Event{{ID: "evt_ok", Attempts: 1}, {ID: "evt_bad", Attempts: 2}}}
	runner := NewRunner(store, fakeProcessor{failIDs: map[string]bool{"evt_bad": true}}, Config{
		ConsumerName:   "worker-a",
		BatchSize:      10,
		MaxAttempts:    4,
		RetryBaseDelay: 5 * time.Second,
		Now:            func() time.Time { return now },
	})

	processed, err := runner.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected processing error to be returned")
	}
	if processed != 1 || len(store.processedIDs) != 1 || store.processedIDs[0] != "evt_ok" {
		t.Fatalf("processed mismatch: processed=%d ids=%v", processed, store.processedIDs)
	}
	if len(store.failedIDs) != 1 || store.failedIDs[0] != "evt_bad" {
		t.Fatalf("failed ids mismatch: %v", store.failedIDs)
	}
	if got, want := store.nextAvailableAt[0], now.Add(10*time.Second); !got.Equal(want) {
		t.Fatalf("next retry = %s, want %s", got, want)
	}
}

type failingNotificationDispatcher struct{}

func (failingNotificationDispatcher) DispatchChannel(context.Context, string, string, string, string, map[string]any) error {
	return errors.New("connector unavailable")
}

func TestRunnerRetriesAndDeadLettersDestructiveNotificationFailures(t *testing.T) {
	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	store := &fakeStore{events: []outbox.Event{{
		ID: "obn-failed", Type: eventbus.EventTypeNotifyAgentDestructive,
		TenantID: "tenant-1", Attempts: 8,
		Payload: []byte(`{
			"public_event_id":"evt-public",
			"operation_id":"op-public",
			"event_type":"tool_attempt_blocked",
			"channel_id":"channel-public",
			"risk_subcategory":"filesystem_delete",
			"reason_summary":"deterministic_destructive_operation",
			"target_summary":"filesystem_delete:1-targets",
			"final_action":"block"
		}`),
	}}}
	runner := NewRunner(store, notifyagent.NewProcessor(failingNotificationDispatcher{}), Config{
		ConsumerName: "worker-notify", BatchSize: 1, MaxAttempts: 4,
		RetryBaseDelay: 5 * time.Second, Now: func() time.Time { return now },
	})
	processed, err := runner.RunOnce(context.Background())
	if err == nil || processed != 0 {
		t.Fatalf("failed notification result: processed=%d err=%v", processed, err)
	}
	if len(store.failedIDs) != 1 || store.failedIDs[0] != "obn-failed" ||
		len(store.maxAttempts) != 1 || store.maxAttempts[0] != 4 {
		t.Fatalf("retry/dead-letter arguments: failed=%v max=%v", store.failedIDs, store.maxAttempts)
	}
	if got := store.nextAvailableAt[0]; !got.Equal(now.Add(time.Minute)) {
		t.Fatalf("bounded retry time=%s want=%s", got, now.Add(time.Minute))
	}
}
