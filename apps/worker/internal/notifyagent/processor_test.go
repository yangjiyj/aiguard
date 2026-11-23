package notifyagent

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
	"github.com/yangjiyj/aiguard/packages/shared-go/outbox"
)

type fakeDispatcher struct {
	tenantID  string
	channelID string
	severity  string
	title     string
	body      map[string]any
	err       error
}

func (f *fakeDispatcher) DispatchChannel(_ context.Context, tenantID, channelID, severity, title string, body map[string]any) error {
	f.tenantID, f.channelID, f.severity, f.title, f.body = tenantID, channelID, severity, title, body
	return f.err
}

func destructiveNotificationEvent(t *testing.T) outbox.Event {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"public_event_id":  "evt-public",
		"operation_id":     "op-public",
		"event_type":       "tool_attempt_blocked",
		"channel_id":       "channel-public",
		"risk_subcategory": "filesystem_delete",
		"reason_summary":   "deterministic_destructive_operation",
		"target_summary":   "filesystem_delete:1-targets",
		"final_action":     "block",
	})
	if err != nil {
		t.Fatal(err)
	}
	return outbox.Event{
		ID: "obn-public", Type: eventbus.EventTypeNotifyAgentDestructive,
		TenantID: "tenant-1", Payload: payload,
	}
}

func TestProcessorDispatchesOpaqueDestructiveNotificationToConfiguredChannel(t *testing.T) {
	dispatcher := &fakeDispatcher{}
	processor := NewProcessor(dispatcher)
	if err := processor.Process(context.Background(), destructiveNotificationEvent(t)); err != nil {
		t.Fatal(err)
	}
	if dispatcher.tenantID != "tenant-1" || dispatcher.channelID != "channel-public" ||
		dispatcher.severity != "high" {
		t.Fatalf("dispatch identity = %+v", dispatcher)
	}
	wantBody := map[string]any{
		"public_event_id":  "evt-public",
		"operation_id":     "op-public",
		"event_type":       "tool_attempt_blocked",
		"risk_subcategory": "filesystem_delete",
		"reason_summary":   "deterministic_destructive_operation",
		"target_summary":   "filesystem_delete:1-targets",
		"final_action":     "block",
	}
	if !reflect.DeepEqual(dispatcher.body, wantBody) {
		t.Fatalf("notification body = %#v want %#v", dispatcher.body, wantBody)
	}
}

func TestProcessorReturnsDispatchFailureForOutboxRetry(t *testing.T) {
	dispatcher := &fakeDispatcher{err: errors.New("connector unavailable")}
	err := NewProcessor(dispatcher).Process(context.Background(), destructiveNotificationEvent(t))
	if err == nil || err.Error() != "connector unavailable" {
		t.Fatalf("dispatch error = %v", err)
	}
}

func TestProcessorIgnoresUnrelatedOutboxEvents(t *testing.T) {
	dispatcher := &fakeDispatcher{err: errors.New("must not dispatch")}
	err := NewProcessor(dispatcher).Process(context.Background(), outbox.Event{
		Type: eventbus.EventTypeAuditSecurityEventWrite, TenantID: "tenant-1",
	})
	if err != nil || dispatcher.tenantID != "" {
		t.Fatalf("unrelated event was dispatched: err=%v dispatcher=%+v", err, dispatcher)
	}
}
