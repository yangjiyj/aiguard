package eventbus

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type fakeStreamClient struct {
	stream string
	values map[string]any
	maxLen int64
	err    error
}

func (f *fakeStreamClient) XAdd(ctx context.Context, stream string, values map[string]any, maxLen int64) (string, error) {
	f.stream = stream
	f.values = values
	f.maxLen = maxLen
	if f.err != nil {
		return "", f.err
	}
	return "1700000000000-0", nil
}

func TestPublisherSerializesEvent(t *testing.T) {
	fake := &fakeStreamClient{}
	publisher := NewPublisher(fake, "custom.events", 1000)
	event, err := NewEvent(EventTypeGatewayRequestCompleted, "tenant_default", "trace_1", "req_1", time.Now().UTC(), map[string]any{"status": "success"})
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}
	id, err := publisher.Publish(context.Background(), event)
	if err != nil {
		t.Fatalf("Publish returned error: %v", err)
	}
	if id != "1700000000000-0" {
		t.Fatalf("stream id = %q", id)
	}
	if fake.stream != "custom.events" {
		t.Fatalf("stream = %q", fake.stream)
	}
	if fake.maxLen != 1000 {
		t.Fatalf("maxLen = %d", fake.maxLen)
	}
	raw, ok := fake.values["event"].(string)
	if !ok || raw == "" {
		t.Fatalf("event payload missing: %#v", fake.values)
	}
	var decoded Event
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("payload is not event JSON: %v", err)
	}
	if decoded.ID != event.ID {
		t.Fatalf("decoded id = %q, want %q", decoded.ID, event.ID)
	}
}

func TestPublisherRejectsInvalidEvent(t *testing.T) {
	fake := &fakeStreamClient{}
	publisher := NewPublisher(fake, "custom.events", 1000)
	_, err := publisher.Publish(context.Background(), Event{})
	if err == nil {
		t.Fatal("Publish should reject invalid event")
	}
	if fake.values != nil {
		t.Fatalf("invalid event should not be published: %#v", fake.values)
	}
}

func TestPublisherDefaults(t *testing.T) {
	if DefaultStreamName != "jjdguard.events" {
		t.Fatalf("DefaultStreamName = %q, want jjdguard.events", DefaultStreamName)
	}
	fake := &fakeStreamClient{}
	publisher := NewPublisher(fake, "", 0)
	event, err := NewEvent(EventTypeUsageRollupUpdated, "tenant_default", "trace_1", "req_1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}
	if _, err := publisher.Publish(context.Background(), event); err != nil {
		t.Fatalf("Publish returned error: %v", err)
	}
	if fake.stream != DefaultStreamName {
		t.Fatalf("default stream = %q, want %q", fake.stream, DefaultStreamName)
	}
}

func TestPublisherReturnsClientError(t *testing.T) {
	fake := &fakeStreamClient{err: errors.New("redis down")}
	publisher := NewPublisher(fake, "custom.events", 1000)
	event, err := NewEvent(EventTypeAlertGroupUpdated, "tenant_default", "trace_1", "req_1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}
	if _, err := publisher.Publish(context.Background(), event); err == nil {
		t.Fatal("Publish should return client error")
	}
}
