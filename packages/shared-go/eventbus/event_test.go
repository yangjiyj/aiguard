package eventbus

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewEventFillsRequiredFields(t *testing.T) {
	occurredAt := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	event, err := NewEvent(EventTypeGatewayRequestCompleted, "tenant_default", "trace_1", "req_1", occurredAt, map[string]any{"status": "success"})
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}
	if event.ID == "" {
		t.Fatal("event ID should be generated")
	}
	if event.SchemaVersion != SchemaVersionV1 {
		t.Fatalf("schema version = %q, want %q", event.SchemaVersion, SchemaVersionV1)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestEventValidateRejectsMissingRequiredFields(t *testing.T) {
	event := Event{Type: EventTypeGatewayRequestCompleted, TenantID: "tenant_default", SchemaVersion: SchemaVersionV1}
	if err := event.Validate(); err == nil {
		t.Fatal("Validate should reject missing id and occurred_at")
	}
}

func TestEventPayloadDoesNotAcceptOversizedContent(t *testing.T) {
	payload := map[string]any{"content": string(make([]byte, MaxPayloadBytes+1))}
	_, err := NewEvent(EventTypeGatewayRequestCompleted, "tenant_default", "trace_1", "req_1", time.Now().UTC(), payload)
	if err == nil {
		t.Fatal("NewEvent should reject oversized payload")
	}
}

func TestAuditContentLogEventAllowsLargeEvidencePayload(t *testing.T) {
	payload := map[string]any{"content": string(make([]byte, MaxPayloadBytes+1))}
	if _, err := NewEvent(EventTypeAuditContentLogRequested, "tenant_default", "trace_1", "req_1", time.Now().UTC(), payload); err != nil {
		t.Fatalf("audit content outbox event should allow large evidence payload: %v", err)
	}
}

func TestEventJSONRoundTrip(t *testing.T) {
	event, err := NewEvent(EventTypeSecurityFindingDetected, "tenant_default", "trace_1", "req_1", time.Now().UTC(), map[string]any{"severity": "high"})
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if decoded.ID != event.ID || decoded.Type != event.Type || decoded.TenantID != event.TenantID {
		t.Fatalf("decoded event mismatch: %#v vs %#v", decoded, event)
	}
}

func TestEventValidateRejectsUnknownTypes(t *testing.T) {
	event, err := NewEvent(EventTypeGatewayRequestCompleted, "tenant_default", "trace_1", "req_1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}
	event.Type = "unknown.event"
	if err := event.Validate(); err == nil {
		t.Fatal("Validate should reject unknown event type")
	}
}

// 2.9.22 起安全事件写入带命中原文和前后文，单独放宽到 1MB；其他事件类型仍是 64KB。
func TestSecurityEventWriteAllowsOneMegabytePayload(t *testing.T) {
	within := map[string]any{"matched_summary": strings.Repeat("a", MaxSecurityEventPayloadBytes-64)}
	if _, err := NewEvent(EventTypeAuditSecurityEventWrite, "tenant_default", "trace_1", "req_1", time.Now().UTC(), within); err != nil {
		t.Fatalf("安全事件写入 1MB 以内应能入队: %v", err)
	}
	over := map[string]any{"matched_summary": strings.Repeat("a", MaxSecurityEventPayloadBytes+1)}
	if _, err := NewEvent(EventTypeAuditSecurityEventWrite, "tenant_default", "trace_1", "req_1", time.Now().UTC(), over); err == nil {
		t.Fatal("安全事件写入超过 1MB 仍应拒绝")
	}
	if MaxSecurityEventPayloadBytes != 1024*1024 {
		t.Fatalf("上限应为 1MB: %d", MaxSecurityEventPayloadBytes)
	}
	other := map[string]any{"content": string(make([]byte, MaxPayloadBytes+1))}
	for _, eventType := range []string{EventTypeSecurityFindingDetected, EventTypeGatewayRequestCompleted, EventTypeAlertGroupUpdated} {
		if _, err := NewEvent(eventType, "tenant_default", "trace_1", "req_1", time.Now().UTC(), other); err == nil {
			t.Fatalf("%s 仍受 64KB 上限", eventType)
		}
	}
}
