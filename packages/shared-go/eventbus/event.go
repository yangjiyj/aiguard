package eventbus

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	SchemaVersionV1 = "v1"

	EventTypeGatewayRequestAccepted   = "gateway.request.accepted"
	EventTypeGatewayRequestCompleted  = "gateway.request.completed"
	EventTypeProxyAccessCompleted     = "proxy.access.completed"
	EventTypeSecurityFindingDetected  = "security.finding.detected"
	EventTypeRetentionObjectCreated   = "retention.object.created"
	EventTypeAlertGroupUpdated        = "alert.group.updated"
	EventTypeAuditContentLogRequested = "audit.content_log.requested"
	EventTypeAuditSecurityEventWrite  = "audit.security_event.write"
	EventTypeNotifyAgentDestructive   = "notify.agent_destructive"
	EventTypeUsageRollupUpdated       = "usage.rollup.updated"
	DefaultStreamName                 = "jjdguard.events"
	MaxPayloadBytes                   = 64 * 1024
	MaxAuditPayloadBytes              = 16 * 1024 * 1024
	// MaxSecurityEventPayloadBytes 是安全事件写入（audit.security_event.write）的载荷上限。
	// 2.9.22 起命中原文和前后文随安全事件入库，单个事件可超过通用的 64KB；其他事件类型仍按 MaxPayloadBytes。
	MaxSecurityEventPayloadBytes = 1024 * 1024
)

var knownEventTypes = map[string]struct{}{
	EventTypeGatewayRequestAccepted:   {},
	EventTypeGatewayRequestCompleted:  {},
	EventTypeProxyAccessCompleted:     {},
	EventTypeSecurityFindingDetected:  {},
	EventTypeRetentionObjectCreated:   {},
	EventTypeAlertGroupUpdated:        {},
	EventTypeAuditContentLogRequested: {},
	EventTypeAuditSecurityEventWrite:  {},
	EventTypeNotifyAgentDestructive:   {},
	EventTypeUsageRollupUpdated:       {},
}

type Event struct {
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	TenantID      string          `json:"tenant_id"`
	TraceID       string          `json:"trace_id,omitempty"`
	RequestID     string          `json:"request_id,omitempty"`
	OccurredAt    time.Time       `json:"occurred_at"`
	SchemaVersion string          `json:"schema_version"`
	Payload       json.RawMessage `json:"payload,omitempty"`
}

func NewEvent(eventType, tenantID, traceID, requestID string, occurredAt time.Time, payload any) (Event, error) {
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	raw, err := marshalPayload(eventType, payload)
	if err != nil {
		return Event{}, err
	}

	event := Event{
		ID:            "evt_" + uuid.NewString(),
		Type:          eventType,
		TenantID:      tenantID,
		TraceID:       traceID,
		RequestID:     requestID,
		OccurredAt:    occurredAt.UTC(),
		SchemaVersion: SchemaVersionV1,
		Payload:       raw,
	}
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	return event, nil
}

func (e Event) Validate() error {
	if e.ID == "" {
		return errors.New("event id is required")
	}
	if e.Type == "" {
		return errors.New("event type is required")
	}
	if _, ok := knownEventTypes[e.Type]; !ok {
		return fmt.Errorf("unknown event type: %s", e.Type)
	}
	if e.TenantID == "" {
		return errors.New("tenant id is required")
	}
	if e.OccurredAt.IsZero() {
		return errors.New("occurred_at is required")
	}
	if e.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("unsupported schema version: %s", e.SchemaVersion)
	}
	maxPayloadBytes := maxPayloadBytesForType(e.Type)
	if len(e.Payload) > maxPayloadBytes {
		return fmt.Errorf("event payload exceeds %d bytes", maxPayloadBytes)
	}
	return nil
}

func marshalPayload(eventType string, payload any) (json.RawMessage, error) {
	if payload == nil {
		return nil, nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal event payload: %w", err)
	}
	maxPayloadBytes := maxPayloadBytesForType(eventType)
	if len(raw) > maxPayloadBytes {
		return nil, fmt.Errorf("event payload exceeds %d bytes", maxPayloadBytes)
	}
	return json.RawMessage(raw), nil
}

func maxPayloadBytesForType(eventType string) int {
	switch eventType {
	case EventTypeAuditContentLogRequested:
		return MaxAuditPayloadBytes
	case EventTypeAuditSecurityEventWrite:
		return MaxSecurityEventPayloadBytes
	default:
		return MaxPayloadBytes
	}
}

func KnownEventType(eventType string) bool {
	_, ok := knownEventTypes[eventType]
	return ok
}
