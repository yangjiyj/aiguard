package handler

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
)

type fakeSyncAuditWriter struct {
	contentWrites    int
	securityWrites   int
	occurrenceWrites int
	anchoredIndex    *int
}

func (f *fakeSyncAuditWriter) EnsureRequestLog(ctx context.Context, envelope *modelrouter.RequestEnvelope) {
}
func (f *fakeSyncAuditWriter) FinalizeRequestLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, respBody []byte, status string, upstreamStatusCode int, latencyMs int, auditResult *AuditResult) {
}
func (f *fakeSyncAuditWriter) WriteSecurityEvent(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding, actionTaken, summary string) {
	f.securityWrites++
}
func (f *fakeSyncAuditWriter) WriteContentLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens int) {
	f.contentWrites++
}
func (f *fakeSyncAuditWriter) WriteContentLogAnchored(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens, messageIndex int) {
	f.contentWrites++
	f.anchoredIndex = &messageIndex
}
func (f *fakeSyncAuditWriter) UpsertAgentSession(ctx context.Context, envelope *modelrouter.RequestEnvelope) {
}
func (f *fakeSyncAuditWriter) AnnotateTriage(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding) {
}
func (f *fakeSyncAuditWriter) RecordSecurityEventOccurrence(ctx context.Context, envelope *modelrouter.RequestEnvelope, representativeEventID, contextKey string) error {
	f.occurrenceWrites++
	return nil
}

type fakeOutboxEnqueuer struct {
	events []eventbus.Event
	err    error
}

func (f *fakeOutboxEnqueuer) Enqueue(ctx context.Context, event eventbus.Event) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, event)
	return nil
}

func TestAsyncAuditWriterWriteContentLogEnqueuesOutboxEvent(t *testing.T) {
	syncWriter := &fakeSyncAuditWriter{}
	outbox := &fakeOutboxEnqueuer{}
	writer := NewAsyncAuditWriter(syncWriter, outbox)
	writer.now = func() time.Time { return time.Date(2026, 6, 19, 9, 0, 0, 0, time.UTC) }
	envelope := asyncAuditTestEnvelope()

	writer.WriteContentLog(context.Background(), envelope, "user", "hello", 3)

	if syncWriter.contentWrites != 0 {
		t.Fatalf("content log should not be synchronously written when enqueue succeeds")
	}
	if len(outbox.events) != 1 {
		t.Fatalf("expected 1 outbox event, got %d", len(outbox.events))
	}
	event := outbox.events[0]
	if event.Type != eventbus.EventTypeAuditContentLogRequested {
		t.Fatalf("event type = %s", event.Type)
	}
	var payload eventbus.AuditContentLogPayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if !strings.HasPrefix(payload.LogID, "cl_") || payload.Content != "hello" || payload.Tokens != 3 {
		t.Fatalf("unexpected content payload: %#v", payload)
	}
	if entropy := strings.TrimPrefix(payload.LogID, "cl_"); len(entropy) < 24 {
		t.Fatalf("content log id %q has only %d hex chars of entropy, want at least 24", payload.LogID, len(entropy))
	}
	if payload.RequestLog.RequestID != envelope.RequestID || payload.RequestLog.TraceID != envelope.TraceID {
		t.Fatalf("request snapshot mismatch: %#v", payload.RequestLog)
	}
	if payload.RequestLog.EnvironmentScope != "customer" {
		t.Fatalf("request snapshot scope = %q, want customer", payload.RequestLog.EnvironmentScope)
	}
}

func TestAsyncAuditWriterWriteContentLogAnchoredPreservesZeroIndex(t *testing.T) {
	syncWriter := &fakeSyncAuditWriter{}
	outbox := &fakeOutboxEnqueuer{}
	writer := NewAsyncAuditWriter(syncWriter, outbox)

	writer.WriteContentLogAnchored(context.Background(), asyncAuditTestEnvelope(), "user", "first", 0, 0)

	var payload eventbus.AuditContentLogPayload
	if err := json.Unmarshal(outbox.events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.MessageIndex == nil || *payload.MessageIndex != 0 {
		t.Fatalf("message index = %v, want anchored zero", payload.MessageIndex)
	}
}

func TestAsyncAuditWriterAnchoredFallbackPreservesIndex(t *testing.T) {
	syncWriter := &fakeSyncAuditWriter{}
	writer := NewAsyncAuditWriter(syncWriter, &fakeOutboxEnqueuer{err: errors.New("outbox down")})

	writer.WriteContentLogAnchored(context.Background(), asyncAuditTestEnvelope(), "user", "third", 0, 2)

	if syncWriter.anchoredIndex == nil || *syncWriter.anchoredIndex != 2 {
		t.Fatalf("sync fallback index = %v, want 2", syncWriter.anchoredIndex)
	}
}

func TestAsyncAuditWriterWriteSecurityEventEnqueuesComputedPayload(t *testing.T) {
	syncWriter := &fakeSyncAuditWriter{}
	outbox := &fakeOutboxEnqueuer{}
	writer := NewAsyncAuditWriter(syncWriter, outbox)
	writer.now = func() time.Time { return time.Date(2026, 6, 19, 9, 0, 0, 0, time.UTC) }
	envelope := asyncAuditTestEnvelope()
	envelope.ConversationKey = "ck_test"
	findings := []SecurityFinding{{Type: "custom", Category: "medical_id", Severity: "high", RuleID: "rule_bah_001", Action: "block"}}

	writer.WriteSecurityEvent(context.Background(), envelope, findings, "block", "病案号外发拦截")

	if syncWriter.securityWrites != 0 {
		t.Fatalf("security event should not be synchronously written when enqueue succeeds")
	}
	if len(outbox.events) != 1 {
		t.Fatalf("expected 1 outbox event, got %d", len(outbox.events))
	}
	var payload eventbus.AuditSecurityEventPayload
	if err := json.Unmarshal(outbox.events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.EventType != "data_security" || payload.Severity != "high" || payload.EffectiveSeverity != "high" || payload.ClassKey != "medical_id" || payload.RuleID != "rule_bah_001" {
		t.Fatalf("unexpected security payload: %#v", payload)
	}
	if entropy := strings.TrimPrefix(payload.EventID, "evt_"); len(entropy) < 24 {
		t.Fatalf("security event id %q has only %d hex chars of entropy, want at least 24", payload.EventID, len(entropy))
	}
	if payload.MatchedSummary["action_taken"] != "block" || payload.MatchedSummary["summary"] != "病案号外发拦截" {
		t.Fatalf("matched summary mismatch: %#v", payload.MatchedSummary)
	}
	if payload.ConversationKey != "ck_test" {
		t.Fatalf("payload 应携带 envelope.ConversationKey, got %q", payload.ConversationKey)
	}
}

func TestAsyncAuditWriterDelegatesSecurityOccurrenceDurably(t *testing.T) {
	syncWriter := &fakeSyncAuditWriter{}
	outbox := &fakeOutboxEnqueuer{}
	writer := NewAsyncAuditWriter(syncWriter, outbox)

	if err := writer.RecordSecurityEventOccurrence(
		context.Background(), asyncAuditTestEnvelope(), "evt-first", "context-key",
	); err != nil {
		t.Fatalf("record occurrence: %v", err)
	}
	if syncWriter.occurrenceWrites != 1 {
		t.Fatalf("occurrence must be delegated to durable sync writer, got %d", syncWriter.occurrenceWrites)
	}
	if len(outbox.events) != 0 {
		t.Fatalf("occurrence should not enqueue an unsupported event type: %+v", outbox.events)
	}
}

func TestAsyncAuditWriterFallsBackToSyncWriterWhenEnqueueFails(t *testing.T) {
	syncWriter := &fakeSyncAuditWriter{}
	writer := NewAsyncAuditWriter(syncWriter, &fakeOutboxEnqueuer{err: errors.New("outbox down")})
	writer.WriteContentLog(context.Background(), asyncAuditTestEnvelope(), "user", "hello", 3)

	if syncWriter.contentWrites != 1 {
		t.Fatalf("expected sync fallback, got %d writes", syncWriter.contentWrites)
	}
}

func asyncAuditTestEnvelope() *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{
		RequestID:        "req_1",
		TenantID:         "tenant_1",
		ProjectID:        "project_1",
		UserID:           "user_1",
		ClientID:         "client_1",
		EnvironmentScope: "customer",
		ProviderID:       "provider_1",
		ModelID:          "model_1",
		SessionID:        "session_1",
		AgentType:        "claude-code",
		EndpointType:     "chat",
		TraceID:          "trace_1",
	}
}
