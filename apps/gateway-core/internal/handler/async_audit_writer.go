package handler

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
)

type outboxEnqueuer interface {
	Enqueue(ctx context.Context, event eventbus.Event) error
}

// AsyncAuditWriter keeps the request hot path thin by enqueueing heavy evidence
// writes into the durable outbox. If enqueue fails, it falls back to the wrapped
// synchronous writer so audit evidence is not silently dropped.
type AsyncAuditWriter struct {
	syncWriter AuditWriter
	outbox     outboxEnqueuer
	now        func() time.Time
}

func NewAsyncAuditWriter(syncWriter AuditWriter, outbox outboxEnqueuer) *AsyncAuditWriter {
	return &AsyncAuditWriter{syncWriter: syncWriter, outbox: outbox, now: time.Now}
}

// EnsureRequestLog 转发给内层；脱离请求取消由内层 RealAuditWriter 入口负责。
func (w *AsyncAuditWriter) EnsureRequestLog(ctx context.Context, envelope *modelrouter.RequestEnvelope) {
	if w != nil && w.syncWriter != nil {
		w.syncWriter.EnsureRequestLog(ctx, envelope)
	}
}

// FinalizeRequestLog 转发给内层；脱离请求取消由内层 RealAuditWriter 入口负责。
func (w *AsyncAuditWriter) FinalizeRequestLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, respBody []byte, status string, upstreamStatusCode int, latencyMs int, auditResult *AuditResult) {
	if w != nil && w.syncWriter != nil {
		w.syncWriter.FinalizeRequestLog(ctx, envelope, respBody, status, upstreamStatusCode, latencyMs, auditResult)
	}
}

// RecordRuntimeFault 不走 outbox：平台级运行告警十分钟至多一条，直接写内层并报告结果。
// 调用方 RuntimeFaultEventWriter 在后台 goroutine 里调它，不占请求路径。
func (w *AsyncAuditWriter) RecordRuntimeFault(ctx context.Context, envelope *modelrouter.RequestEnvelope, summary string) error {
	if w == nil || w.syncWriter == nil {
		return fmt.Errorf("runtime fault writer is unavailable")
	}
	return recordRuntimeFault(ctx, w.syncWriter, envelope, summary)
}

// Procurement settlement cannot wait for an outbox route update.
func (w *AsyncAuditWriter) PersistBillingRoute(ctx context.Context, envelope *modelrouter.RequestEnvelope) error {
	if w == nil || w.syncWriter == nil {
		return fmt.Errorf("billing route writer is unavailable")
	}
	if writer, ok := w.syncWriter.(billingRouteWriter); ok {
		return writer.PersistBillingRoute(ctx, envelope)
	}
	return nil
}

// MarkBillingOutcome 转发给内层；脱离请求取消由内层 RealAuditWriter 入口负责。
func (w *AsyncAuditWriter) MarkBillingOutcome(ctx context.Context, envelope *modelrouter.RequestEnvelope, outcome string) {
	if w == nil || w.syncWriter == nil {
		return
	}
	if outcomeWriter, ok := w.syncWriter.(billingOutcomeWriter); ok {
		outcomeWriter.MarkBillingOutcome(ctx, envelope, outcome)
	}
}

func (w *AsyncAuditWriter) WriteSecurityEvent(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding, actionTaken, summary string) {
	// A block is always persisted: it is the record the agent's notice points to.
	if !writerPersists(ctx, findings, actionTaken) {
		return
	}
	if envelope == nil {
		return
	}
	now := w.nowUTC()
	matchedSummary := buildSecurityMatchedSummary(findings, actionTaken, summary)
	// 请求识别标签只进 request_labels，不参与事件分级、分桶与规则归属（与 RealAuditWriter 一致）。
	findings, _ = splitRequestContextLabels(findings)
	annotateSecurityEventStage(ctx, matchedSummary)
	annotateFingerprintReuse(ctx, matchedSummary)
	eventType := eventTypeForFindings(findings)
	effectiveSeverity := securityEventEffectiveSeverity(findings, matchedSummary)
	classKey := securityEventClassKey(findings, eventType)
	eventID := securityEventIDFromContext(ctx)
	if eventID == "" {
		eventID = newAuditID("evt_")
	}
	annotateSecurityEventBlock(ctx, envelope, eventID, findings, actionTaken, summary, matchedSummary)
	payload := eventbus.AuditSecurityEventPayload{
		RequestLog:        requestLogSnapshotFromEnvelope(envelope, now),
		EventID:           eventID,
		EventType:         eventType,
		Severity:          getFindingsSeverity(findings),
		EffectiveSeverity: effectiveSeverity,
		ClassKey:          classKey,
		RuleID:            firstPersistablePolicyRuleID(findings),
		ActionTaken:       actionTaken,
		MatchedSummary:    matchedSummary,
		ConversationKey:   envelope.ConversationKey,
		CreatedAt:         now,
	}.NormalizeCreatedAt(now)

	if err := w.enqueue(ctx, eventbus.EventTypeAuditSecurityEventWrite, envelope, payload, now); err != nil {
		log.Printf("[audit.async] security event enqueue failed request_id=%s: %v", envelope.RequestID, err)
		if w.syncWriter != nil {
			// Preserve the ID already embedded in the notice/outbox payload. An
			// ambiguous enqueue failure must not create a second unsearchable ID.
			fallbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			w.syncWriter.WriteSecurityEvent(withSecurityEventID(fallbackCtx, eventID), envelope, findings, actionTaken, summary)
		} else {
			forgetBlockRecord(ctx, eventID)
		}
	}
}

// RecordSecurityEventOccurrence delegates the small idempotent ledger write to
// the synchronous writer. It must be durable before the duplicate full event is
// suppressed; unsupported writers return an error so the caller keeps full evidence.
func (w *AsyncAuditWriter) RecordSecurityEventOccurrence(
	ctx context.Context,
	envelope *modelrouter.RequestEnvelope,
	representativeEventID, contextKey string,
) error {
	if w == nil || w.syncWriter == nil {
		return fmt.Errorf("security occurrence writer is unavailable")
	}
	recorder, ok := w.syncWriter.(securityOccurrenceRecorder)
	if !ok {
		return fmt.Errorf("security occurrence writer is unsupported")
	}
	return recorder.RecordSecurityEventOccurrence(ctx, envelope, representativeEventID, contextKey)
}

func (w *AsyncAuditWriter) WriteContentLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens int) {
	w.writeContentLog(ctx, envelope, role, content, tokens, nil)
}

func (w *AsyncAuditWriter) WriteContentLogAnchored(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens, messageIndex int) {
	w.writeContentLog(ctx, envelope, role, content, tokens, &messageIndex)
}

func (w *AsyncAuditWriter) writeContentLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, content string, tokens int, messageIndex *int) {
	if envelope == nil || content == "" {
		return
	}
	now := w.nowUTC()
	payload := eventbus.AuditContentLogPayload{
		RequestLog:   requestLogSnapshotFromEnvelope(envelope, now),
		LogID:        newAuditID("cl_"),
		Role:         role,
		MessageIndex: messageIndex,
		Content:      content,
		Tokens:       tokens,
		CreatedAt:    now,
	}.NormalizeCreatedAt(now)

	if err := w.enqueue(ctx, eventbus.EventTypeAuditContentLogRequested, envelope, payload, now); err != nil {
		log.Printf("[audit.async] content log enqueue failed request_id=%s: %v", envelope.RequestID, err)
		if w.syncWriter != nil {
			fallbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if messageIndex != nil {
				if anchoredWriter, ok := w.syncWriter.(AnchoredContentLogWriter); ok {
					anchoredWriter.WriteContentLogAnchored(fallbackCtx, envelope, role, content, tokens, *messageIndex)
					return
				}
			}
			w.syncWriter.WriteContentLog(fallbackCtx, envelope, role, content, tokens)
		}
	}
}

// UpsertAgentSession 转发给内层；脱离请求取消由内层 RealAuditWriter 入口负责。
func (w *AsyncAuditWriter) UpsertAgentSession(ctx context.Context, envelope *modelrouter.RequestEnvelope) {
	if w != nil && w.syncWriter != nil {
		w.syncWriter.UpsertAgentSession(ctx, envelope)
	}
}

// AnnotateTriage 委托给同步写器：triage 标注是对已落库 security_event 的 UPDATE（observe-only，
// 同步路径已先写 event 留底），非新增证据事件，故直接走 syncWriter 的 UPDATE 即可（与
// EnsureRequestLog/UpsertAgentSession 同款委托范式，不进 outbox）。
// 脱离请求取消由内层 RealAuditWriter.AnnotateTriage 入口负责。
func (w *AsyncAuditWriter) AnnotateTriage(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding) {
	if w != nil && w.syncWriter != nil {
		w.syncWriter.AnnotateTriage(ctx, envelope, findings)
	}
}

func (w *AsyncAuditWriter) enqueue(ctx context.Context, eventType string, envelope *modelrouter.RequestEnvelope, payload any, occurredAt time.Time) error {
	if w == nil || w.outbox == nil {
		return fmt.Errorf("audit outbox is unavailable")
	}
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	event, err := eventbus.NewEvent(eventType, envelope.TenantID, envelope.TraceID, envelope.RequestID, occurredAt, payload)
	if err != nil {
		return err
	}
	return w.outbox.Enqueue(ctx, event)
}

func (w *AsyncAuditWriter) nowUTC() time.Time {
	if w != nil && w.now != nil {
		return w.now().UTC()
	}
	return time.Now().UTC()
}

func requestLogSnapshotFromEnvelope(envelope *modelrouter.RequestEnvelope, now time.Time) eventbus.RequestLogSnapshot {
	if envelope == nil {
		return eventbus.RequestLogSnapshot{CreatedAt: now}
	}
	return eventbus.RequestLogSnapshot{
		AgentIdentityHeaders: envelope.AgentIdentityHeaders,
		UserAgent:            envelope.UserAgent,
		AgentDetectionSource: envelope.AgentDetectionSource,
		RequestID:            envelope.RequestID,
		TenantID:             envelope.TenantID,
		ProjectID:            envelope.ProjectID,
		UserID:               envelope.UserID,
		ClientID:             envelope.ClientID,
		EnvironmentScope:     envelope.EnvironmentScope,
		ProviderID:           envelope.ProviderID,
		ModelID:              envelope.ModelID,
		SessionID:            envelope.SessionID,
		AgentType:            envelope.AgentType,
		AgentInstanceID:      envelope.AgentInstanceID,
		EndpointType:         envelope.EndpointType,
		TraceID:              envelope.TraceID,
		LSEEvalRunID:         envelope.LSEEvalRunID,
		LSETaskID:            envelope.LSETaskID,
		LSESampleID:          envelope.LSESampleID,
		LSETargetID:          envelope.LSETargetID,
		SourceIP:             envelope.SourceIP,
		CreatedAt:            now,
	}
}
