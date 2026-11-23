package auditpipe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
	"github.com/yangjiyj/aiguard/packages/shared-go/outbox"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type dbExecutor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

type Sink struct {
	db               dbExecutor
	environmentScope string
}

func NewSink(db dbExecutor, environmentScope string) *Sink {
	return &Sink{db: db, environmentScope: retentionartifact.NormalizeEnvironmentScope(environmentScope)}
}

func (s *Sink) environmentScopeFor(snapshot eventbus.RequestLogSnapshot) string {
	if s == nil {
		return retentionartifact.ResolveEnvironmentScope(snapshot.EnvironmentScope, "")
	}
	return retentionartifact.ResolveEnvironmentScope(snapshot.EnvironmentScope, s.environmentScope)
}

func (s *Sink) Process(ctx context.Context, event outbox.Event) error {
	if s == nil || s.db == nil {
		return errors.New("audit sink db is required")
	}
	switch event.Type {
	case eventbus.EventTypeAuditContentLogRequested:
		var payload eventbus.AuditContentLogPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return fmt.Errorf("decode content log payload: %w", err)
		}
		return s.writeContentLog(ctx, payload.NormalizeCreatedAt(time.Now().UTC()))
	case eventbus.EventTypeAuditSecurityEventWrite:
		var payload eventbus.AuditSecurityEventPayload
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return fmt.Errorf("decode security event payload: %w", err)
		}
		return s.writeSecurityEvent(ctx, payload.NormalizeCreatedAt(time.Now().UTC()))
	default:
		return nil
	}
}

func (s *Sink) writeContentLog(ctx context.Context, payload eventbus.AuditContentLogPayload) error {
	if err := validateContentPayload(payload); err != nil {
		return err
	}
	sessionID := payload.RequestLog.SessionID
	if sessionID == "" {
		sessionID = payload.RequestLog.RequestID
	}
	_, err := s.db.Exec(ctx, `
		WITH request_log AS (
			INSERT INTO request_logs (
				id, request_id, tenant_id, project_id, user_id, client_id, provider_id, model_id,
				session_id, agent_type, endpoint_type, trace_id, lse_eval_run_id, lse_task_id,
				lse_sample_id, lse_target_id, request_status, proxy_access_type_resolved, source_ip, created_at,
				environment_scope, proxy_mode, proxy_user_agent, agent_identity_headers, agent_detection_source, agent_instance_id
			) VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''),
				$9, NULLIF($10, ''), NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, ''), NULLIF($14, ''),
				NULLIF($15, ''), NULLIF($16, ''), 'received', $25, NULLIF($24, ''), $17, $27, 'chat_completion', $28, COALESCE(NULLIF($29, ''), '{}')::jsonb, NULLIF($30, ''), NULLIF($31, ''))
			ON CONFLICT (request_id) DO UPDATE SET
				request_id = EXCLUDED.request_id,
				environment_scope = CASE
					WHEN request_logs.environment_scope = 'legacy-unclassified' THEN EXCLUDED.environment_scope
					ELSE request_logs.environment_scope
				END
			RETURNING id
		)
		-- content_logs 是兼容视图（987），不支持 ON CONFLICT：已存在的 id 只按原语义补 environment_scope，
		-- 不存在才插入（由视图触发器写入消息行与去重后的正文）。
		, existing AS (
			UPDATE content_logs cl SET environment_scope = $27
			WHERE cl.id = $18 AND cl.environment_scope = 'legacy-unclassified' AND $27 <> 'legacy-unclassified'
				AND EXISTS (SELECT 1 FROM request_log)
			RETURNING cl.id
		)
		INSERT INTO content_logs (id, request_id, tenant_id, user_id, session_id, role, content, tokens, created_at, message_index, environment_scope)
		SELECT $18, request_log.id, $3, NULLIF($5, ''), $19, $20, $21, $22, $23, $26, $27
		FROM request_log
		WHERE NOT EXISTS (SELECT 1 FROM content_logs cl WHERE cl.id = $18)
	`, requestLogID(), payload.RequestLog.RequestID, payload.RequestLog.TenantID, payload.RequestLog.ProjectID,
		payload.RequestLog.UserID, payload.RequestLog.ClientID, payload.RequestLog.ProviderID, payload.RequestLog.ModelID,
		payload.RequestLog.SessionID, payload.RequestLog.AgentType, payload.RequestLog.EndpointType, payload.RequestLog.TraceID,
		payload.RequestLog.LSEEvalRunID, payload.RequestLog.LSETaskID, payload.RequestLog.LSESampleID, payload.RequestLog.LSETargetID,
		payload.RequestLog.CreatedAt, payload.LogID, sessionID, payload.Role, payload.Content, payload.Tokens, payload.CreatedAt,
		payload.RequestLog.SourceIP, resolvedProxyAccessType(payload.RequestLog.ModelID), payload.MessageIndex,
		s.environmentScopeFor(payload.RequestLog), payload.RequestLog.UserAgent, payload.RequestLog.AgentIdentityHeaders, payload.RequestLog.AgentDetectionSource, payload.RequestLog.AgentInstanceID)
	if err != nil {
		return fmt.Errorf("write content log: %w", err)
	}
	if inferred := agentdetect.InferFromContentRole(payload.Role, payload.Content); inferred != "" {
		if _, err := s.db.Exec(ctx, `
			UPDATE request_logs
			SET agent_type = $1
			WHERE tenant_id = $2
			  AND request_id = $3
			  AND COALESCE(agent_type, '') = ''
		`, inferred, payload.RequestLog.TenantID, payload.RequestLog.RequestID); err != nil {
			return fmt.Errorf("backfill request agent type: %w", err)
		}
	}
	return nil
}

// principalKeyFromSnapshot 物化 principal_key = COALESCE(user_id, client_id, source_ip)
// （契约第 6 条，Go 侧 COALESCE；与 gateway 同步路径 principalKeyFromEnvelope 同语义）。
func principalKeyFromSnapshot(s eventbus.RequestLogSnapshot) string {
	for _, v := range []string{s.UserID, s.ClientID, s.SourceIP} {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (s *Sink) writeSecurityEvent(ctx context.Context, payload eventbus.AuditSecurityEventPayload) error {
	if err := validateSecurityPayload(payload); err != nil {
		return err
	}
	matchedSummaryJSON, err := json.Marshal(payload.MatchedSummary)
	if err != nil {
		return fmt.Errorf("marshal security matched summary: %w", err)
	}
	_, err = s.db.Exec(ctx, `
		WITH request_log AS (
			INSERT INTO request_logs (
				id, request_id, tenant_id, project_id, user_id, client_id, provider_id, model_id,
				session_id, agent_type, endpoint_type, trace_id, lse_eval_run_id, lse_task_id,
				lse_sample_id, lse_target_id, request_status, proxy_access_type_resolved, source_ip, created_at,
				environment_scope, agent_instance_id
			) VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''),
				$9, NULLIF($10, ''), NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, ''), NULLIF($14, ''),
				NULLIF($15, ''), NULLIF($16, ''), 'received', $27, NULLIF($26, ''), $17, $32, NULLIF($33, ''))
			ON CONFLICT (request_id) DO UPDATE SET
				request_id = EXCLUDED.request_id,
				environment_scope = CASE
					WHEN request_logs.environment_scope = 'legacy-unclassified' THEN EXCLUDED.environment_scope
					ELSE request_logs.environment_scope
				END
			RETURNING request_id
		)
		INSERT INTO security_events (
			id, request_id, tenant_id, project_id, user_id, event_type, severity, rule_id,
			action_taken, matched_summary, evidence_ref, created_at, principal_key, conversation_key,
			effective_severity, class_key, agent_instance_id
		)
		SELECT $18, request_log.request_id, $3, $4, NULLIF($5, ''), $19, $20, NULLIF($21, ''),
		       $22, $23::jsonb, NULLIF($24, ''), $25, NULLIF($28, ''), NULLIF($29, ''),
		       NULLIF($30, ''), NULLIF($31, ''), NULLIF($33, '')
		FROM request_log
		ON CONFLICT (id) DO UPDATE SET
			severity = EXCLUDED.severity,
			action_taken = EXCLUDED.action_taken,
			matched_summary = EXCLUDED.matched_summary,
			evidence_ref = EXCLUDED.evidence_ref,
			principal_key = COALESCE(EXCLUDED.principal_key, security_events.principal_key),
			conversation_key = COALESCE(EXCLUDED.conversation_key, security_events.conversation_key),
			effective_severity = COALESCE(EXCLUDED.effective_severity, security_events.effective_severity),
			class_key = COALESCE(EXCLUDED.class_key, security_events.class_key)
	`, requestLogID(), payload.RequestLog.RequestID, payload.RequestLog.TenantID, payload.RequestLog.ProjectID,
		payload.RequestLog.UserID, payload.RequestLog.ClientID, payload.RequestLog.ProviderID, payload.RequestLog.ModelID,
		payload.RequestLog.SessionID, payload.RequestLog.AgentType, payload.RequestLog.EndpointType, payload.RequestLog.TraceID,
		payload.RequestLog.LSEEvalRunID, payload.RequestLog.LSETaskID, payload.RequestLog.LSESampleID, payload.RequestLog.LSETargetID,
		payload.RequestLog.CreatedAt, payload.EventID, payload.EventType, payload.Severity, payload.RuleID,
		payload.ActionTaken, string(matchedSummaryJSON), payload.EvidenceRef, payload.CreatedAt,
		payload.RequestLog.SourceIP, resolvedProxyAccessType(payload.RequestLog.ModelID),
		principalKeyFromSnapshot(payload.RequestLog), payload.ConversationKey,
		payload.EffectiveSeverity, payload.ClassKey, s.environmentScopeFor(payload.RequestLog), payload.RequestLog.AgentInstanceID)
	if err != nil {
		return fmt.Errorf("write security event: %w", err)
	}
	return nil
}

func validateContentPayload(payload eventbus.AuditContentLogPayload) error {
	if strings.TrimSpace(payload.LogID) == "" || strings.TrimSpace(payload.Role) == "" || payload.Content == "" {
		return errors.New("content log payload missing required fields")
	}
	return validateRequestLogSnapshot(payload.RequestLog)
}

func validateSecurityPayload(payload eventbus.AuditSecurityEventPayload) error {
	if strings.TrimSpace(payload.EventID) == "" || strings.TrimSpace(payload.EventType) == "" || strings.TrimSpace(payload.Severity) == "" || strings.TrimSpace(payload.ActionTaken) == "" {
		return errors.New("security event payload missing required fields")
	}
	return validateRequestLogSnapshot(payload.RequestLog)
}

func validateRequestLogSnapshot(snapshot eventbus.RequestLogSnapshot) error {
	if strings.TrimSpace(snapshot.RequestID) == "" || strings.TrimSpace(snapshot.TenantID) == "" || strings.TrimSpace(snapshot.ProjectID) == "" {
		return errors.New("request log snapshot missing required fields")
	}
	return nil
}

func requestLogID() string {
	randomHex := strings.ReplaceAll(uuid.NewString(), "-", "")
	return "log_" + randomHex[:24]
}

// resolvedProxyAccessType 对齐 gateway-core 写入侧同名函数的口径（model_id 非空即 llm）。
// 兜底 INSERT 若漏写该列会落 DEFAULT 'normal_public'，带 model_id 的行被 rollup 的
// ai_request_count（「请求数只算大模型」）漏算，且 gateway 预插入失败时无人回来修正。
func resolvedProxyAccessType(modelID string) string {
	if modelID != "" {
		return "llm"
	}
	return "normal_public"
}
