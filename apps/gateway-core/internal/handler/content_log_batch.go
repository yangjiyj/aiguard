package handler

import (
	"context"
	"log"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// ContentLogEntry 是一个请求里待写入 content_logs 的一条消息。
type ContentLogEntry struct {
	Role         string
	Content      string
	Tokens       int
	MessageIndex int
}

// BatchContentLogWriter 一次写入一个请求的全部消息。
type BatchContentLogWriter interface {
	WriteContentLogsBatch(ctx context.Context, envelope *modelrouter.RequestEnvelope, entries []ContentLogEntry)
}

// WriteContentLogsBatch 用一条语句写完一个请求的全部消息（客户现场：长对话一个请求上百条消息，
// 逐条写是上百次往返、提交与 WAL 刷盘）。父请求行沿用「已存在不重写」的写法；created_at 按消息
// 顺序以微秒递增，读方按 created_at,id 排序得到的顺序与逐条写入一致。失败则逐条回退，保证不丢。
func (w *RealAuditWriter) WriteContentLogsBatch(ctx context.Context, envelope *modelrouter.RequestEnvelope, entries []ContentLogEntry) {
	if envelope == nil {
		return
	}
	kept := make([]ContentLogEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Content != "" {
			kept = append(kept, entry)
		}
	}
	if len(kept) == 0 {
		return
	}
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	ids := make([]string, len(kept))
	roles := make([]string, len(kept))
	contents := make([]string, len(kept))
	tokens := make([]int32, len(kept))
	indexes := make([]int32, len(kept))
	for i, entry := range kept {
		ids[i] = newAuditID("cl_")
		roles[i] = entry.Role
		contents[i] = entry.Content
		tokens[i] = int32(entry.Tokens)
		indexes[i] = int32(entry.MessageIndex)
	}
	query := `
		WITH request_log AS (
			INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, client_id, provider_id, model_id, session_id, agent_type, endpoint_type, trace_id, lse_eval_run_id, lse_task_id, lse_sample_id, lse_target_id, request_status, proxy_access_type_resolved, source_ip, proxy_mode, agent_runtime, agent_detection_source, agent_detection_confidence, evidence_run_id, evidence_run_source, created_at, environment_scope, proxy_user_agent, agent_identity_headers, agent_instance_id)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 'received', $17, NULLIF($18, ''), 'chat_completion', NULLIF($19, ''), NULLIF($20, ''), NULLIF($21, 0), NULLIF($22, ''), NULLIF($23, ''), NOW(), COALESCE(NULLIF($24, ''), 'legacy-unclassified'), $25, COALESCE(NULLIF($26, ''), '{}')::jsonb, NULLIF($27, ''))
			ON CONFLICT (request_id) DO NOTHING
			RETURNING id
		), parent AS (
			SELECT id FROM request_log
			UNION ALL
			SELECT rl.id FROM request_logs rl
			WHERE rl.request_id = $2 AND NOT EXISTS (SELECT 1 FROM request_log)
		)
		INSERT INTO content_logs (id, request_id, tenant_id, user_id, session_id, role, content, tokens, environment_scope, message_index, created_at)
		SELECT m.id, parent.id, $3, NULLIF($5, ''), $28, m.role, m.content, m.tokens,
		       COALESCE(NULLIF($24, ''), 'legacy-unclassified'), m.message_index,
		       LOCALTIMESTAMP + (m.ord * interval '1 microsecond')
		FROM parent
		CROSS JOIN unnest($29::text[], $30::text[], $31::text[], $32::int[], $33::int[])
		     WITH ORDINALITY AS m(id, role, content, tokens, message_index, ord)
	`
	args := []interface{}{
		newAuditID("log_"),
		envelope.RequestID,
		envelope.TenantID,
		envelope.ProjectID,
		envelope.UserID,
		envelope.ClientID,
		envelope.ProviderID,
		envelope.ModelID,
		envelope.SessionID,
		envelope.AgentType,
		envelope.EndpointType,
		envelope.TraceID,
		envelope.LSEEvalRunID,
		envelope.LSETaskID,
		envelope.LSESampleID,
		envelope.LSETargetID,
		resolvedProxyAccessType(envelope.ModelID),
		envelope.SourceIP,
		envelope.AgentRuntime,
		envelope.AgentDetectionSource,
		envelope.AgentDetectionConfidence,
		envelope.EvidenceRunID,
		envelope.EvidenceRunSource,
		envelope.EnvironmentScope,
		envelope.UserAgent,
		envelope.AgentIdentityHeaders,
		envelope.AgentInstanceID,
		contentLogSessionID(envelope),
		ids, roles, contents, tokens, indexes,
	}
	result, err := w.db.Exec(ctx, query, args...)
	// 与 writeContentLog 相同：父请求行由并发事务刚提交时本语句可能写入 0 行，换新快照重试一次。
	if err == nil && result != nil && result.RowsAffected() == 0 {
		result, err = w.db.Exec(ctx, query, args...)
	}
	if err == nil && result != nil && result.RowsAffected() == 0 {
		log.Printf("batch content log write affected 0 rows for request %s", envelope.RequestID)
	}
	if err != nil {
		log.Printf("batch content log write failed for request %s, falling back to per-message: %v", envelope.RequestID, err)
		// 逐条回退共用批量入口那一个整体预算：预算耗尽就停，不再为每条重新计时。
		for _, entry := range kept {
			if ctx.Err() != nil {
				log.Printf("batch content log fallback stopped for request %s: audit budget exhausted: %v", envelope.RequestID, ctx.Err())
				return
			}
			index := entry.MessageIndex
			w.writeContentLogWithin(ctx, envelope, entry.Role, entry.Content, entry.Tokens, &index)
		}
		return
	}
	for _, entry := range kept {
		if agentType := inferAgentTypeFromContent(entry.Role, entry.Content); agentType != "" {
			w.BackfillRequestAgentType(ctx, envelope.TenantID, envelope.RequestID, agentType)
			break
		}
	}
}

// WriteContentLogsBatch 透传给内层；内层不支持批量时逐条写。
func (w *BillingAuditWriter) WriteContentLogsBatch(ctx context.Context, e *modelrouter.RequestEnvelope, entries []ContentLogEntry) {
	if batch, ok := w.inner.(BatchContentLogWriter); ok {
		batch.WriteContentLogsBatch(ctx, e, entries)
		return
	}
	for _, entry := range entries {
		w.WriteContentLogAnchored(ctx, e, entry.Role, entry.Content, entry.Tokens, entry.MessageIndex)
	}
}

// WriteContentLogsBatch：异步模式下每条消息仍各自进 outbox（事件格式不变）。
func (w *AsyncAuditWriter) WriteContentLogsBatch(ctx context.Context, e *modelrouter.RequestEnvelope, entries []ContentLogEntry) {
	for _, entry := range entries {
		w.WriteContentLogAnchored(ctx, e, entry.Role, entry.Content, entry.Tokens, entry.MessageIndex)
	}
}
