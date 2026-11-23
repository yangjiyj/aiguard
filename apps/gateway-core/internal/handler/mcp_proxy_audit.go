package handler

// MCP 代理留痕（仿 reverse_proxy_audit.go）。顺序铁律：先同步 upsert request_logs，
// 再写 security_events（security_events.request_id 是 NOT NULL 外键，异步/乱序会丢事件）；
// 最后经 LogToolCall 回写 control-plane tool_call_logs（053 双决策列全量留痕）。
// endpoint_type='proxy' + proxy_mode='mcp'：rollup 的 ai_request_count 只统计
// endpoint_type<>'proxy' 或 llm/ai_ide 流量，MCP 代理流量因此不会污染
// 「请求数只算大模型」的客户看板口径（67e24d7 治理过）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/clientip"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

// defaultMCPProjectID 满足 security_events.project_id NOT NULL 外键；
// 鉴权链正常时用 AuthInfo.ProjectID，缺省才落占位（同反代口径）。
const defaultMCPProjectID = "project_default"

// mcpAuditTx 抽象一次审计事务（生产由 pgx.Tx 实现），便于单测注入失败并断言回滚。
type mcpAuditTx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// mcpAuditDB 抽象审计写库能力：Begin 供事务化留痕（父行 request_logs 先于子行
// security_events 原子落库），Exec 供轻审计单写（非 tools/call）。生产实现是
// mcpPgxPoolDB（包 *pgxpool.Pool），单测可注入可控失败的假实现。
type mcpAuditDB interface {
	Begin(ctx context.Context) (mcpAuditTx, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// mcpPgxPoolDB 把 *pgxpool.Pool 适配成 mcpAuditDB（pgx.Tx 天然满足 mcpAuditTx）。
type mcpPgxPoolDB struct {
	pool *pgxpool.Pool
}

func (d *mcpPgxPoolDB) Begin(ctx context.Context) (mcpAuditTx, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err // 显式返回 nil 接口，避免 pgx.Tx 空值被包成非 nil 接口
	}
	return tx, nil
}

func (d *mcpPgxPoolDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return d.pool.Exec(ctx, sql, args...)
}

type mcpProxyAuditRecorder struct {
	db mcpAuditDB
	// redlineDedupe 折叠 record 模式下重复的纯红线 security_events（复审 M-5）；nil 表示不去重。
	redlineDedupe *mcpRedlineEventDedupe
	// policyFaults 限制“MCP 策略读取失败按设置放行”的运行告警：按租户加服务 10 分钟一条（2.9.22）。
	policyFaultsOnce sync.Once
	policyFaults     *runtimeFaultLimiter
}

func (rec *mcpProxyAuditRecorder) policyFaultLimiter() *runtimeFaultLimiter {
	rec.policyFaultsOnce.Do(func() {
		if rec.policyFaults == nil {
			rec.policyFaults = newRuntimeFaultLimiter(runtimeFaultEventWindow)
		}
	})
	return rec.policyFaults
}

// mcpPolicyFaultEventArgs 是“MCP 策略读取失败、按设置放行”的运行告警：事件类型沿用检测故障，
// 原因写 semantic_reason=mcp_policy_unavailable，控制面按原因分组。
func mcpPolicyFaultEventArgs(record mcpProxyAuditRecord, d *mcpToolCallDecision) []interface{} {
	summary := map[string]interface{}{
		"source": "gateway_mcp", "stage": "tool", "category": "system",
		"counts_as_security_finding": false,
		"semantic_status":            "incomplete", "semantic_reason": mcpPolicyUnavailableReason,
		"server_id": record.ServerID, "server_name": record.ServerName, "tool_name": d.Qualified,
		"action_taken": "audit",
		"summary":      "MCP 策略读取失败，按 mcp_policy_fail_mode=open 放行，只记录覆盖缺口",
	}
	matchedJSON, _ := json.Marshal(summary)
	return []interface{}{
		"evt_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:16],
		record.RequestID, record.TenantID, record.ProjectID,
		"security_check_failed", "low", "", "audit", matchedJSON,
		"request_logs:" + record.RequestID, mcpPrincipalKey(record),
	}
}

func newMCPProxyAuditRecorder(db *pgxpool.Pool) *mcpProxyAuditRecorder {
	if db == nil {
		return nil
	}
	return &mcpProxyAuditRecorder{db: &mcpPgxPoolDB{pool: db}, redlineDedupe: newMCPRedlineEventDedupe(mcpRedlineEventDedupeWindowFromEnv())}
}

// mcpProxyAuditRecord 是一次 MCP 代理请求的访问留痕行。
type mcpProxyAuditRecord struct {
	RequestID string
	TenantID  string
	ProjectID string
	UserID    string
	SessionID string
	TraceID   string
	// LSE 关联四元组：与反代 reverse_proxy_audit.go 同口径落 request_logs 的
	// lse_eval_run_id/task/sample/target 列，供 LSE 测-堵-验闭环按 eval_run/task/
	// sample/target 维度归并 MCP 审计（trace_id 单跳之外的多维归因）。
	LSEEvalRunID     string
	LSETaskID        string
	LSESampleID      string
	LSETargetID      string
	AgentType        string
	ServerID         string
	ServerName       string
	TargetHost       string
	TargetPath       string
	Method           string
	SourceIP         string
	UserAgent        string
	ClientID         string
	EnvironmentScope string
	RequestBytes     int64
	ResponseBytes    int64
	Status           string
	StatusCode       int
	LatencyMS        int
}

// newMCPAuditRecord 从鉴权信息 + server 行组装访问留痕行。
func (h *MCPProxyHandler) newMCPAuditRecord(info *auth.AuthInfo, server *mcpServerRoute, r *http.Request, requestBytes, responseBytes int64, status string, statusCode int, latency time.Duration) mcpProxyAuditRecord {
	record := mcpProxyAuditRecord{
		Method:        r.Method,
		UserAgent:     r.UserAgent(),
		SourceIP:      clientip.ClientIP(r),
		RequestBytes:  requestBytes,
		ResponseBytes: responseBytes,
		Status:        status,
		StatusCode:    statusCode,
		LatencyMS:     int(latency / time.Millisecond),
	}
	if info != nil {
		record.RequestID = info.RequestID
		record.TenantID = info.TenantID
		record.ProjectID = info.ProjectID
		record.UserID = info.UserID
		record.SessionID = info.SessionID
		record.TraceID = info.TraceID
		record.LSEEvalRunID = info.LSEEvalRunID
		record.LSETaskID = info.LSETaskID
		record.LSESampleID = info.LSESampleID
		record.LSETargetID = info.LSETargetID
		record.AgentType = info.AgentType
		record.ClientID = info.KeyID
		record.EnvironmentScope = info.EnvironmentScope
	}
	if record.ProjectID == "" {
		record.ProjectID = defaultMCPProjectID
	}
	if server != nil {
		record.ServerID = server.ID
		record.ServerName = server.Name
		record.TargetHost = extractTargetHost(server.ServerURL)
		record.TargetPath = "/mcp/" + server.ID
	}
	return record
}

// writeMCPLightAudit 给非 tools/call 场景（GET SSE、透传方法）落一条轻审计
// （只有 request_logs，不写 security_events / tool_call_logs）。
func (h *MCPProxyHandler) writeMCPLightAudit(ctx context.Context, info *auth.AuthInfo, server *mcpServerRoute, r *http.Request, requestBytes, responseBytes int64, status string, statusCode int, latency time.Duration) {
	record := h.newMCPAuditRecord(info, server, r, requestBytes, responseBytes, status, statusCode, latency)
	if h.auditRecorder != nil {
		h.auditRecorder.writeMCPAccess(ctx, record)
	}
}

// writeMCPProxyAudit 是 POST 主链留痕总入口，写库顺序不可交换：
// ① 同步 upsert request_logs；② security_events（仅 raw=block/confirm
// 时写，audit_only 下 action_taken 归一为 security_audit_only 绝不伪称已拦截）；
// ③ LogToolCall 回写 tool_call_logs。任一步失败都返回给调用方，由普通代理选择
// best-effort，批准执行链则把它作为执行前门禁或 evidence_status=failed。
func (h *MCPProxyHandler) writeMCPProxyAudit(ctx context.Context, envelope *modelrouter.RequestEnvelope, record mcpProxyAuditRecord, decisions []mcpToolCallDecision, auditOnly bool) (string, error) {
	if h.auditRecorder != nil {
		if err := h.auditRecorder.writeMCPProxyAuditTx(ctx, record, decisions, auditOnly); err != nil {
			return "", err
		}
	}
	id, err := h.writeMCPToolLogs(ctx, envelope, decisions)
	if err != nil && !errors.Is(err, errToolLogIDUnavailable) {
		// 此前该错误被调用方丢弃，tool_call_logs 缺行完全无声（D5）。
		log.Printf("MCP tool_call_logs 写入失败，审计行缺失 (request_id=%s): %v", record.RequestID, err)
	}
	return id, err
}

// writeMCPProxyOutcomeAudit 更新同一 request_id 的终态并写 execution_forwarded 工具日志。
// security_event 已在执行前门禁中持久化，这里不重复插入。
func (h *MCPProxyHandler) writeMCPProxyOutcomeAudit(ctx context.Context, envelope *modelrouter.RequestEnvelope, record mcpProxyAuditRecord, decisions []mcpToolCallDecision) (string, error) {
	if h.auditRecorder != nil {
		if err := h.auditRecorder.writeMCPProxyAuditTx(ctx, record, decisions, false); err != nil {
			return "", err
		}
	}
	return h.writeMCPToolLogs(ctx, envelope, decisions)
}

func (h *MCPProxyHandler) writeMCPToolLogs(ctx context.Context, envelope *modelrouter.RequestEnvelope, decisions []mcpToolCallDecision) (string, error) {
	if len(decisions) == 0 {
		return "", nil
	}
	if h.toolRiskClient == nil || envelope == nil {
		return "", errors.New("MCP tool audit client is unavailable")
	}
	toolLogID := ""
	for i := range decisions {
		for _, payload := range buildMCPToolAuditPayloads(&decisions[i]) {
			if payload.TraceID == "" {
				payload.TraceID = envelope.TraceID
			}
			storedID, err := h.toolRiskClient.LogToolCallWithID(ctx, envelope, payload)
			if err != nil {
				return "", err
			}
			if storedID == "" {
				return "", errToolLogIDUnavailable
			}
			toolLogID = storedID
		}
	}
	return toolLogID, nil
}

func mcpToolCallID(id json.RawMessage) string {
	key, ok := mcpRPCIDKey(id)
	if !ok {
		return ""
	}
	return key
}

// buildMCPToolAuditPayload 组装 tool_call_logs 行：raw/effective/mode 全填。
func buildMCPToolAuditPayload(d *mcpToolCallDecision) ToolAuditLogPayload {
	eventKind := "invocation_proposed"
	if d.ExecutionForwarded {
		eventKind = "execution_forwarded"
	}
	decision := d.Decision
	status := d.OutcomeStatus
	if status == "" {
		status = "proposed"
	}
	if decision.EffectiveDecision == agentguard.DecisionBlock || decision.EffectiveDecision == agentguard.DecisionConfirm {
		status = "blocked"
	} else if status == "proposed" && (decision.RawDecision == agentguard.DecisionBlock || decision.RawDecision == agentguard.DecisionConfirm) {
		status = "audited"
	}
	riskLevel := "medium"
	parameters, _ := parseToolCallArguments(d.ArgsJSON)
	if mcpAdmissionCritical(decision) {
		riskLevel = "critical"
	} else if decision.RawDecision == agentguard.DecisionBlock {
		riskLevel = "high"
	}
	result := decision.EffectiveReason
	if d.ResultExcerpt != "" {
		result = d.ResultExcerpt
	}
	return ToolAuditLogPayload{
		ToolName:              d.Qualified,
		ToolType:              "mcp",
		RiskLevel:             riskLevel,
		Parameters:            sanitizeToolCallParameters(parameters),
		Result:                result,
		Status:                status,
		MatchedPolicyID:       d.PolicyID,
		MatchedPolicyName:     "MCP 权限策略",
		MatchedAction:         string(decision.EffectiveDecision),
		MatchReason:           mcpDecisionReason(decision),
		RawDecision:           string(decision.RawDecision),
		EffectiveDecision:     string(decision.EffectiveDecision),
		Mode:                  string(decision.Mode),
		EffectiveReason:       decision.EffectiveReason,
		PolicyVersion:         decision.PolicyVersion,
		TraceID:               decision.TraceID,
		OperationID:           decision.OperationID,
		Confidence:            decision.Confidence,
		EvidenceJSON:          decision.Evidence,
		NormalizedTarget:      d.Qualified,
		Provenance:            "mcp_gateway",
		TaintedArguments:      decision.TaintedArguments,
		EventKind:             eventKind,
		ExecutionForwarded:    d.ExecutionForwarded,
		ExecutionObserved:     d.ExecutionForwarded,
		ResultObserved:        d.ResultObserved,
		ToolCallID:            mcpToolCallID(d.Message.ID),
		MCPServerID:           d.MCPServerID,
		MCPToolID:             d.MCPToolID,
		AssetID:               decision.SkillAssetID,
		DefinitionHash:        decision.SkillBundleHash,
		AttributionMode:       "explicit",
		AttributionConfidence: 1,
	}
}

func buildMCPToolAuditPayloads(d *mcpToolCallDecision) []ToolAuditLogPayload {
	base := buildMCPToolAuditPayload(d)
	decision := d.Decision
	if decision.RiskCategory != agentguard.DestructiveRiskCategory && !isDestructiveGateDecision(decision) {
		return []ToolAuditLogPayload{base}
	}
	base.Parameters = nil
	base.Result = ""
	base.EventType = "tool_destructive_intent"
	base.RiskCategory = decision.RiskCategory
	base.RiskSubcategory = decision.RiskSubcategory
	base.ReasonSummary = decision.ReasonSummary
	base.TargetSummary = decision.NormalizedTarget
	base.ModeDefaultAction = string(decision.ModeDefaultAction)
	base.CustomAction = string(decision.CustomAction)
	base.FinalAction = string(decision.FinalAction)
	base.NotificationRequired = decision.NotificationRequired
	base.NotifyChannelIDs = append([]string(nil), decision.NotifyChannelIDs...)
	base.NotificationStatus = "skipped"
	base.DiscardablePathMatched = decision.DiscardablePathMatched
	base.DiscardablePathReason = decision.DiscardablePathReason
	base.EventKind = "invocation_proposed"
	base.Status = "recorded"
	if d.OutcomeStatus == "failed" {
		base.Status = "failed"
	}
	base.ExecutionForwarded = false
	base.ExecutionObserved = false
	base.ResultObserved = false
	if decision.NotificationRequired && !decision.DiscardablePathMatched {
		base.NotificationStatus = "pending"
	}
	switch decision.FinalAction {
	case agentguard.DestructiveActionAlertAllow:
		base.Status = "alerted"
	case agentguard.DestructiveActionConfirm:
		base.Status = "waiting_confirmation"
	}
	payloads := []ToolAuditLogPayload{base}

	if d.ExecutionForwarded {
		execution := base
		execution.EventType = "tool_execution_risk"
		execution.EventKind = "execution_forwarded"
		execution.Status = d.OutcomeStatus
		if execution.Status == "" {
			execution.Status = "forwarded"
		}
		execution.ExecutionForwarded = true
		execution.ExecutionObserved = true
		execution.ResultObserved = d.ResultObserved
		payloads = append(payloads, execution)
	} else if decision.EffectiveDecision == agentguard.DecisionBlock {
		blocked := base
		blocked.EventType = "tool_attempt_blocked"
		blocked.Status = "blocked"
		payloads = append(payloads, blocked)
	}
	return payloads
}

func mcpDecisionReason(decision agentguard.Decision) string {
	if decision.EffectiveReason != "" {
		return decision.EffectiveReason
	}
	if decision.Reason != "" {
		return decision.Reason
	}
	return "mcp_policy_decision"
}

// mcpAccessUpsertSQL 把访问留痕 upsert 进 request_logs。endpoint_type='proxy'、
// proxy_mode='mcp'（口径见文件头注释）。供 pool 单写（轻审计）与事务化留痕复用。
const mcpAccessUpsertSQL = `
	INSERT INTO request_logs (
		id, request_id, tenant_id, project_id, user_id, session_id, trace_id,
		lse_eval_run_id, lse_task_id, lse_sample_id, lse_target_id,
		agent_type, endpoint_type, request_status, upstream_status_code, latency_ms,
		input_tokens, output_tokens, proxy_mode, proxy_target_host, proxy_target_path,
		proxy_method, proxy_source_ip, proxy_user_agent, proxy_request_bytes,
		proxy_response_bytes, client_id, source_ip, created_at, environment_scope
	) VALUES (
		$1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''),
		NULLIF($21, ''), NULLIF($22, ''), NULLIF($23, ''), NULLIF($24, ''),
		NULLIF($8, ''), 'proxy', $9, $10, $11,
		0, 0, 'mcp', $12, $13,
		$14, $15, $16, $17,
		$18, NULLIF($19, ''), NULLIF($20, ''), NOW(), $25
	)
	ON CONFLICT (request_id) DO UPDATE SET
		request_status = EXCLUDED.request_status,
		upstream_status_code = EXCLUDED.upstream_status_code,
		latency_ms = EXCLUDED.latency_ms,
		proxy_response_bytes = EXCLUDED.proxy_response_bytes,
		proxy_request_bytes = EXCLUDED.proxy_request_bytes,
		lse_eval_run_id = COALESCE(NULLIF(EXCLUDED.lse_eval_run_id, ''), request_logs.lse_eval_run_id),
		lse_task_id = COALESCE(NULLIF(EXCLUDED.lse_task_id, ''), request_logs.lse_task_id),
		lse_sample_id = COALESCE(NULLIF(EXCLUDED.lse_sample_id, ''), request_logs.lse_sample_id),
		lse_target_id = COALESCE(NULLIF(EXCLUDED.lse_target_id, ''), request_logs.lse_target_id),
		environment_scope = CASE
			WHEN request_logs.environment_scope = 'legacy-unclassified' THEN EXCLUDED.environment_scope
			ELSE request_logs.environment_scope
		END
`

// mcpSecurityEventSQL 写一条与本次 MCP 请求关联的安全事件。matched_summary["source"]=
// "gateway_mcp"（告警桥 suppressSources 按此整源抑制，按 raw decision 处置）；rule_id 是
// rules(id) 外键，红线是内置规则不在 rules 表，恒 NULL。security_events.request_id 是
// NOT NULL 外键，故必须与 request_logs upsert 在同一事务内、父行先落。
const mcpSecurityEventSQL = `
	INSERT INTO security_events (
		id, request_id, tenant_id, project_id, event_type, severity,
		rule_id, action_taken, matched_summary, evidence_ref, created_at, principal_key
	) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9, $10, NOW(), NULLIF($11, ''))
`

// mcpSecurityEventOccurrenceSQL 记一条幂等的重复发生行（迁移 130），与 RealAuditWriter.RecordSecurityEventOccurrence 同口径：
// 代表事件已入告警组时同语句把组计数 +1；否则挂账，由控制面 ReconcileOccurrences 回算。
const mcpSecurityEventOccurrenceSQL = `
	WITH inserted AS (
		INSERT INTO security_event_occurrences (
			tenant_id, representative_event_id, request_id, principal_key,
			conversation_key, context_key, alert_group_id, occurred_at
		) VALUES (
			$1, $2, $3, NULLIF($4, ''), NULL, $5,
			(SELECT se.alert_group_id FROM security_events se WHERE se.tenant_id = $1 AND se.id = $2),
			NOW()
		)
		ON CONFLICT (tenant_id, representative_event_id, request_id) DO NOTHING
		RETURNING alert_group_id, occurred_at
	)
	UPDATE alert_groups ag
	   SET occurrence_count = ag.occurrence_count + 1,
	       last_seen_at = GREATEST(ag.last_seen_at, inserted.occurred_at),
	       updated_at = NOW()
	  FROM inserted
	 WHERE ag.tenant_id = $1 AND ag.id = inserted.alert_group_id
`

func mcpSecurityEventOccurrenceArgs(record mcpProxyAuditRecord, representativeEventID, contextKey string) []interface{} {
	return []interface{}{record.TenantID, representativeEventID, record.RequestID, mcpPrincipalKey(record), contextKey}
}

// mcpAccessUpsertArgs 组装 request_logs upsert 的位置参数（顺序与 mcpAccessUpsertSQL 对齐）。
func mcpAccessUpsertArgs(record mcpProxyAuditRecord) []interface{} {
	if record.TargetHost == "" {
		record.TargetHost = "unknown"
	}
	return []interface{}{
		"log_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:16],
		record.RequestID,
		record.TenantID,
		record.ProjectID,
		record.UserID,
		record.SessionID,
		record.TraceID,
		record.AgentType,
		record.Status,
		record.StatusCode,
		record.LatencyMS,
		record.TargetHost,
		record.TargetPath,
		record.Method,
		record.SourceIP,
		record.UserAgent,
		record.RequestBytes,
		record.ResponseBytes,
		record.ClientID,
		record.SourceIP,
		// $21-$24：LSE 关联四元组，追加在末尾以免打乱既有 $1-$20 位置参数编号
		// （SQL VALUES 里已按 trace_id 之后的列位置引用这些占位符）。
		record.LSEEvalRunID,
		record.LSETaskID,
		record.LSESampleID,
		record.LSETargetID,
		retentionartifact.NormalizeEnvironmentScope(record.EnvironmentScope),
	}
}

// mcpPrincipalKey 物化 principal_key = COALESCE(user_id, client_id, source_ip)（契约第 6 条）。
func mcpPrincipalKey(record mcpProxyAuditRecord) string {
	for _, v := range []string{record.UserID, record.ClientID, record.SourceIP} {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// mcpSecurityEventArgs 组装 security_events insert 的位置参数（顺序与 mcpSecurityEventSQL
// 对齐）。request_id 复用父行的 record.RequestID，满足 NOT NULL 外键。
func mcpSecurityEventArgs(record mcpProxyAuditRecord, d *mcpToolCallDecision, auditOnly bool) []interface{} {
	severity := "high"
	eventType := "tool_attempt_blocked"
	// action_taken 记录真实处置动作，不再错位填事件类型字符串：
	// 拟确认→confirm；执行已转发→allow（调用真实执行了）；其余阻断→block。
	actionTaken := "block"
	if d.Decision.RawDecision == agentguard.DecisionConfirm {
		actionTaken = "confirm"
	}
	eventKind := "invocation_proposed"
	if d.ExecutionForwarded {
		eventType = "tool_execution_risk"
		actionTaken = "allow"
		eventKind = "execution_forwarded"
	}
	if auditOnly {
		// record 模式没有真正拦截，绝不伪称 block/confirm（同反代口径）。
		actionTaken = mcpSecurityActionTaken(d.Decision.EffectiveDecision, true)
	}
	summary := map[string]interface{}{
		"source":              "gateway_mcp",
		"stage":               "tool",
		"event_kind":          eventKind,
		"execution_forwarded": d.ExecutionForwarded,
		"result_observed":     d.ResultObserved,
		"server_id":           record.ServerID,
		"server_name":         record.ServerName,
		"tool_name":           d.Qualified,
		"raw_decision":        string(d.Decision.RawDecision),
		"effective_decision":  string(d.Decision.EffectiveDecision),
		"mode":                string(d.Decision.Mode),
		"policy_id":           d.PolicyID,
		"reason":              mcpDecisionReason(d.Decision),
		"summary":             "MCP 工具调用命中权限策略/安全红线",
	}
	if agentType := strings.TrimSpace(record.AgentType); agentType != "" {
		summary["agent_type"] = agentType
	}
	// 决定这次处置的防护项（拦截记录据此定位配置、给加例外入口；告警放行也写下是哪一项）。
	if item := mcpDecidingProtectionItem(d.Decision); item != "" {
		summary["protection_item"] = item
	}
	if mcpProtectionAlert(d) && !d.ExecutionForwarded {
		eventType, actionTaken = "mcp_protection_alert", "alert"
		summary["protection_item"] = d.Decision.ProtectionItem
		summary["summary"] = "MCP 调用命中防护项（告警放行）"
	}
	destructive := d.Decision.RiskCategory == agentguard.DestructiveRiskCategory || isDestructiveGateDecision(d.Decision)
	if len(d.ToolsListDrops) > 0 {
		eventType = "mcp_tools_list_drift"
		actionTaken = "mcp_tools_list_alerted"
		if d.ToolsListEnforced {
			actionTaken = "mcp_tools_list_filtered"
		}
		drops := d.ToolsListDrops
		if len(drops) > mcpToolsListDropEvidenceLimit {
			drops = drops[:mcpToolsListDropEvidenceLimit]
		}
		summary["summary"] = "MCP tools/list 响应与已批准工具快照不一致"
		summary["dropped_tools"] = drops
		summary["dropped_count"] = len(d.ToolsListDrops)
		summary["filtered"] = d.ToolsListEnforced
	}
	if d.ToolResultWouldBlock {
		eventType = "mcp_tool_result_injection"
		actionTaken = "mcp_tool_result_alerted"
		if d.ToolResultEnforced {
			actionTaken = "mcp_tool_result_blocked"
		}
		summary["summary"] = "MCP 工具返回内容命中安全检测（疑似间接注入）"
		summary["tool_result_findings"] = d.ToolResultFindings
		summary["blocked"] = d.ToolResultEnforced
	}
	if d.ServerInitiated {
		eventType = "mcp_server_request_blocked"
		actionTaken = "mcp_server_request_blocked"
		eventKind = "server_request"
		if d.ExecutionForwarded {
			actionTaken = "mcp_server_request_alerted"
		}
		summary["event_kind"] = eventKind
		summary["summary"] = "MCP 上游发起的反向请求命中权限策略"
	}
	if d.ResultExcerpt != "" && !destructive {
		summary["result_excerpt"] = d.ResultExcerpt
	}
	if len(d.Decision.Evidence) > 0 {
		summary["evidence"] = d.Decision.Evidence
	}
	matchedJSON, _ := json.Marshal(summary)
	return []interface{}{
		"evt_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:16],
		record.RequestID,
		record.TenantID,
		record.ProjectID,
		eventType,
		severity,
		"", // rule_id：红线为内置规则，恒 NULL（外键防护）
		actionTaken,
		matchedJSON,
		"request_logs:" + record.RequestID,
		mcpPrincipalKey(record), // principal_key：契约6 Go 侧 COALESCE
	}
}

// mcpDecisionNeedsSecurityEvent 判定一条决策是否需要落 security_events：仅
// block/confirm（真实/拟阻断）时写，避免 audit 常态刷屏。
func mcpDecisionNeedsSecurityEvent(d *mcpToolCallDecision, auditOnly bool) bool {
	if d == nil {
		return false
	}
	// 红线命中（含 record/audit 处置）必须留 security_events：record 模式只是不拦截，
	// 绝不意味着不留痕（D5）。auditOnly 仅影响 action_taken 的措辞，见 mcpSecurityEventArgs。
	if mcpDecisionHasRedlineEvidence(d) {
		return true
	}
	if auditOnly {
		raw := d.Decision.RawDecision
		return raw == agentguard.DecisionBlock || raw == agentguard.DecisionConfirm
	}
	// 2.9.22：故障类 mcp.* 项（确认单建不出来、批准后重放时环境变化）设为仅记录或被例外放开时，
	// 放行的调用只留工具日志，不因“拟确认却执行了”再发安全事件。
	if mcpFaultReleasedAsRecord(d) {
		return false
	}
	// 2.9.22：mcp.* 防护项告警放行（未准入、地址/Schema 变化、投毒……）要发告警，观察留痕下不发。
	if mcpProtectionAlert(d) {
		return true
	}
	// W1 1.3：tools/list 与已批准快照不一致即告警（无论是否已剔除）。
	if len(d.ToolsListDrops) > 0 {
		return true
	}
	// W1 1.7：工具返回命中阻断类检测即告警（无论是否已拦截）。
	if d.ToolResultWouldBlock {
		return true
	}
	raw := d.Decision.RawDecision
	if raw != agentguard.DecisionBlock && raw != agentguard.DecisionConfirm {
		return false
	}
	if d.ExecutionForwarded {
		return true
	}
	return d.Decision.EffectiveDecision == agentguard.DecisionBlock || d.Decision.EffectiveDecision == agentguard.DecisionConfirm
}

// mcpDecidingProtectionItem 是决定这次处置的防护项：与 chat 拦截记录同口径（DecidingProtectionItem），
// 再加故障类 mcp.* 项配成阻断、由该项本身拦下的情形（那时决策原因是故障原因，不是 protection_item）。
func mcpDecidingProtectionItem(decision agentguard.Decision) string {
	if item := agentguard.DecidingProtectionItem(decision); item != "" {
		return item
	}
	if protection.Action(decision.ProtectionAction) == protection.ActionBlock && strings.HasPrefix(decision.ProtectionItem, "mcp.") {
		return decision.ProtectionItem
	}
	return ""
}

// mcpFaultReleasedAsRecord 判断决策是不是被故障类 mcp.* 项按“仅记录”放行（见 mcpProtectionFallback：
// 放行时 EffectiveReason 是故障原因，ProtectionItem 是该项）。
func mcpFaultReleasedAsRecord(d *mcpToolCallDecision) bool {
	if d == nil || protection.Action(d.Decision.ProtectionAction) != protection.ActionRecord {
		return false
	}
	switch d.Decision.EffectiveDecision {
	case agentguard.DecisionBlock, agentguard.DecisionConfirm:
		return false
	}
	item, ok := protection.ItemForReason(d.Decision.EffectiveReason)
	if !ok || item.Key != d.Decision.ProtectionItem {
		return false
	}
	return (item.Key == protection.KeyMCPConfirmUnavailable || item.Key == protection.KeyMCPReplayChanged) &&
		len(d.ToolsListDrops) == 0 && !d.ToolResultWouldBlock
}

// mcpProtectionAlert 判断决策是不是 mcp.* 防护项的告警放行（没有被别的结论拦下）。
func mcpProtectionAlert(d *mcpToolCallDecision) bool {
	if d == nil || !d.Decision.ProtectionAlert() || !strings.HasPrefix(d.Decision.ProtectionItem, "mcp.") {
		return false
	}
	raw := d.Decision.RawDecision
	return raw != agentguard.DecisionBlock && raw != agentguard.DecisionConfirm
}

// mcpDecisionHasRedlineEvidence 判定决策是否带内置红线证据（category=mcp_redline）。
func mcpDecisionHasRedlineEvidence(d *mcpToolCallDecision) bool {
	for _, ev := range d.Decision.Evidence {
		if ev.Category == "mcp_redline" {
			return true
		}
	}
	return false
}

// mcpEnforcedDecisionSummary 汇总本次请求中「已生效阻断」类决策（block/confirm），
// 供事务失败日志定位是否丢了必留痕的阻断；无则返回 "none"。
func mcpEnforcedDecisionSummary(decisions []mcpToolCallDecision) string {
	parts := make([]string, 0, len(decisions))
	for i := range decisions {
		d := &decisions[i]
		if !mcpDecisionNeedsSecurityEvent(d, false) {
			continue
		}
		tag := string(d.Decision.EffectiveDecision)
		if d.Decision.RawDecision == agentguard.DecisionBlock {
			tag = "block"
		}
		parts = append(parts, tag+":"+d.Qualified)
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

// writeMCPAccess 把访问留痕 upsert 进 request_logs（pool 单写路径，供非 tools/call 的
// 轻审计使用；tools/call 主链走 writeMCPProxyAuditTx 的事务路径）。
func (rec *mcpProxyAuditRecorder) writeMCPAccess(ctx context.Context, record mcpProxyAuditRecord) {
	if rec == nil || rec.db == nil || record.TenantID == "" || record.RequestID == "" {
		return
	}
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	if _, err := rec.db.Exec(ctx, mcpAccessUpsertSQL, mcpAccessUpsertArgs(record)...); err != nil {
		log.Printf("Failed to write MCP proxy access log: %v", err)
	}
}

// writeMCPProxyAuditTx 把 ① request_logs upsert 与 ② security_events insert 包进单个事务：
// 父行先于子行原子落库，要么都落、要么都不落，彻底消除「access 写失败→事件外键违例被静默
// 丢弃」的孤儿 FK 事故（幸存项 7）。对 block/confirm 这类已生效阻断，事务任一步
// 失败都打含 request_id / 已生效阻断摘要的结构化错误日志——确保「阻断了必留痕」，即便留痕
// 落库失败也能被告警发现，而非仅静默返回。LogToolCall（tool_call_logs 的 HTTP 回写）不属
// 本地 DB 写，仍留在事务外由调用方处理。
func (rec *mcpProxyAuditRecorder) writeMCPProxyAuditTx(ctx context.Context, record mcpProxyAuditRecord, decisions []mcpToolCallDecision, auditOnly bool) error {
	if rec == nil || rec.db == nil || record.TenantID == "" || record.RequestID == "" {
		return nil
	}
	enforced := mcpEnforcedDecisionSummary(decisions)
	tx, err := rec.db.Begin(ctx)
	if err != nil {
		log.Printf("MCP 审计事务开启失败，留痕丢失风险 (request_id=%s tenant=%s enforced=%s): %v", record.RequestID, record.TenantID, enforced, err)
		return fmt.Errorf("begin MCP audit transaction: %w", err)
	}
	// Commit 成功后 Rollback 返回 ErrTxClosed，忽略即可（照抄 repository 事务范式）。
	defer func() { _ = tx.Rollback(ctx) }()

	// ① request_logs upsert（父行，满足 security_events.request_id NOT NULL 外键）。
	if _, err := tx.Exec(ctx, mcpAccessUpsertSQL, mcpAccessUpsertArgs(record)...); err != nil {
		log.Printf("MCP 审计写 request_logs 失败，事务整体回滚 (request_id=%s tenant=%s enforced=%s): %v", record.RequestID, record.TenantID, enforced, err)
		return fmt.Errorf("write MCP request audit: %w", err)
	}

	// ② security_events：block/confirm、红线命中等（子行，依赖①的父行外键）。
	// 复审 M-5：纯红线信号在窗口内重复时折叠为 occurrence（首次必写完整事件，计数准确）；其余一律逐条写。
	var registered []string // 本事务新登记的代表事件键：事务失败时撤销，避免后续重复折叠到不存在的事件上
	for i := range decisions {
		d := &decisions[i]
		if !mcpDecisionNeedsSecurityEvent(d, auditOnly) {
			continue
		}
		dedupeKey := ""
		if rec.redlineDedupe != nil && mcpPureRedlineSignal(d) {
			dedupeKey = mcpRedlineDedupeKey(record, d, auditOnly)
			if repEventID, folded := rec.redlineDedupe.lookup(dedupeKey); folded {
				if _, err := tx.Exec(ctx, mcpSecurityEventOccurrenceSQL, mcpSecurityEventOccurrenceArgs(record, repEventID, dedupeKey)...); err != nil {
					log.Printf("MCP 审计写 security_event_occurrences 失败，事务整体回滚 (request_id=%s tool=%s): %v", record.RequestID, d.Qualified, err)
					return fmt.Errorf("write MCP security event occurrence: %w", err)
				}
				continue
			}
		}
		args := mcpSecurityEventArgs(record, d, auditOnly)
		if _, err := tx.Exec(ctx, mcpSecurityEventSQL, args...); err != nil {
			log.Printf("MCP 审计写 security_events 失败，事务整体回滚 (request_id=%s tool=%s raw=%s effective=%s): %v",
				record.RequestID, d.Qualified, d.Decision.RawDecision, d.Decision.EffectiveDecision, err)
			for _, k := range registered {
				rec.redlineDedupe.forget(k)
			}
			return fmt.Errorf("write MCP security event: %w", err)
		}
		if dedupeKey != "" {
			if eventID, ok := args[0].(string); ok {
				rec.redlineDedupe.register(dedupeKey, eventID)
				registered = append(registered, dedupeKey)
			}
		}
	}

	// ③ MCP 策略读取失败按设置放行：同一租户加服务 10 分钟记一条运行告警（2.9.22）。
	faultKey := ""
	for i := range decisions {
		if !mcpPolicyGapReleased(decisions[i].Decision) {
			continue
		}
		key := record.TenantID + "\x1f" + record.ServerID
		if rec.policyFaultLimiter().due(key) {
			if _, err := tx.Exec(ctx, mcpSecurityEventSQL, mcpPolicyFaultEventArgs(record, &decisions[i])...); err != nil {
				log.Printf("MCP 审计写策略读取失败告警失败，事务整体回滚 (request_id=%s server=%s): %v", record.RequestID, record.ServerID, err)
				return fmt.Errorf("write MCP policy fault event: %w", err)
			}
			faultKey = key
		}
		break
	}

	if err := tx.Commit(ctx); err != nil {
		for _, k := range registered {
			rec.redlineDedupe.forget(k)
		}
		log.Printf("MCP 审计事务提交失败，已生效阻断留痕丢失 (request_id=%s tenant=%s enforced=%s): %v", record.RequestID, record.TenantID, enforced, err)
		return fmt.Errorf("commit MCP audit transaction: %w", err)
	}
	if faultKey != "" {
		rec.policyFaultLimiter().mark(faultKey)
	}
	return nil
}

// mcpSecurityActionTaken 把 MCP 生效决策与 audit-only 开关映射为
// security_events.action_taken。audit-only 下即便 raw 判 block 也未真正阻断，
// 统一记 security_audit_only，绝不伪称已拦截（同反代口径）。
func mcpSecurityActionTaken(effective agentguard.DecisionAction, auditOnly bool) string {
	if auditOnly {
		return "security_audit_only"
	}
	switch effective {
	case agentguard.DecisionBlock, agentguard.DecisionConfirm:
		return "security_blocked"
	default:
		return "security_audit"
	}
}

// mcpAdmissionCritical 标出准入类结论（MCP 供应链准入、审批上下文漂移、策略运行时不可用、
// 管理员配置的 Skill 准入处置），审计风险等级记 critical。
func mcpAdmissionCritical(decision agentguard.Decision) bool {
	if decision.Reason == "policy_runtime_unavailable" {
		return true
	}
	if !decision.ConfiguredEnforcement {
		return false
	}
	return strings.HasPrefix(decision.Reason, "mcp_supply_chain:") || mcpAdmissionReasons[decision.Reason]
}

// mcpAdmissionReasons 是按配置执行时记 critical 的准入类原因：审批上下文漂移、
// 管理员的 Skill 隔离/撤销、Skill 身份异常与准入服务不可用（后两类是防护项，配成
// 确认/阻断时才带 ConfiguredEnforcement）。
var mcpAdmissionReasons = map[string]bool{
	"approval_context_drift":                   true,
	"skill_version_quarantined":                true,
	"skill_version_revoked":                    true,
	protection.ReasonSkillAdmissionUnavailable: true,
	"skill_identity_misplaced":                 true,
	"skill_identity_invalid":                   true,
	"skill_identity_conflict":                  true,
}
