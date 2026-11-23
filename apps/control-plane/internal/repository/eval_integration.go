package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type EvalAuditEventFilter struct {
	AgentInstanceID string
	EvalRunID       string
	TaskID          string
	SampleID        string
	TraceID         string
	ClientID        string
	SourceIP        string
	StartTime       *time.Time
	EndTime         *time.Time
	SkipTotal       bool
}

type EvalAuditEvent struct {
	AgentInstanceID    string
	ID                 string
	RequestID          string
	TenantID           string
	ProjectID          string
	UserID             string
	ClientID           string
	SourceIP           string
	ProviderID         string
	ModelID            string
	ModelName          string
	SessionID          string
	AgentType          string
	EndpointType       string
	RequestStatus      string
	StatusCode         int
	LatencyMs          int
	InputTokens        int
	OutputTokens       int
	TotalCost          float64
	CreatedAt          time.Time
	TraceID            string
	LSEEvalRunID       string
	LSETaskID          string
	LSESampleID        string
	LSETargetID        string
	ContentLogCount    int
	SecurityEventCount int
	// ToolCallCount 是该请求关联的 tool_call_logs 行数；MCPToolCallCount 只统计
	// tool_type='mcp' 的行。MCP 的 allow/audit 决策只落 tool_call_logs、不写
	// security_events（仅 block/confirm 才写事件），故按工具决策维度
	// 校验「网关是否记录了 MCP 裁决」必须看这两个计数，否则会把 audit-only 下的
	// 正常留痕误判为 GW_NO_POLICY_HIT。
	ToolCallCount    int
	MCPToolCallCount int
	SecurityEvents   []EvalSecurityEvent
}

type EvalSecurityEvent struct {
	ID             string
	EventType      string
	Severity       string
	RuleID         string
	ActionTaken    string
	MatchedSummary map[string]interface{}
	CreatedAt      time.Time
}

func buildEvalAuditEventsWhere(tenantID string, filter EvalAuditEventFilter) (string, []interface{}) {
	clauses := []string{"rl.tenant_id = $1"}
	args := []interface{}{tenantID}
	add := func(clause string, value interface{}) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if filter.AgentInstanceID != "" {
		add("rl.agent_instance_id = $%d", filter.AgentInstanceID)
	}
	if filter.EvalRunID != "" {
		add("rl.lse_eval_run_id = $%d", filter.EvalRunID)
	}
	if filter.TaskID != "" {
		add("rl.lse_task_id = $%d", filter.TaskID)
	}
	if filter.SampleID != "" {
		add("rl.lse_sample_id = $%d", filter.SampleID)
	}
	if filter.TraceID != "" {
		add("rl.trace_id = $%d", filter.TraceID)
	}
	if filter.ClientID != "" {
		add("rl.client_id = $%d", filter.ClientID)
	}
	if filter.SourceIP != "" {
		args = append(args, filter.SourceIP)
		clauses = append(clauses, fmt.Sprintf("(rl.source_ip = $%d OR rl.proxy_source_ip = $%d)", len(args), len(args)))
	}
	if filter.StartTime != nil {
		add("rl.created_at >= $%d", *filter.StartTime)
	}
	if filter.EndTime != nil {
		add("rl.created_at <= $%d", *filter.EndTime)
	}
	return strings.Join(clauses, " AND "), args
}

func (r *RequestLogRepository) ListEvalAuditEvents(ctx context.Context, tenantID string, filter EvalAuditEventFilter, limit, offset int) ([]*EvalAuditEvent, int, error) {
	where, args := buildEvalAuditEventsWhere(tenantID, filter)
	query, queryArgs, countQuery, countArgs := buildEvalAuditEventsListQuery(where, args, limit, offset)
	rows, err := r.db.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list eval audit events: %w", err)
	}
	defer rows.Close()

	events := []*EvalAuditEvent{}
	for rows.Next() {
		event, err := scanEvalAuditEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	total := len(events)
	if !filter.SkipTotal {
		if err := r.db.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("failed to count eval audit events: %w", err)
		}
	}
	return events, total, nil
}

func buildEvalAuditEventsListQuery(where string, args []interface{}, limit, offset int) (string, []interface{}, string, []interface{}) {
	queryArgs := append(append([]interface{}{}, args...), limit, offset)
	limitParam := len(args) + 1
	offsetParam := len(args) + 2
	query := fmt.Sprintf(`
		SELECT
			rl.id, rl.request_id, rl.tenant_id, COALESCE(rl.project_id, ''),
			COALESCE(rl.user_id, ''), COALESCE(rl.client_id, ''),
			COALESCE(rl.source_ip, rl.proxy_source_ip, ''),
			COALESCE(rl.provider_id, ''), COALESCE(rl.model_id, ''),
			COALESCE(m.model_name, rl.model_id, ''), COALESCE(rl.session_id, ''),
			COALESCE(rl.agent_type, ''), COALESCE(rl.endpoint_type, ''),
			COALESCE(rl.request_status, ''), COALESCE(rl.upstream_status_code, 0),
			COALESCE(rl.latency_ms, 0), COALESCE(rl.input_tokens, 0),
			COALESCE(rl.output_tokens, 0), COALESCE(rl.total_cost, 0), rl.created_at,
			COALESCE(rl.trace_id, ''), COALESCE(rl.lse_eval_run_id, ''),
			COALESCE(rl.lse_task_id, ''), COALESCE(rl.lse_sample_id, ''),
			COALESCE(rl.lse_target_id, ''), COALESCE(content.content_log_count, 0),
			COALESCE(sec.security_event_count, 0),
			COALESCE(tcl.tool_call_count, 0), COALESCE(tcl.mcp_tool_call_count, 0), COALESCE(rl.agent_instance_id, '')
		FROM request_logs rl
		LEFT JOIN models m ON m.id = rl.model_id
		LEFT JOIN (
			SELECT request_id, COUNT(*) AS content_log_count
			FROM content_logs
			WHERE tenant_id = $1
			GROUP BY request_id
		) content ON content.request_id = rl.id
		LEFT JOIN (
			SELECT request_id, COUNT(*) AS security_event_count
			FROM security_events
			WHERE tenant_id = $1
			GROUP BY request_id
		) sec ON sec.request_id = rl.request_id
		LEFT JOIN (
			SELECT request_id, COUNT(*) AS tool_call_count,
			       COUNT(*) FILTER (WHERE tool_type = 'mcp') AS mcp_tool_call_count
			FROM tool_call_logs
			WHERE tenant_id = $1
			GROUP BY request_id
		) tcl ON tcl.request_id = rl.request_id
		WHERE %s
		ORDER BY rl.created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, limitParam, offsetParam)
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM request_logs rl WHERE %s`, where)
	countArgs := append([]interface{}{}, args...)
	return query, queryArgs, countQuery, countArgs
}

func (r *RequestLogRepository) GetEvalAuditEvent(ctx context.Context, tenantID, id string) (*EvalAuditEvent, error) {
	query := `
		SELECT
			rl.id, rl.request_id, rl.tenant_id, COALESCE(rl.project_id, ''),
			COALESCE(rl.user_id, ''), COALESCE(rl.client_id, ''),
			COALESCE(rl.source_ip, rl.proxy_source_ip, ''),
			COALESCE(rl.provider_id, ''), COALESCE(rl.model_id, ''),
			COALESCE(m.model_name, rl.model_id, ''), COALESCE(rl.session_id, ''),
			COALESCE(rl.agent_type, ''), COALESCE(rl.endpoint_type, ''),
			COALESCE(rl.request_status, ''), COALESCE(rl.upstream_status_code, 0),
			COALESCE(rl.latency_ms, 0), COALESCE(rl.input_tokens, 0),
			COALESCE(rl.output_tokens, 0), COALESCE(rl.total_cost, 0), rl.created_at,
			COALESCE(rl.trace_id, ''), COALESCE(rl.lse_eval_run_id, ''),
			COALESCE(rl.lse_task_id, ''), COALESCE(rl.lse_sample_id, ''),
			COALESCE(rl.lse_target_id, ''), COALESCE(content.content_log_count, 0),
			COALESCE(sec.security_event_count, 0),
			COALESCE(tcl.tool_call_count, 0), COALESCE(tcl.mcp_tool_call_count, 0), COALESCE(rl.agent_instance_id, '')
		FROM request_logs rl
		LEFT JOIN models m ON m.id = rl.model_id
		LEFT JOIN (
			SELECT request_id, COUNT(*) AS content_log_count
			FROM content_logs
			WHERE tenant_id = $1
			GROUP BY request_id
		) content ON content.request_id = rl.id
		LEFT JOIN (
			SELECT request_id, COUNT(*) AS security_event_count
			FROM security_events
			WHERE tenant_id = $1
			GROUP BY request_id
		) sec ON sec.request_id = rl.request_id
		LEFT JOIN (
			SELECT request_id, COUNT(*) AS tool_call_count,
			       COUNT(*) FILTER (WHERE tool_type = 'mcp') AS mcp_tool_call_count
			FROM tool_call_logs
			WHERE tenant_id = $1
			GROUP BY request_id
		) tcl ON tcl.request_id = rl.request_id
		WHERE rl.tenant_id = $1 AND (rl.id = $2 OR rl.request_id = $2)
		LIMIT 1
	`
	event, err := scanEvalAuditEvent(r.db.QueryRow(ctx, query, tenantID, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get eval audit event: %w", err)
	}
	events, err := r.listEvalSecurityEvents(ctx, tenantID, event.RequestID)
	if err != nil {
		return nil, err
	}
	event.SecurityEvents = events
	return event, nil
}

type evalAuditEventScanner interface {
	Scan(dest ...interface{}) error
}

func scanEvalAuditEvent(scanner evalAuditEventScanner) (*EvalAuditEvent, error) {
	var event EvalAuditEvent
	if err := scanner.Scan(
		&event.ID,
		&event.RequestID,
		&event.TenantID,
		&event.ProjectID,
		&event.UserID,
		&event.ClientID,
		&event.SourceIP,
		&event.ProviderID,
		&event.ModelID,
		&event.ModelName,
		&event.SessionID,
		&event.AgentType,
		&event.EndpointType,
		&event.RequestStatus,
		&event.StatusCode,
		&event.LatencyMs,
		&event.InputTokens,
		&event.OutputTokens,
		&event.TotalCost,
		&event.CreatedAt,
		&event.TraceID,
		&event.LSEEvalRunID,
		&event.LSETaskID,
		&event.LSESampleID,
		&event.LSETargetID,
		&event.ContentLogCount,
		&event.SecurityEventCount,
		&event.ToolCallCount,
		&event.MCPToolCallCount,
		&event.AgentInstanceID,
	); err != nil {
		return nil, err
	}
	return &event, nil
}

func (r *RequestLogRepository) listEvalSecurityEvents(ctx context.Context, tenantID, requestID string) ([]EvalSecurityEvent, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, event_type, severity, COALESCE(rule_id, ''), action_taken,
		       COALESCE(matched_summary, '{}'::jsonb), created_at
		FROM security_events
		WHERE tenant_id = $1 AND request_id = $2
		ORDER BY created_at ASC
	`, tenantID, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to list eval security events: %w", err)
	}
	defer rows.Close()

	events := []EvalSecurityEvent{}
	for rows.Next() {
		var event EvalSecurityEvent
		var summaryJSON []byte
		if err := rows.Scan(&event.ID, &event.EventType, &event.Severity, &event.RuleID, &event.ActionTaken, &summaryJSON, &event.CreatedAt); err != nil {
			return nil, err
		}
		if len(summaryJSON) > 0 {
			_ = json.Unmarshal(summaryJSON, &event.MatchedSummary)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

// ModelEvalStatusRow 一个被 lse 测评过的模型的最新测评状态（只读聚合）。
type ModelEvalStatusRow struct {
	ModelID      string
	LSETargetID  string
	HasHighRisk  bool
	LatestEvalAt time.Time
}

func buildModelEvalStatusQuery() string {
	return `
		SELECT
			rl.model_id,
			COALESCE((array_agg(rl.lse_target_id ORDER BY rl.created_at DESC)
				FILTER (WHERE rl.lse_target_id <> ''))[1], '') AS lse_target_id,
			COALESCE(bool_or(sev.is_high), false) AS has_high_risk,
			MAX(rl.created_at) AS latest_eval_at
		FROM request_logs rl
		LEFT JOIN LATERAL (
			SELECT bool_or(lower(se.severity) IN ('high','critical')) AS is_high
			FROM security_events se
			WHERE se.request_id = rl.request_id
			  AND se.event_type = 'eval_content_safety'
		) sev ON true
		WHERE rl.tenant_id = $1
		  AND rl.lse_eval_run_id <> ''
		  AND rl.model_id IS NOT NULL
		  AND rl.model_id <> ''
		GROUP BY rl.model_id
	`
}

// ListModelEvalStatus 返回该租户下所有「被 lse 测评过」的模型的最新测评状态。未出现的模型=未测评。
func (r *RequestLogRepository) ListModelEvalStatus(ctx context.Context, tenantID string) ([]ModelEvalStatusRow, error) {
	rows, err := r.db.Query(ctx, buildModelEvalStatusQuery(), tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list model eval status: %w", err)
	}
	defer rows.Close()
	out := []ModelEvalStatusRow{}
	for rows.Next() {
		var row ModelEvalStatusRow
		if err := rows.Scan(&row.ModelID, &row.LSETargetID, &row.HasHighRisk, &row.LatestEvalAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
