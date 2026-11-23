package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alertconfig"
	"github.com/yangjiyj/aiguard/packages/shared-go/userhistory"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RequestLog represents a request log record
type RequestLog struct {
	ID                string
	RequestID         string
	TenantID          string
	ProjectID         string
	UserID            string
	ClientID          string
	ProviderID        string
	ModelID           string
	ModelName         string
	SessionID         string
	ConversationID    string
	AgentType         string
	EndpointType      string
	RequestStatus     string
	StatusCode        int
	LatencyMs         int
	InputTokens       int
	OutputTokens      int
	TotalCost         float64
	CreatedAt         time.Time
	InputAuditResult  map[string]interface{}
	OutputAuditResult map[string]interface{}
	// Related counts for audit display
	ContentCount       int
	ToolCallCount      int
	SecurityEventCount int
}

type RequestEvidenceMetadata struct {
	ProxyContentRetained bool
	RetentionUntil       *time.Time
	RequestID            string    `json:"request_id"`
	OccurredAt           time.Time `json:"occurred_at"`
	UserID               string    `json:"user_id"`
	Username             string    `json:"username"`
	ClientID             string    `json:"client_id"`
	ClientName           string    `json:"client_name"`
	SourceIP             string    `json:"source_ip"`
	AgentType            string    `json:"agent_type"`
	Provider             string    `json:"provider"`
	Target               string    `json:"target"`
}

// RequestLogRepository handles request log database operations
type RequestLogRepository struct {
	db *pgxpool.Pool
}

type RequestLogListFilter struct {
	TenantID  string
	StartTime time.Time
	EndTime   time.Time
	Limit     int
	Offset    int
	SkipTotal bool
}

// PortalCallRecord is the privacy-minimized request view exposed to an employee.
// It intentionally contains no prompt, response, credential, or raw audit payload.
type PortalCallRecord struct {
	RequestID             string
	CreatedAt             time.Time
	Model                 string
	Status                string
	UpstreamStatus        int
	InputTokens           int
	CachedInputTokens     int
	CacheWriteInputTokens int
	OutputTokens          int
	LatencyMs             int
	AgentType             string
	EndpointType          string
	InputAction           string
	OutputAction          string
	SecurityEventCount    int
	BillingAmountMicros   *int64
	BillingCurrency       string
	BillingState          string
}

type PortalCallRecordFilter struct {
	TenantID        string
	UserID          string
	StartTime       time.Time
	BeforeCreatedAt time.Time
	BeforeRequestID string
	// RequestID 仅收窄列表（总数与汇总不受影响），始终叠加在租户与用户条件之上。
	RequestID string
	Limit     int
}

type AuditActionListFilter struct {
	TenantID  string
	Action    string
	StartTime time.Time
	EndTime   time.Time
	Limit     int
	Offset    int
	SkipTotal bool
}

// NewRequestLogRepository creates a new request log repository
func NewRequestLogRepository(db *pgxpool.Pool) *RequestLogRepository {
	return &RequestLogRepository{db: db}
}

// DB returns the underlying database connection pool
func (r *RequestLogRepository) DB() *pgxpool.Pool {
	return r.db
}

func (r *RequestLogRepository) GetEvidenceMetadata(
	ctx context.Context,
	tenantID string,
	requestID string,
) (*RequestEvidenceMetadata, error) {
	return r.getEvidenceMetadata(ctx, tenantID, requestID, "", time.Time{}, time.Time{})
}

func (r *RequestLogRepository) GetEvidenceMetadataScoped(
	ctx context.Context,
	tenantID string,
	requestID string,
	start, end time.Time,
	environmentScope string,
) (*RequestEvidenceMetadata, error) {
	return r.getEvidenceMetadata(ctx, tenantID, requestID, environmentScope, start, end)
}

func (r *RequestLogRepository) getEvidenceMetadata(
	ctx context.Context,
	tenantID string,
	requestID string,
	environmentScope string,
	start, end time.Time,
) (*RequestEvidenceMetadata, error) {
	scopes := EnvironmentScopesForRead(environmentScope)
	window := ""
	args := []interface{}{tenantID, requestID}
	if len(scopes) > 0 && !start.IsZero() && !end.IsZero() {
		args = append(args, scopes, start.UTC(), end.UTC())
		window = " AND rl.environment_scope = ANY($3) AND rl.created_at >= $4 AND rl.created_at < $5"
	}
	query := `
		SELECT
			COALESCE(rl.proxy_content_retained, FALSE),
			rl.content_evidence_retention_until,
			rl.request_id,
			rl.created_at,
			COALESCE(rl.user_id, ''),
			COALESCE(NULLIF(key_owner.username, ''), NULLIF(request_user.username, ''), ''),
			COALESCE(rl.client_id, ''),
			COALESCE(NULLIF(client_key.name, ''), NULLIF(client_key.key_prefix, ''), ''),
			COALESCE(NULLIF(rl.proxy_source_ip, ''), NULLIF(rl.source_ip, ''), ''),
			COALESCE(rl.agent_type, ''),
			COALESCE(NULLIF(rl.proxy_provider, ''), NULLIF(provider.name, ''), ''),
			COALESCE(NULLIF(rl.proxy_target_host, ''), NULLIF(model.model_name, ''), NULLIF(rl.model_id, ''), '')
		FROM request_logs rl
		LEFT JOIN internal_keys client_key
		  ON client_key.tenant_id = rl.tenant_id
		 AND (
		   client_key.id = rl.client_id
		   OR (LEFT(rl.client_id, 7) = 'caller_' AND LEFT(client_key.key_hash, 12) = SUBSTRING(rl.client_id FROM 8))
		 )
		LEFT JOIN users request_user ON request_user.tenant_id = rl.tenant_id AND request_user.id = rl.user_id
		LEFT JOIN users key_owner ON key_owner.tenant_id = rl.tenant_id AND key_owner.id = client_key.user_id
		LEFT JOIN providers provider ON provider.id = rl.provider_id
		LEFT JOIN models model ON model.id = rl.model_id
		WHERE rl.tenant_id = $1
		  AND rl.request_id = $2
		` + window + `
		LIMIT 1
	`
	var out RequestEvidenceMetadata
	var retentionUntil sql.NullTime
	if err := r.db.QueryRow(ctx, query, args...).Scan(
		&out.ProxyContentRetained,
		&retentionUntil,
		&out.RequestID,
		&out.OccurredAt,
		&out.UserID,
		&out.Username,
		&out.ClientID,
		&out.ClientName,
		&out.SourceIP,
		&out.AgentType,
		&out.Provider,
		&out.Target,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get request evidence metadata: %w", err)
	}
	if retentionUntil.Valid {
		out.RetentionUntil = &retentionUntil.Time
	}
	return &out, nil
}

// List retrieves request logs for a tenant with related counts
func (r *RequestLogRepository) List(ctx context.Context, tenantID string, limit, offset int) ([]*RequestLog, int, error) {
	return r.ListFiltered(ctx, RequestLogListFilter{TenantID: tenantID, Limit: limit, Offset: offset})
}

func buildPortalCallRecordQueries(filter PortalCallRecordFilter) (string, []interface{}, string, []interface{}) {
	baseWhere := `
	        rl.tenant_id = $1
	        AND (rl.user_id = $2 OR rl.user_id IN (SELECT user_id FROM user_history))
	        AND rl.created_at >= $3
	        AND COALESCE(rl.endpoint_type, '') <> 'proxy'
	        AND COALESCE(rl.request_status, '') NOT IN ('', 'received', 'in_progress')
	    `
	countArgs := []interface{}{filter.TenantID, filter.UserID, filter.StartTime}
	queryArgs := append([]interface{}{}, countArgs...)
	listWhere := baseWhere
	if !filter.BeforeCreatedAt.IsZero() {
		queryArgs = append(queryArgs, filter.BeforeCreatedAt, filter.BeforeRequestID)
		listWhere += fmt.Sprintf(
			"\n        AND (rl.created_at, rl.request_id) < ($%d, $%d)",
			len(queryArgs)-1,
			len(queryArgs),
		)
	}
	if filter.RequestID != "" {
		queryArgs = append(queryArgs, filter.RequestID)
		listWhere += fmt.Sprintf("\n        AND rl.request_id = $%d", len(queryArgs))
	}
	queryArgs = append(queryArgs, filter.Limit)
	query := userhistory.OwnersCTE + fmt.Sprintf(`
	        SELECT
	            rl.request_id,
	            rl.created_at,
	            COALESCE(
	                NULLIF(m.model_label, ''),
	                NULLIF(m.model_name, ''),
	                '未识别模型'
	            ) AS model,
            COALESCE(rl.request_status, '') AS request_status,
            COALESCE(rl.upstream_status_code, 0) AS upstream_status_code,
            GREATEST(COALESCE(rl.input_tokens, 0), 0) AS input_tokens,
            GREATEST(COALESCE(buf.cached_input_tokens, 0), 0) AS cached_input_tokens,
            GREATEST(COALESCE(buf.cache_write_input_tokens, 0), 0) AS cache_write_input_tokens,
            GREATEST(COALESCE(rl.output_tokens, 0), 0) AS output_tokens,
            GREATEST(COALESCE(rl.latency_ms, 0), 0) AS latency_ms,
            COALESCE(rl.agent_type, '') AS agent_type,
            COALESCE(rl.endpoint_type, '') AS endpoint_type,
	            COALESCE(
	                NULLIF(rl.input_audit_result->>'action', ''),
	                NULLIF(rl.input_audit_result->>'action_taken', ''),
	                ''
	            ) AS input_action,
	            COALESCE(
	                NULLIF(rl.output_audit_result->>'action', ''),
	                NULLIF(rl.output_audit_result->>'action_taken', ''),
	                ''
	            ) AS output_action,
            (
                SELECT COUNT(*)
                FROM security_events se
                WHERE se.tenant_id = rl.tenant_id
                  AND se.request_id = rl.request_id
	            ) AS security_event_count,
	            CASE
	                WHEN (%s) = 'settled' THEN (%s)::bigint
	                ELSE NULL
	            END AS billing_amount_micros,
	            COALESCE((%s), '') AS billing_currency,
	            (%s) AS billing_state
	        FROM request_logs rl
	        LEFT JOIN models m ON m.id = rl.model_id
	        LEFT JOIN billing_reservations br ON br.tenant_id = rl.tenant_id AND br.request_id = rl.request_id
	        LEFT JOIN billing_charge_records bc ON bc.tenant_id = rl.tenant_id AND bc.request_id = rl.request_id
	        LEFT JOIN billing_usage_facts buf ON buf.tenant_id = rl.tenant_id AND buf.request_id = rl.request_id
	        WHERE %s
	        ORDER BY rl.created_at DESC, rl.request_id DESC
	        LIMIT $%d
	    `, billingStateSQL, billingAmountSQL, billingCurrencySQL, billingStateSQL, listWhere, len(queryArgs))
	countQuery := userhistory.OwnersCTE + `SELECT COUNT(*) FROM request_logs rl WHERE ` + baseWhere
	return query, queryArgs, countQuery, countArgs
}

// ListPortalCallRecords returns completed model calls for exactly one tenant user.
func (r *RequestLogRepository) ListPortalCallRecords(
	ctx context.Context,
	filter PortalCallRecordFilter,
) ([]PortalCallRecord, int, error) {
	query, args, countQuery, countArgs := buildPortalCallRecordQueries(filter)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list portal call records: %w", err)
	}
	defer rows.Close()

	records := make([]PortalCallRecord, 0)
	for rows.Next() {
		var record PortalCallRecord
		if err := rows.Scan(
			&record.RequestID,
			&record.CreatedAt,
			&record.Model,
			&record.Status,
			&record.UpstreamStatus,
			&record.InputTokens,
			&record.CachedInputTokens,
			&record.CacheWriteInputTokens,
			&record.OutputTokens,
			&record.LatencyMs,
			&record.AgentType,
			&record.EndpointType,
			&record.InputAction,
			&record.OutputAction,
			&record.SecurityEventCount,
			&record.BillingAmountMicros,
			&record.BillingCurrency,
			&record.BillingState,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan portal call record: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to read portal call records: %w", err)
	}

	var total int
	if err := r.db.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count portal call records: %w", err)
	}
	return records, total, nil
}

func buildRequestLogListQuery(filter RequestLogListFilter) (string, []interface{}, string, []interface{}) {
	args := []interface{}{filter.TenantID}
	// 平台自建的请求日志（运行故障告警等）不是业务请求，不进请求日志列表（2.9.22）。
	where := []string{"rl.tenant_id = $1", ExcludeNonBusinessEndpointsSQL("rl")}
	if !filter.StartTime.IsZero() {
		args = append(args, filter.StartTime)
		where = append(where, fmt.Sprintf("rl.created_at >= $%d", len(args)))
	}
	if !filter.EndTime.IsZero() {
		args = append(args, filter.EndTime)
		where = append(where, fmt.Sprintf("rl.created_at <= $%d", len(args)))
	}
	baseWhere := strings.Join(where, " AND ")
	limitArg := len(args) + 1
	offsetArg := len(args) + 2
	queryArgs := append(append([]interface{}{}, args...), filter.Limit, filter.Offset)
	query := fmt.Sprintf(`
			WITH page AS (
				SELECT
					rl.id, rl.request_id, rl.tenant_id, COALESCE(rl.project_id, '') AS project_id,
					COALESCE(rl.user_id, '') AS user_id,
					COALESCE(rl.client_id, '') AS client_id,
					COALESCE(rl.provider_id, '') AS provider_id,
					COALESCE(rl.model_id, '') AS model_id,
					COALESCE(m.model_name, rl.model_id, '') AS model_name,
					COALESCE(rl.session_id, '') AS session_id,
					COALESCE(rl.agent_type, '') AS agent_type,
					COALESCE(rl.endpoint_type, '') AS endpoint_type,
					COALESCE(rl.request_status, '') AS request_status,
					COALESCE(rl.upstream_status_code, 0) AS status_code,
					COALESCE(rl.latency_ms, 0) AS latency_ms,
					COALESCE(rl.input_tokens, 0) AS input_tokens,
					COALESCE(rl.output_tokens, 0) AS output_tokens,
					COALESCE(rl.total_cost, 0) AS total_cost,
					rl.created_at,
					COALESCE(rl.input_audit_result, '{}'::jsonb) AS input_audit_result,
					COALESCE(rl.output_audit_result, '{}'::jsonb) AS output_audit_result
				FROM request_logs rl
				LEFT JOIN models m ON m.id = rl.model_id
				WHERE %s
				ORDER BY rl.created_at DESC
				LIMIT $%d OFFSET $%d
			)
			SELECT
				page.id, page.request_id, page.tenant_id, page.project_id,
				page.user_id, page.client_id, page.provider_id, page.model_id,
				page.model_name, page.session_id,
				CASE
					WHEN NULLIF(page.session_id, '') IS NOT NULL THEN 'client:' || page.session_id
					WHEN fuc.content IS NOT NULL THEN 'fallback:' || md5(fuc.content) || ':' || date_trunc('day', page.created_at)::text
					ELSE 'request:' || page.request_id
				END,
				page.agent_type, page.endpoint_type, page.request_status, page.status_code,
				page.latency_ms, page.input_tokens, page.output_tokens, page.total_cost,
				page.created_at, page.input_audit_result, page.output_audit_result,
				(SELECT COUNT(*) FROM content_logs WHERE content_logs.request_id = page.id) as content_count,
				(SELECT COUNT(*) FROM tool_call_logs WHERE tool_call_logs.request_id = page.request_id) as tool_call_count,
				(SELECT COUNT(*) FROM security_events WHERE security_events.request_id = page.request_id) as security_event_count
			FROM page
			LEFT JOIN LATERAL (
				SELECT cl.content
				FROM content_logs cl
				WHERE cl.request_id = page.id
					AND cl.tenant_id = page.tenant_id
					AND cl.role = 'user'
					AND cl.content !~* '^The user stepped away and is coming back'
					AND cl.content !~* '^Recap in under [0-9]+ words'
					AND cl.content !~* '^<system-reminder>'
				ORDER BY cl.created_at ASC
				LIMIT 1
			) fuc ON TRUE
			ORDER BY page.created_at DESC
	`, baseWhere, limitArg, offsetArg)
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM request_logs rl WHERE %s`, baseWhere)
	return query, queryArgs, countQuery, args
}

func (r *RequestLogRepository) ListFiltered(ctx context.Context, filter RequestLogListFilter) ([]*RequestLog, int, error) {
	query, args, countQuery, countArgs := buildRequestLogListQuery(filter)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list request logs: %w", err)
	}
	defer rows.Close()

	logs := []*RequestLog{}
	for rows.Next() {
		var log RequestLog
		var inputAuditJSON, outputAuditJSON []byte
		err := rows.Scan(
			&log.ID,
			&log.RequestID,
			&log.TenantID,
			&log.ProjectID,
			&log.UserID,
			&log.ClientID,
			&log.ProviderID,
			&log.ModelID,
			&log.ModelName,
			&log.SessionID,
			&log.ConversationID,
			&log.AgentType,
			&log.EndpointType,
			&log.RequestStatus,
			&log.StatusCode,
			&log.LatencyMs,
			&log.InputTokens,
			&log.OutputTokens,
			&log.TotalCost,
			&log.CreatedAt,
			&inputAuditJSON,
			&outputAuditJSON,
			&log.ContentCount,
			&log.ToolCallCount,
			&log.SecurityEventCount,
		)
		if err != nil {
			return nil, 0, err
		}
		// Parse JSONB fields
		if len(inputAuditJSON) > 0 {
			json.Unmarshal(inputAuditJSON, &log.InputAuditResult)
		}
		if len(outputAuditJSON) > 0 {
			json.Unmarshal(outputAuditJSON, &log.OutputAuditResult)
		}
		logs = append(logs, &log)
	}

	total := len(logs)
	if !filter.SkipTotal {
		if err := r.db.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("failed to count request logs: %w", err)
		}
	}

	return logs, total, nil
}

// GetByProject retrieves request logs for a project
func (r *RequestLogRepository) GetByProject(ctx context.Context, projectID string, limit, offset int) ([]*RequestLog, int, error) {
	query := `
			SELECT id, request_id, tenant_id, COALESCE(project_id, ''),
			       COALESCE(user_id, ''),
			       COALESCE(client_id, ''),
			       COALESCE(provider_id, ''),
			       COALESCE(model_id, ''),
			       COALESCE(model_id, ''),
			       COALESCE(session_id, ''),
			       COALESCE(agent_type, ''),
			       COALESCE(endpoint_type, ''),
			       COALESCE(request_status, ''),
			       COALESCE(upstream_status_code, 0),
			       COALESCE(latency_ms, 0),
			       COALESCE(input_tokens, 0),
			       COALESCE(output_tokens, 0),
			       COALESCE(total_cost, 0),
			       created_at
			FROM request_logs
			WHERE project_id = $1
			ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.Query(ctx, query, projectID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list request logs: %w", err)
	}
	defer rows.Close()

	logs := []*RequestLog{}
	for rows.Next() {
		var log RequestLog
		err := rows.Scan(
			&log.ID,
			&log.RequestID,
			&log.TenantID,
			&log.ProjectID,
			&log.UserID,
			&log.ClientID,
			&log.ProviderID,
			&log.ModelID,
			&log.ModelName,
			&log.SessionID,
			&log.AgentType,
			&log.EndpointType,
			&log.RequestStatus,
			&log.StatusCode,
			&log.LatencyMs,
			&log.InputTokens,
			&log.OutputTokens,
			&log.TotalCost,
			&log.CreatedAt,
		)
		if err != nil {
			return nil, 0, err
		}
		logs = append(logs, &log)
	}

	// Get total count
	countQuery := `SELECT COUNT(*) FROM request_logs WHERE project_id = $1`
	var total int
	r.db.QueryRow(ctx, countQuery, projectID).Scan(&total)

	return logs, total, nil
}

// ListByAuditAction retrieves request logs filtered by action_taken in audit results.
// When action is empty, all audit records (any action) are returned.
func (r *RequestLogRepository) ListByAuditAction(ctx context.Context, tenantID string, action string, startTime, endTime time.Time, limit, offset int) ([]*RequestLog, int, error) {
	return r.ListByAuditActionFiltered(ctx, AuditActionListFilter{
		TenantID: tenantID, Action: action, StartTime: startTime, EndTime: endTime, Limit: limit, Offset: offset,
	})
}

func buildAuditActionListQuery(filter AuditActionListFilter) (string, []interface{}, string, []interface{}) {
	var (
		query      string
		countQuery string
		args       []interface{}
		countArgs  []interface{}
	)

	tenantID := filter.TenantID
	action := filter.Action
	startTime := filter.StartTime
	endTime := filter.EndTime
	limit := filter.Limit
	offset := filter.Offset

	selectCols := `SELECT id, request_id, tenant_id, COALESCE(project_id, ''),
			       COALESCE(user_id, ''),
			       COALESCE(client_id, ''),
			       COALESCE(provider_id, ''),
			       COALESCE(model_id, ''),
			       COALESCE(model_id, ''),
			       COALESCE(session_id, ''),
			       COALESCE(agent_type, ''),
			       COALESCE(endpoint_type, ''),
			       COALESCE(request_status, ''),
			       COALESCE(upstream_status_code, 0),
			       COALESCE(latency_ms, 0),
			       COALESCE(input_tokens, 0),
			       COALESCE(output_tokens, 0),
			       COALESCE(total_cost, 0),
			       created_at,
			       COALESCE(input_audit_result, '{}'::jsonb),
			       COALESCE(output_audit_result, '{}'::jsonb)
			FROM request_logs`

	if action == "" {
		// No action filter — return all logs in the time range
		query = selectCols + `
			WHERE tenant_id = $1
				AND created_at >= $2 AND created_at <= $3
			ORDER BY created_at DESC
			LIMIT $4 OFFSET $5`
		args = []interface{}{tenantID, startTime, endTime, limit, offset}
		countQuery = `SELECT COUNT(*) FROM request_logs WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3`
		countArgs = []interface{}{tenantID, startTime, endTime}
	} else {
		query = selectCols + `
			WHERE tenant_id = $1
				AND created_at >= $2 AND created_at <= $3
				AND (input_audit_result->>'action_taken' = $4 OR output_audit_result->>'action_taken' = $4)
			ORDER BY created_at DESC
			LIMIT $5 OFFSET $6`
		args = []interface{}{tenantID, startTime, endTime, action, limit, offset}
		countQuery = `SELECT COUNT(*) FROM request_logs WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3 AND (input_audit_result->>'action_taken' = $4 OR output_audit_result->>'action_taken' = $4)`
		countArgs = []interface{}{tenantID, startTime, endTime, action}
	}
	return query, args, countQuery, countArgs
}

func (r *RequestLogRepository) ListByAuditActionFiltered(ctx context.Context, filter AuditActionListFilter) ([]*RequestLog, int, error) {
	query, args, countQuery, countArgs := buildAuditActionListQuery(filter)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list request logs by audit action: %w", err)
	}
	defer rows.Close()

	logs := []*RequestLog{}
	for rows.Next() {
		var log RequestLog
		var inputAuditJSON, outputAuditJSON []byte
		err := rows.Scan(
			&log.ID,
			&log.RequestID,
			&log.TenantID,
			&log.ProjectID,
			&log.UserID,
			&log.ClientID,
			&log.ProviderID,
			&log.ModelID,
			&log.ModelName,
			&log.SessionID,
			&log.AgentType,
			&log.EndpointType,
			&log.RequestStatus,
			&log.StatusCode,
			&log.LatencyMs,
			&log.InputTokens,
			&log.OutputTokens,
			&log.TotalCost,
			&log.CreatedAt,
			&inputAuditJSON,
			&outputAuditJSON,
		)
		if err != nil {
			return nil, 0, err
		}
		// Parse JSONB fields
		if len(inputAuditJSON) > 0 {
			json.Unmarshal(inputAuditJSON, &log.InputAuditResult)
		}
		if len(outputAuditJSON) > 0 {
			json.Unmarshal(outputAuditJSON, &log.OutputAuditResult)
		}
		logs = append(logs, &log)
	}

	total := len(logs)
	if !filter.SkipTotal {
		if err := r.db.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("failed to count request logs by audit action: %w", err)
		}
	}

	return logs, total, nil
}

// SecurityEvent represents a security event record
type SecurityEvent struct {
	AgentInstanceID string
	ID              string
	RequestID       string
	TenantID        string
	ProjectID       string
	UserID          string
	EventType       string
	Severity        string
	RuleID          string
	RuleName        string
	RuleType        string
	ActionTaken     string
	MatchedSummary  map[string]interface{}
	EvidenceRef     string
	PrincipalKey    string
	CreatedAt       time.Time
}

// SecurityEventRepository handles security event database operations
type SecurityEventRepository struct {
	db *pgxpool.Pool
}

// NewSecurityEventRepository creates a new security event repository
func NewSecurityEventRepository(db *pgxpool.Pool) *SecurityEventRepository {
	return &SecurityEventRepository{db: db}
}

type SecurityEventUpsert struct {
	ID             string
	RequestID      string
	TenantID       string
	ProjectID      string
	UserID         string
	EventType      string
	Severity       string
	RuleID         string
	ActionTaken    string
	MatchedSummary map[string]interface{}
	EvidenceRef    string
	// PrincipalKey 契约第 6 条：写入点物化 COALESCE(user_id, client_id, source_ip)。
	// 为空时 Upsert 回退 UserID（本仓库的调用方多为带用户上下文的管理面/评估链路）。
	PrincipalKey string
	// ConversationKey 会话归组键；管理面链路通常为空（计数口径回退 request_id）。
	ConversationKey string
}

// resolvePrincipalKey 物化 Plan D 契约第 6 条主体键回退：
// 显式 principalKey 优先，缺省回退 userID（管理面写入点多带用户上下文）。
// 二者皆空返回空串，由 SQL 侧 NULLIF 落 NULL。
func resolvePrincipalKey(principalKey, userID string) string {
	if principalKey != "" {
		return principalKey
	}
	return userID
}

// Upsert inserts a security event or updates the existing deterministic event.
func (r *SecurityEventRepository) Upsert(ctx context.Context, event SecurityEventUpsert) error {
	if event.ID == "" || event.RequestID == "" || event.TenantID == "" || event.ProjectID == "" || event.EventType == "" || event.Severity == "" || event.ActionTaken == "" {
		return fmt.Errorf("security event missing required fields")
	}
	summaryJSON, err := json.Marshal(event.MatchedSummary)
	if err != nil {
		return fmt.Errorf("failed to marshal security event summary: %w", err)
	}
	principal := resolvePrincipalKey(event.PrincipalKey, event.UserID)
	_, err = r.db.Exec(ctx, `
		INSERT INTO security_events (
			id, request_id, tenant_id, project_id, user_id, event_type, severity, rule_id,
			action_taken, matched_summary, evidence_ref, principal_key, conversation_key
		) VALUES (
			$1, $2, $3, $4, NULLIF($5, ''), $6, $7, NULLIF($8, ''),
			$9, $10::jsonb, NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, '')
		)
		ON CONFLICT (id) DO UPDATE SET
			severity = EXCLUDED.severity,
			action_taken = EXCLUDED.action_taken,
			matched_summary = EXCLUDED.matched_summary,
			evidence_ref = EXCLUDED.evidence_ref,
			principal_key = COALESCE(EXCLUDED.principal_key, security_events.principal_key)
	`, event.ID, event.RequestID, event.TenantID, event.ProjectID, event.UserID, event.EventType, event.Severity, event.RuleID, event.ActionTaken, string(summaryJSON), event.EvidenceRef, principal, event.ConversationKey)
	if err != nil {
		return fmt.Errorf("failed to upsert security event: %w", err)
	}
	return nil
}

// List retrieves security events for a tenant
func (r *SecurityEventRepository) List(ctx context.Context, tenantID string, limit, offset int) ([]*SecurityEvent, int, error) {
	return r.ListFiltered(ctx, tenantID, SecurityEventFilter{}, limit, offset)
}

// SecurityEventFilter 是 List/ListFiltered 的可选过滤条件；零值 = 无过滤（老行为）。
type SecurityEventFilter struct {
	AgentInstanceID string
	UserID          string
	ClientID        string
	Severity        string
	EventType       string
	ProjectIDs      []string
	StartTime       *time.Time
	EndTime         *time.Time
}

// buildSecurityEventsWhere 返回 (joinClause, where, args)。
// client_id 在 request_logs 上，user/client 过滤时 JOIN request_logs（request_id 唯一，1:1 安全；
// 索引 idx_security_events_request_id + 076 的 (tenant_id, request_id) 复合索引兜底）。
// user_id 双侧匹配：security_events.user_id 可空，历史事件从 rl.user_id 兜底。
func buildSecurityEventsWhere(tenantID string, f SecurityEventFilter) (string, string, []interface{}) {
	join := ""
	clauses := []string{"se.tenant_id = $1"}
	args := []interface{}{tenantID}
	add := func(clause string, value interface{}) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if f.AgentInstanceID != "" {
		add("se.agent_instance_id = $%d", f.AgentInstanceID)
	}
	if f.UserID != "" || f.ClientID != "" {
		join = "LEFT JOIN request_logs rl ON rl.request_id = se.request_id"
	}
	if f.UserID != "" {
		args = append(args, f.UserID)
		clauses = append(clauses, fmt.Sprintf("(se.user_id = $%d OR rl.user_id = $%d)", len(args), len(args)))
	}
	if f.ClientID != "" {
		add("rl.client_id = $%d", f.ClientID)
	}
	if f.Severity != "" {
		add("se.severity = $%d", f.Severity)
	}
	if f.EventType != "" {
		add("se.event_type = $%d", f.EventType)
	}
	if len(f.ProjectIDs) > 0 {
		// security_events.project_id 有索引 idx_security_events_project_created，ANY 走索引。
		add("se.project_id = ANY($%d)", f.ProjectIDs)
	}
	if f.StartTime != nil {
		add("se.created_at >= $%d", *f.StartTime)
	}
	if f.EndTime != nil {
		add("se.created_at <= $%d", *f.EndTime)
	}
	return join, strings.Join(clauses, " AND "), args
}

// ListFiltered 带过滤条件列安全事件。SELECT 列与老 List 完全一致（rules 别名 r 与
// request_logs 别名 rl 不冲突）；count 与 list 共享 join/where/args。
func (r *SecurityEventRepository) ListFiltered(ctx context.Context, tenantID string, filter SecurityEventFilter, limit, offset int) ([]*SecurityEvent, int, error) {
	join, where, args := buildSecurityEventsWhere(tenantID, filter)
	query := fmt.Sprintf(`
		SELECT se.id, se.request_id, se.tenant_id, se.project_id,
		       COALESCE(se.user_id, ''),
		       se.event_type,
		       se.severity,
		       COALESCE(se.rule_id, ''),
		       COALESCE(r.name, ''),
		       COALESCE(r.rule_type, ''),
		       se.action_taken,
		       COALESCE(se.matched_summary, '{}'::jsonb),
		       COALESCE(se.evidence_ref, ''),
		       se.created_at, COALESCE(se.agent_instance_id, '')
		FROM security_events se
		LEFT JOIN rules r ON r.id = se.rule_id
		%s
		WHERE %s
		ORDER BY se.created_at DESC, se.id DESC
		LIMIT $%d OFFSET $%d
	`, join, where, len(args)+1, len(args)+2)
	queryArgs := append(append([]interface{}{}, args...), limit, offset)

	rows, err := r.db.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list security events: %w", err)
	}
	defer rows.Close()

	events := []*SecurityEvent{}
	for rows.Next() {
		var event SecurityEvent
		var matchedJSON []byte
		err := rows.Scan(
			&event.ID,
			&event.RequestID,
			&event.TenantID,
			&event.ProjectID,
			&event.UserID,
			&event.EventType,
			&event.Severity,
			&event.RuleID,
			&event.RuleName,
			&event.RuleType,
			&event.ActionTaken,
			&matchedJSON,
			&event.EvidenceRef,
			&event.CreatedAt,
			&event.AgentInstanceID,
		)
		if err != nil {
			return nil, 0, err
		}
		event.MatchedSummary = map[string]interface{}{}
		if len(matchedJSON) > 0 {
			json.Unmarshal(matchedJSON, &event.MatchedSummary)
		}
		events = append(events, &event)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	// Get total count（沿用老 List 的容错语义：count 失败不整体报错，total 落 0）
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM security_events se %s WHERE %s`, join, where)
	var total int
	r.db.QueryRow(ctx, countQuery, args...).Scan(&total)

	return events, total, nil
}

// clampWindowHours 兜底 ListSemanticSince 的时间窗：非法窗（h<=0 或 h>8760，
// 即超过一年）回落默认 24 小时；合法窗原样返回。避免 overview 端点因外部传入
// 的异常窗打出全表扫或空窗。
func clampWindowHours(h int) int {
	if h <= 0 || h > 8760 {
		return 24
	}
	return h
}

// ListSemanticSince 拉取时间窗内 event_type='semantic_attack' 的命中事件，
// 供智能检测控制台 overview 端点聚合级联漏斗。全租户扫描（私有化单租户下等价
// 于当前租户），按 created_at DESC，硬上限 5000 条防跑飞。列顺序与 List 严格一致。
func (r *SecurityEventRepository) ListSemanticSince(ctx context.Context, hours int) ([]*SecurityEvent, error) {
	hours = clampWindowHours(hours)

	query := `
		SELECT se.id, se.request_id, se.tenant_id, se.project_id,
		       COALESCE(se.user_id, ''),
		       se.event_type,
		       se.severity,
		       COALESCE(se.rule_id, ''),
		       COALESCE(r.name, ''),
		       COALESCE(r.rule_type, ''),
		       se.action_taken,
		       COALESCE(se.matched_summary, '{}'::jsonb),
		       COALESCE(se.evidence_ref, ''),
		       se.created_at, COALESCE(se.agent_instance_id, '')
		FROM security_events se
		LEFT JOIN rules r ON r.id = se.rule_id
		WHERE se.event_type = 'semantic_attack'
		  AND se.created_at >= NOW() - make_interval(hours => $1)
		ORDER BY se.created_at DESC
		LIMIT 5000
	`

	rows, err := r.db.Query(ctx, query, hours)
	if err != nil {
		return nil, fmt.Errorf("failed to list semantic events: %w", err)
	}
	defer rows.Close()

	events := []*SecurityEvent{}
	for rows.Next() {
		var event SecurityEvent
		var matchedJSON []byte
		if err := rows.Scan(
			&event.ID,
			&event.RequestID,
			&event.TenantID,
			&event.ProjectID,
			&event.UserID,
			&event.EventType,
			&event.Severity,
			&event.RuleID,
			&event.RuleName,
			&event.RuleType,
			&event.ActionTaken,
			&matchedJSON,
			&event.EvidenceRef,
			&event.CreatedAt,
			&event.AgentInstanceID,
		); err != nil {
			return nil, err
		}
		event.MatchedSummary = map[string]interface{}{}
		if len(matchedJSON) > 0 {
			json.Unmarshal(matchedJSON, &event.MatchedSummary)
		}
		events = append(events, &event)
	}

	return events, nil
}

// matchedSummaryTriageSuppressible 报告一条事件的 matched_summary 是否整体被 LLM triage 闸压制：
// 当且仅当其每个 finding 都被标 triage.verdict=likely_false_positive 时返回 true。
// 任何未被标 likely_fp 的 finding 都让整事件穿透（不因个别 FP 藏真信号）。
// 与 control-plane alert.allTriageSuppressible / handler allSemanticTriageSuppressible 语义一致，
// 但跨桶适用（不限 semantic_attack）——误报压制的意图类 finding 多落在 security_check 桶。
func matchedSummaryTriageSuppressible(summary map[string]any) bool {
	findingsRaw, ok := summary["findings"].([]any)
	if !ok {
		return false
	}
	sawSuppressible := false
	for _, raw := range findingsRaw {
		fm, ok := raw.(map[string]any)
		if !ok {
			return false // 形状异常 → 不压（fail open）
		}
		tr, ok := fm["triage"].(map[string]any)
		if !ok {
			return false // 无 triage → 存在未裁判 finding → 整事件提升
		}
		if v, _ := tr["verdict"].(string); v != "likely_false_positive" {
			return false // 非 likely_fp（如 confirmed_risk）→ 整事件提升
		}
		sawSuppressible = true
	}
	return sawSuppressible
}

// CountTriageSuppressedSince 计窗内被 LLM triage 闸整事件压制的安全事件数（SFIX-1(c) fp_suppressed 源）。
//
// 口径：跨全部 event_type 桶（误报压制的意图类 finding 多落 security_check，非 semantic_attack），
// SQL 先按 jsonb 廉价预筛「至少含一个 triage.verdict=likely_false_positive 的 finding」缩小候选集，
// 再用 matchedSummaryTriageSuppressible 施加完整安全谓词（每 finding 皆 likely_fp）。
// 全租户扫描（私有化单租户下等价当前租户）。窗经 clampWindowHours 兜底，硬上限 20000 行防跑飞。
func (r *SecurityEventRepository) CountTriageSuppressedSince(ctx context.Context, hours int) (int, error) {
	hours = clampWindowHours(hours)

	query := `
		SELECT COALESCE(se.matched_summary, '{}'::jsonb)
		FROM security_events se
		WHERE se.created_at >= NOW() - make_interval(hours => $1)
		  AND se.matched_summary @> '{"findings":[{"triage":{"verdict":"likely_false_positive"}}]}'::jsonb
		ORDER BY se.created_at DESC
		LIMIT 20000
	`

	rows, err := r.db.Query(ctx, query, hours)
	if err != nil {
		return 0, fmt.Errorf("failed to count triage-suppressed events: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var matchedJSON []byte
		if err := rows.Scan(&matchedJSON); err != nil {
			return 0, err
		}
		summary := map[string]any{}
		if len(matchedJSON) > 0 {
			json.Unmarshal(matchedJSON, &summary)
		}
		if matchedSummaryTriageSuppressible(summary) {
			count++
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

// ListByRequest retrieves security events for a specific request_id
func (r *SecurityEventRepository) ListByRequest(ctx context.Context, tenantID, requestID string) ([]*SecurityEvent, error) {
	return r.listByRequest(ctx, tenantID, requestID, "", time.Time{}, time.Time{})
}

func (r *SecurityEventRepository) ListByRequestScoped(ctx context.Context, tenantID, requestID string, start, end time.Time, environmentScope string) ([]*SecurityEvent, error) {
	return r.listByRequest(ctx, tenantID, requestID, environmentScope, start, end)
}

func (r *SecurityEventRepository) listByRequest(ctx context.Context, tenantID, requestID, environmentScope string, start, end time.Time) ([]*SecurityEvent, error) {
	scopes := EnvironmentScopesForRead(environmentScope)
	eventWindow := ""
	args := []interface{}{tenantID, requestID}
	if len(scopes) > 0 && !start.IsZero() && !end.IsZero() {
		args = append(args, scopes, start.UTC(), end.UTC())
		eventWindow = " AND se.created_at >= $4 AND se.created_at < $5 AND EXISTS (SELECT 1 FROM request_logs rl_scope WHERE rl_scope.tenant_id = se.tenant_id AND rl_scope.request_id = se.request_id AND rl_scope.environment_scope = ANY($3) AND rl_scope.created_at >= $4 AND rl_scope.created_at < $5)"
	}
	query := `
		SELECT se.id, se.request_id, se.tenant_id, se.project_id,
		       COALESCE(se.user_id, ''),
		       se.event_type,
		       se.severity,
		       COALESCE(se.rule_id, ''),
		       COALESCE(r.name, ''),
		       COALESCE(r.rule_type, ''),
		       se.action_taken,
		       COALESCE(se.matched_summary, '{}'::jsonb),
		       COALESCE(se.evidence_ref, ''),
		       se.created_at, COALESCE(se.agent_instance_id, '')
		FROM security_events se
		LEFT JOIN rules r ON r.id = se.rule_id
		WHERE se.tenant_id = $1 AND se.request_id = $2` + eventWindow + `
		ORDER BY se.created_at DESC
	`

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list security events by request: %w", err)
	}
	defer rows.Close()

	events := []*SecurityEvent{}
	for rows.Next() {
		var event SecurityEvent
		var matchedJSON []byte
		err := rows.Scan(
			&event.ID,
			&event.RequestID,
			&event.TenantID,
			&event.ProjectID,
			&event.UserID,
			&event.EventType,
			&event.Severity,
			&event.RuleID,
			&event.RuleName,
			&event.RuleType,
			&event.ActionTaken,
			&matchedJSON,
			&event.EvidenceRef,
			&event.CreatedAt,
			&event.AgentInstanceID,
		)
		if err != nil {
			return nil, err
		}
		event.MatchedSummary = map[string]interface{}{}
		if len(matchedJSON) > 0 {
			json.Unmarshal(matchedJSON, &event.MatchedSummary)
		}
		events = append(events, &event)
	}

	return events, nil
}

// ListByContentSession retrieves security events tied to any request snapshot in a content audit session.
func (r *SecurityEventRepository) ListByContentSession(ctx context.Context, tenantID, sessionID string) ([]*SecurityEvent, error) {
	return r.listByContentSession(ctx, tenantID, sessionID, "", time.Time{}, time.Time{}, 0, 0)
}

func (r *SecurityEventRepository) ListByContentSessionScoped(ctx context.Context, tenantID, sessionID string, start, end time.Time, environmentScope string) ([]*SecurityEvent, error) {
	return r.listByContentSession(ctx, tenantID, sessionID, environmentScope, start, end, 0, 0)
}

func (r *SecurityEventRepository) ListByContentSessionPageScoped(ctx context.Context, tenantID, sessionID string, start, end time.Time, environmentScope string, limit, offset int) ([]*SecurityEvent, bool, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	events, err := r.listByContentSession(ctx, tenantID, sessionID, environmentScope, start, end, limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}
	return events, hasMore, nil
}

func buildContentSessionEventsQuery(scoped bool, limitArg, offsetArg int) string {
	window := ""
	eventWindow := ""
	// Keep the session event list consistent with the session list counters: an
	// event whose findings are all explicitly excluded from security findings is
	// observation telemetry and must not be listed here.
	effectiveEvent := ` AND (
			jsonb_typeof(se.matched_summary->'findings') IS DISTINCT FROM 'array'
			OR jsonb_array_length(se.matched_summary->'findings') = 0
			OR EXISTS (
				SELECT 1
				FROM jsonb_array_elements(se.matched_summary->'findings') se_effective_finding
				WHERE COALESCE(se_effective_finding->>'counts_as_security_finding', 'true') <> 'false'
			)
		)`
	if scoped {
		window = " AND cl.environment_scope = ANY($3) AND cl.created_at >= $4 AND cl.created_at < $5"
		eventWindow = " AND se.created_at >= $4 AND se.created_at < $5 AND EXISTS (SELECT 1 FROM request_logs se_scope_rl WHERE se_scope_rl.tenant_id = $1 AND se_scope_rl.request_id = se.request_id AND se_scope_rl.environment_scope = ANY($3) AND se_scope_rl.created_at >= $4 AND se_scope_rl.created_at < $5)"
	}
	page := ""
	if limitArg > 0 && offsetArg > 0 {
		page = fmt.Sprintf(" LIMIT $%d OFFSET $%d", limitArg, offsetArg)
	}
	return `
		WITH session_requests AS (
			SELECT DISTINCT COALESCE(NULLIF(rl.request_id, ''), cl.request_id) AS security_request_id
			FROM content_logs cl
			LEFT JOIN request_logs rl ON rl.id = cl.request_id` + func() string {
		if scoped {
			return " AND rl.environment_scope = ANY($3)"
		}
		return ""
	}() + `
			WHERE cl.tenant_id = $1 AND cl.session_id = $2` + window + `
		)
		SELECT se.id, se.request_id, se.tenant_id, se.project_id,
		       COALESCE(se.user_id, ''),
		       se.event_type,
		       se.severity,
		       COALESCE(se.rule_id, ''),
		       COALESCE(r.name, ''),
		       COALESCE(r.rule_type, ''),
		       se.action_taken,
		       COALESCE(se.matched_summary, '{}'::jsonb),
		       COALESCE(se.evidence_ref, ''),
		       se.created_at, COALESCE(se.agent_instance_id, '')
		FROM security_events se
		JOIN session_requests sr ON sr.security_request_id = se.request_id
		LEFT JOIN rules r ON r.id = se.rule_id
		WHERE se.tenant_id = $1` + effectiveEvent + eventWindow + `
		ORDER BY se.created_at DESC, se.id DESC` + page
}

func (r *SecurityEventRepository) listByContentSession(ctx context.Context, tenantID, sessionID, environmentScope string, start, end time.Time, limit, offset int) ([]*SecurityEvent, error) {
	scopes := EnvironmentScopesForRead(environmentScope)
	args := []interface{}{tenantID, sessionID}
	scoped := len(scopes) > 0 && !start.IsZero() && !end.IsZero()
	if scoped {
		args = append(args, scopes, start.UTC(), end.UTC())
	}
	limitArg, offsetArg := 0, 0
	if limit > 0 {
		args = append(args, limit, offset)
		limitArg, offsetArg = len(args)-1, len(args)
	}
	query := buildContentSessionEventsQuery(scoped, limitArg, offsetArg)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list security events by content session: %w", err)
	}
	defer rows.Close()

	events := []*SecurityEvent{}
	for rows.Next() {
		var event SecurityEvent
		var matchedJSON []byte
		err := rows.Scan(
			&event.ID,
			&event.RequestID,
			&event.TenantID,
			&event.ProjectID,
			&event.UserID,
			&event.EventType,
			&event.Severity,
			&event.RuleID,
			&event.RuleName,
			&event.RuleType,
			&event.ActionTaken,
			&matchedJSON,
			&event.EvidenceRef,
			&event.CreatedAt,
			&event.AgentInstanceID,
		)
		if err != nil {
			return nil, err
		}
		event.MatchedSummary = map[string]interface{}{}
		if len(matchedJSON) > 0 {
			json.Unmarshal(matchedJSON, &event.MatchedSummary)
		}
		events = append(events, &event)
	}

	return events, nil
}

// secEventInboxSeverities returns the severity set ListUnalerted surfaces to the
// actionable inbox, derived from SECEVENT_INBOX_MIN_SEVERITY (default "high").
// Lowering the floor lets an independent-gateway deployment surface medium/low
// runtime hits without a code change; the default preserves the legacy
// high/critical floor — zero regression to the existing inbox noise treatment.
// Unknown/empty values fall back to the default. This only widens the DB fetch;
// the SecEventBridge confidence/category/source gates still apply downstream.
func secEventInboxSeverities() []string {
	order := []string{"low", "medium", "high", "critical"}
	idx := 2 // default floor: "high"
	floor := strings.ToLower(strings.TrimSpace(os.Getenv("SECEVENT_INBOX_MIN_SEVERITY")))
	for i, s := range order {
		if s == floor {
			idx = i
			break
		}
	}
	out := make([]string, len(order)-idx)
	copy(out, order[idx:])
	return out
}

// secEventSemanticInboxSeverities returns the severity floor applied specifically
// to semantic_attack events. Semantic detection is the gateway's own model-based
// signal (small-model triage + 3B judge) — a medium semantic hit is higher value
// than a rule keyword medium, so a deployment can surface medium semantic attacks
// to the actionable inbox without lowering the global floor (which would re-flood
// the inbox with rule/keyword medium noise). Configure via
// SECEVENT_INBOX_SEMANTIC_MIN_SEVERITY. Unset/unknown falls back to the global
// floor (secEventInboxSeverities) — zero regression: an event still has to clear
// the same bar as everything else unless this knob is explicitly lowered.
func secEventSemanticInboxSeverities() []string {
	order := []string{"low", "medium", "high", "critical"}
	floor := strings.ToLower(strings.TrimSpace(os.Getenv("SECEVENT_INBOX_SEMANTIC_MIN_SEVERITY")))
	for i, s := range order {
		if s == floor {
			out := make([]string, len(order)-i)
			copy(out, order[i:])
			return out
		}
	}
	return secEventInboxSeverities() // unset/unknown → same bar as global floor
}

// secEventAlertGraceSeconds 读取告警提升 grace 窗（秒），默认 0=行为不变。
// 目的：security_events 落库后给异步 LLM triage 标注留落地时间，收敛「先提升进收件箱、
// 裁判随后才写回 likely_false_positive」的竞态。事件只是晚 grace 秒进入告警桥，
// 不丢不减：留证与最终提升语义不变。非法/负值一律回落 0。
func secEventAlertGraceSeconds() int {
	v := strings.TrimSpace(os.Getenv("SECEVENT_ALERT_GRACE_SECONDS"))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// secEventReviewPendingTimeoutSeconds bounds how long async review may remain
// pending before the event becomes eligible for manual review. Recent pending
// rows are skipped by the queue query so they cannot starve unrelated old rows.
func secEventReviewPendingTimeoutSeconds() int {
	return int(alertconfig.ReviewPendingTimeout() / time.Second)
}

const (
	secEventRealtimeWindowSeconds = 15 * 60
	secEventRealtimeQuota         = 50
)

// listUnalertedQuery builds a bounded dual-lane queue. The realtime lane reserves
// part of every batch for recent critical/high and security-engine events, while
// the oldest lane always receives the remaining capacity. This prevents a large
// historical backlog from delaying new redlines without reintroducing starvation
// of old evidence.
func listUnalertedQuery(graceSeconds int) string {
	graceClause := ""
	realtimeWindowArg := "$5"
	realtimeQuotaArg := "$6"
	if graceSeconds > 0 {
		graceClause = `
		  AND se.created_at < NOW() - ($5::bigint * INTERVAL '1 second')`
		realtimeWindowArg = "$6"
		realtimeQuotaArg = "$7"
	}
	eligible := `
		  AND (se.severity = ANY($2::text[])
		       OR (se.event_type = 'semantic_attack' AND se.severity = ANY($3::text[]))
               OR se.event_type = 'security_check_failed')
		  AND NOT (
			COALESCE(se.matched_summary->>'review_state', '') = 'review_pending'
			AND se.created_at >= NOW() - ($4::bigint * INTERVAL '1 second')
		  )` + graceClause
	selectColumns := `se.id, COALESCE(se.request_id, '') AS request_id, se.tenant_id, COALESCE(se.project_id, '') AS project_id,
		       COALESCE(se.user_id, '') AS user_id,
		       se.event_type,
		       se.severity,
		       COALESCE(se.rule_id, '') AS rule_id,
		       COALESCE(r.name, '') AS rule_name,
		       COALESCE(r.rule_type, '') AS rule_type,
		       se.action_taken,
		       COALESCE(se.matched_summary, '{}'::jsonb) AS matched_summary,
		       COALESCE(se.evidence_ref, '') AS evidence_ref,
		       COALESCE(se.principal_key, '') AS principal_key,
		       se.created_at, COALESCE(se.agent_instance_id, '') AS agent_instance_id`
	query := `
		WITH recent AS (
			SELECT ` + selectColumns + `, 0 AS queue_priority
			FROM security_events se
			LEFT JOIN rules r ON r.id = se.rule_id
			WHERE se.alerted_at IS NULL` + eligible + `
			  AND se.created_at >= NOW() - (` + realtimeWindowArg + `::bigint * INTERVAL '1 second')
			ORDER BY CASE LOWER(se.severity)
				WHEN 'critical' THEN 0
				WHEN 'high' THEN 1
				ELSE 2
			END ASC,
			CASE WHEN se.event_type IN ('security_check', 'semantic_attack') THEN 0 ELSE 1 END ASC,
			se.created_at ASC, se.id ASC
			LIMIT LEAST($1::bigint, ` + realtimeQuotaArg + `::bigint)
		), oldest AS (
			SELECT ` + selectColumns + `, 1 AS queue_priority
			FROM security_events se
			LEFT JOIN rules r ON r.id = se.rule_id
			WHERE se.alerted_at IS NULL` + eligible + `
			  AND NOT EXISTS (SELECT 1 FROM recent rt WHERE rt.id = se.id)
			ORDER BY se.created_at ASC, se.id ASC
			LIMIT $1::bigint
		)
		SELECT id, request_id, tenant_id, project_id, user_id, event_type,
		       severity, rule_id, rule_name, rule_type, action_taken,
		       matched_summary, evidence_ref, principal_key, created_at, agent_instance_id
		FROM (
			SELECT * FROM recent
			UNION ALL
			SELECT * FROM oldest
		) queued
		ORDER BY queue_priority ASC, created_at ASC, id ASC
		LIMIT $1::bigint
	`
	return query
}

// ListUnalerted retrieves a bounded mix of recent high-priority events and the
// oldest eligible evidence. The reserved realtime lane keeps fresh redlines from
// waiting behind a historical backlog; the remaining capacity always advances
// the oldest-first durable checkpoint.
func (r *SecurityEventRepository) ListUnalerted(ctx context.Context, limit int) ([]*SecurityEvent, error) {
	grace := secEventAlertGraceSeconds()
	query := listUnalertedQuery(grace)
	args := []any{limit, secEventInboxSeverities(), secEventSemanticInboxSeverities(), secEventReviewPendingTimeoutSeconds()}
	if grace > 0 {
		args = append(args, grace)
	}
	args = append(args, secEventRealtimeWindowSeconds, secEventRealtimeQuota)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list unalerted security events: %w", err)
	}
	defer rows.Close()

	events := []*SecurityEvent{}
	for rows.Next() {
		var event SecurityEvent
		var matchedJSON []byte
		if err := rows.Scan(
			&event.ID,
			&event.RequestID,
			&event.TenantID,
			&event.ProjectID,
			&event.UserID,
			&event.EventType,
			&event.Severity,
			&event.RuleID,
			&event.RuleName,
			&event.RuleType,
			&event.ActionTaken,
			&matchedJSON,
			&event.EvidenceRef,
			&event.PrincipalKey,
			&event.CreatedAt,
			&event.AgentInstanceID,
		); err != nil {
			return nil, err
		}
		event.MatchedSummary = map[string]interface{}{}
		if len(matchedJSON) > 0 {
			json.Unmarshal(matchedJSON, &event.MatchedSummary)
		}
		events = append(events, &event)
	}

	return events, nil
}

const markSecurityEventsAlertedSQL = `UPDATE security_events
SET alerted_at = NOW(),
    processed_at = COALESCE(processed_at, NOW()),
    delivery = COALESCE(delivery, 'delivered')
WHERE id = ANY($1)`

// MarkAlerted persists both the legacy checkpoint and the split lifecycle dimensions.
func (r *SecurityEventRepository) MarkAlerted(ctx context.Context, eventIDs []string) error {
	if len(eventIDs) == 0 {
		return nil
	}
	_, err := r.db.Exec(ctx, markSecurityEventsAlertedSQL, eventIDs)
	if err != nil {
		return fmt.Errorf("failed to mark security events as alerted: %w", err)
	}
	return nil
}

// UsageDaily represents daily usage summary
type UsageDaily struct {
	ID           string
	TenantID     string
	ProjectID    string
	UserID       string
	Day          time.Time
	RequestCount int
	InputTokens  int64
	OutputTokens int64
	TotalCost    float64
}

// UsageDailyRepository handles daily usage database operations
type UsageDailyRepository struct {
	db *pgxpool.Pool
}

// NewUsageDailyRepository creates a new usage daily repository
func NewUsageDailyRepository(db *pgxpool.Pool) *UsageDailyRepository {
	return &UsageDailyRepository{db: db}
}

// DB returns the underlying database connection pool
func (r *UsageDailyRepository) DB() *pgxpool.Pool {
	return r.db
}

// GetSummary retrieves usage summary for a tenant
func (r *UsageDailyRepository) GetSummary(ctx context.Context, tenantID string, startDate, endDate time.Time) (*UsageSummary, error) {
	query := `
		SELECT COALESCE(COUNT(*), 0) as requests,
		       COALESCE(SUM(COALESCE(input_tokens, 0)), 0) as input_tokens,
		       COALESCE(SUM(COALESCE(output_tokens, 0)), 0) as output_tokens,
		       COALESCE(SUM(COALESCE(total_cost, 0)), 0) as total_cost
		FROM request_logs
		WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3
	`

	row := r.db.QueryRow(ctx, query, tenantID, startDate, endDate)
	var summary UsageSummary
	summary.TenantID = tenantID

	if err := row.Scan(&summary.Requests, &summary.InputTokens, &summary.OutputTokens, &summary.TotalCost); err != nil {
		return nil, fmt.Errorf("failed to get usage summary: %w", err)
	}

	return &summary, nil
}

// GetByProject retrieves usage by project for a tenant
func (r *UsageDailyRepository) GetByProject(ctx context.Context, tenantID string, startDate, endDate time.Time) ([]*ProjectUsage, error) {
	query := `
		SELECT project_id,
		       COALESCE(COUNT(*), 0) as requests,
		       COALESCE(SUM(COALESCE(input_tokens, 0)), 0) as input_tokens,
		       COALESCE(SUM(COALESCE(output_tokens, 0)), 0) as output_tokens,
		       COALESCE(SUM(COALESCE(total_cost, 0)), 0) as total_cost
		FROM request_logs
		WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY project_id
	`

	rows, err := r.db.Query(ctx, query, tenantID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage by project: %w", err)
	}
	defer rows.Close()

	usages := []*ProjectUsage{}
	for rows.Next() {
		var usage ProjectUsage
		usage.TenantID = tenantID
		err := rows.Scan(&usage.ProjectID, &usage.Requests, &usage.InputTokens, &usage.OutputTokens, &usage.TotalCost)
		if err != nil {
			return nil, err
		}
		usages = append(usages, &usage)
	}

	return usages, nil
}

type UsageSummary struct {
	TenantID     string
	Requests     int
	InputTokens  int64
	OutputTokens int64
	TotalCost    float64
}

type ProjectUsage struct {
	TenantID     string
	ProjectID    string
	Requests     int
	InputTokens  int64
	OutputTokens int64
	TotalCost    float64
}

// RoutingDecision represents a routing decision audit record with model context.
// It is a filtered view of request_logs where routing_decision_json IS NOT NULL.
type RoutingDecision struct {
	ID                  string                 `json:"id"`
	RequestID           string                 `json:"request_id"`
	TenantID            string                 `json:"tenant_id"`
	ProjectID           string                 `json:"project_id"`
	UserID              string                 `json:"user_id"`
	ModelID             string                 `json:"model_id"`
	ModelName           string                 `json:"model_name"` // customer-readable model name from models table join
	ProviderID          string                 `json:"provider_id"`
	SessionID           string                 `json:"session_id"`
	EndpointType        string                 `json:"endpoint_type"`
	RequestStatus       string                 `json:"request_status"`
	StatusCode          int                    `json:"status_code"`
	LatencyMS           *int                   `json:"latency_ms"`
	CreatedAt           time.Time              `json:"created_at"`
	RoutingDecisionJSON map[string]interface{} `json:"routing_decision_json"` // the routing_decision_json JSONB payload
	DecisionParseStatus string                 `json:"-"`
}

type RoutingDecisionFilter struct {
	RequestID string
	From      time.Time
	To        time.Time
	Model     string
	Provider  string
	Result    string
	Fallback  *bool
}

// ListRoutingDecisions retrieves request logs that have routing decisions recorded,
// joining with models table to provide customer-readable model names.
// This is an observability endpoint exposing already-stored routing_decision_json.
func (r *RequestLogRepository) ListRoutingDecisions(ctx context.Context, tenantID string, limit, offset int) ([]*RoutingDecision, int, error) {
	return r.ListRoutingDecisionsFiltered(ctx, tenantID, RoutingDecisionFilter{}, limit, offset)
}

func (r *RequestLogRepository) ListRoutingDecisionsFiltered(ctx context.Context, tenantID string, filter RoutingDecisionFilter, limit, offset int) ([]*RoutingDecision, int, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	from := `
		FROM request_logs rl
		LEFT JOIN models m ON m.id = rl.model_id
		WHERE rl.tenant_id = $1 AND rl.routing_decision_json IS NOT NULL`
	args := []any{tenantID}
	add := func(clause string, value any) {
		args = append(args, value)
		from += fmt.Sprintf(" AND "+clause, len(args))
	}
	if filter.RequestID != "" {
		add("rl.request_id = $%d", filter.RequestID)
	}
	if !filter.From.IsZero() {
		add("rl.created_at >= $%d", filter.From)
	}
	if !filter.To.IsZero() {
		add("rl.created_at <= $%d", filter.To)
	}
	if filter.Model != "" {
		add("COALESCE(rl.routing_decision_json #>> '{model_route_v2,requested_model}', m.model_name, rl.model_id, '') = $%d", filter.Model)
	}
	if filter.Provider != "" {
		args = append(args, filter.Provider)
		n := len(args)
		from += fmt.Sprintf(" AND (rl.routing_decision_json #>> '{model_route_v2,planned_route,provider_name}' = $%d OR rl.routing_decision_json #>> '{model_route_v2,actual_route,provider_name}' = $%d)", n, n)
	}
	if filter.Result != "" {
		add("rl.request_status = $%d", filter.Result)
	}
	if filter.Fallback != nil {
		add("COALESCE(rl.routing_decision_json #>> '{model_route_v2,fallback_used}', 'false') = $%d", strconv.FormatBool(*filter.Fallback))
	}
	query := `
		SELECT
			COALESCE(rl.id, ''),
			COALESCE(rl.request_id, ''),
			COALESCE(rl.tenant_id, ''),
			COALESCE(rl.project_id, ''),
			COALESCE(rl.user_id, ''),
			COALESCE(rl.model_id, ''),
			COALESCE(m.model_name, rl.model_id, '') AS model_name,
			COALESCE(rl.provider_id, ''),
			COALESCE(rl.session_id, ''),
			COALESCE(rl.endpoint_type, ''),
			COALESCE(rl.request_status, ''),
			COALESCE(rl.upstream_status_code, 0),
			rl.latency_ms,
			rl.created_at,
			rl.routing_decision_json
	` + from + fmt.Sprintf(" ORDER BY rl.created_at DESC, rl.id DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list routing decisions: %w", err)
	}
	defer rows.Close()

	decisions := []*RoutingDecision{}
	for rows.Next() {
		var d RoutingDecision
		var routingJSON []byte
		err := rows.Scan(
			&d.ID,
			&d.RequestID,
			&d.TenantID,
			&d.ProjectID,
			&d.UserID,
			&d.ModelID,
			&d.ModelName,
			&d.ProviderID,
			&d.SessionID,
			&d.EndpointType,
			&d.RequestStatus,
			&d.StatusCode,
			&d.LatencyMS,
			&d.CreatedAt,
			&routingJSON,
		)
		if err != nil {
			return nil, 0, err
		}
		// Parse routing_decision_json JSONB field
		if len(routingJSON) > 0 {
			if err := json.Unmarshal(routingJSON, &d.RoutingDecisionJSON); err != nil || d.RoutingDecisionJSON == nil {
				d.RoutingDecisionJSON = nil
				d.DecisionParseStatus = "unparseable"
			} else {
				d.DecisionParseStatus = "parsed"
			}
		}
		decisions = append(decisions, &d)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed while reading routing decisions: %w", err)
	}

	// Get total count of routing decisions for this tenant
	countQuery := `SELECT COUNT(*) ` + from
	var total int
	if err := r.db.QueryRow(ctx, countQuery, args[:len(args)-2]...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count routing decisions: %w", err)
	}

	return decisions, total, nil
}

func (r *RequestLogRepository) GetRoutingDecision(ctx context.Context, tenantID, requestID string) (*RoutingDecision, error) {
	items, _, err := r.ListRoutingDecisionsFiltered(ctx, tenantID, RoutingDecisionFilter{RequestID: requestID}, 1, 0)
	if err != nil {
		return nil, err
	}
	if len(items) > 0 {
		return items[0], nil
	}
	return nil, nil
}
