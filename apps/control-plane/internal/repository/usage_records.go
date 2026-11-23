package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// UsageRecord 是一条访问/调用明细，对应 request_logs 中的一行，
// 并联表补齐用户名、Key 前缀、应用名、供应商名、模型名等展示字段。
//
// 计费口径来自 prepaid 扣费记录或统一 billing_usage_facts；不读取历史成本列。
type UsageRecord struct {
	Timing              RequestTiming `json:"timing"`
	ID                  string        `json:"id"`
	RequestID           string        `json:"request_id"`
	SessionID           string        `json:"session_id"`
	CreatedAt           time.Time     `json:"created_at"`
	UserName            string        `json:"user_name"`
	UserID              string        `json:"-"`
	KeyPrefix           string        `json:"key_prefix"`
	KeyName             string        `json:"key_name"`
	ClientID            string        `json:"-"`
	ProjectName         string        `json:"project_name"`
	ProjectID           string        `json:"-"`
	ProviderName        string        `json:"provider_name"`
	ProviderID          string        `json:"-"`
	ModelName           string        `json:"model_name"`
	ModelID             string        `json:"-"`
	SourceIP            string        `json:"source_ip"`
	RawStatus           string        `json:"raw_status"`
	ErrorMessage        string        `json:"error_message"`
	ErrorHint           string        `json:"error_hint"`
	UpstreamErrorCode   string        `json:"upstream_error_code"`
	RequestStatus       string        `json:"request_status"`
	UpstreamStatusCode  int           `json:"upstream_status_code"`
	InputTokens         int64         `json:"input_tokens"`
	OutputTokens        int64         `json:"output_tokens"`
	TotalTokens         int64         `json:"total_tokens"`
	BillingAmountMicros *int64        `json:"billing_amount_micros"`
	BillingCurrency     string        `json:"billing_currency"`
	BillingState        string        `json:"billing_state"`
	BillingMode         string        `json:"billing_mode"`
	LatencyMs           int           `json:"latency_ms"`
	// 路由行为与失败归因（来自 routing_decision_json + 上游状态码推导）：
	UpstreamTTFTMs   *int64          `json:"upstream_ttft_ms"`   // 首 token 延迟（速度优先选路口径）
	FallbackUsed     bool            `json:"fallback_used"`      // 是否发生自动切换（成功但走了备用线路）
	PlannedRouteName string          `json:"planned_route_name"` // 首选线路展示名
	ActualRouteName  string          `json:"actual_route_name"`  // 实际命中线路展示名
	FailureCategory  string          `json:"failure_category"`   // 失败原因类别（枚举，前端映射中文）
	Attempts         json.RawMessage `json:"attempts"`           // 逐次尝试记录（已脱敏）
}

// usageRouteAttempt 是 routing_decision_json.model_route_v2.attempts 的元素，
// 写入前已在网关侧脱敏，这里只读取失败归因字段。
type usageRouteAttempt struct {
	Result             string `json:"result"`
	StatusCodeCategory string `json:"status_code_category"`
	FailureCategory    string `json:"failure_category"`
}

// deriveUsageFailureCategory 推导失败原因类别：
// 安全拦截 → 路由决策中最后一次失败的类别 → 上游状态码映射 → unknown。
// 保证任何失败/阻断行都有可展示的类别，不回到「失败但不知道为啥」。
func deriveUsageFailureCategory(status string, upstreamCode int, attempts json.RawMessage) string {
	if status == "blocked" {
		return "security_rejected"
	}
	if status != "failed" {
		return ""
	}
	if len(attempts) > 0 && string(attempts) != "null" {
		var parsed []usageRouteAttempt
		if err := json.Unmarshal(attempts, &parsed); err == nil {
			for i := len(parsed) - 1; i >= 0; i-- {
				if parsed[i].FailureCategory != "" {
					return parsed[i].FailureCategory
				}
			}
		}
	}
	switch {
	case upstreamCode == 401 || upstreamCode == 403:
		return "auth_failed"
	case upstreamCode == 429:
		return "rate_limited"
	case upstreamCode == 408:
		return "timeout"
	case upstreamCode >= 500:
		return "upstream_5xx"
	}
	return "unknown"
}

// UsageRecordFilter 是明细查询的过滤条件。
// StartDate/EndDate 必填（时间范围）；其余维度均可选。
// BillingState 可按 settled/reserved/released/exception/not_billed 以及被预算断流拒绝的
// budget_exhausted/budget_unpriced/budget_unavailable 筛选。
type UsageRecordFilter struct {
	StartDate       time.Time
	EndDate         time.Time
	UserID          string
	ClientID        string
	ProjectID       string
	ModelID         string
	ProviderID      string
	SourceIP        string
	FailureCategory string
	ErrorKeyword    string
	HTTPStatus      int
	RequestStatus   string
	BillingState    string
	// FallbackOnly 为 true 时只返回发生过自动切换（备用线路救场）的请求。
	FallbackOnly bool
	Limit        int
	Offset       int
	CursorTime   time.Time // keyset 游标:上一页最后一行的 created_at(置零=用 offset)
	CursorID     string    // keyset 游标的 id 次级键
	SkipTotal    bool      // 退订无界 COUNT(游标分页时)
}

// UsageRecordsSummary 是按时间范围（及过滤条件）的明细统计。
// 金额与状态均基于账单预占和扣费记录；只有 settled 金额计入合计。
type UsageRecordsSummary struct {
	Requests              int   `json:"requests"`
	Users                 int   `json:"users"`
	Apps                  int   `json:"apps"`
	Keys                  int   `json:"keys"`
	InputTokens           int64 `json:"input_tokens"`
	OutputTokens          int64 `json:"output_tokens"`
	TotalTokens           int64 `json:"total_tokens"`
	BillingAmountMicros   int64 `json:"billing_amount_micros"`
	SettledRequests       int   `json:"settled_requests"`
	ReservedRequests      int   `json:"reserved_requests"`
	ReleasedRequests      int   `json:"released_requests"`
	UnpricedRequests      int   `json:"unpriced_requests"`
	BillingFailedRequests int   `json:"billing_failed_requests"`
	ExceptionRequests     int   `json:"exception_requests"`
	NotBilledRequests     int   `json:"not_billed_requests"`
	SuccessRequests       int   `json:"success_requests"`
	FailedRequests        int   `json:"failed_requests"`
}

// usageRecordFilterWhere 在 usageScopeWhere 给出的基础条件之上，追加明细维度过滤。
// where/args 由调用方先经 usageScopeWhere 初始化（已占用 $1/$2/$3 等），
// 这里从 len(args) 继续接续位置参数，确保多租户隔离条件始终在最前。
// A metering settlement has a reservation and a fact, but no prepaid charge.
// Require the settled metering fact explicitly: a prepaid/missing fact must
// still expose an incomplete audit trail as an exception.
const billingStateSQL = `
	CASE
		WHEN bc.status IN ('failed', 'unpriced')
			OR (br.status = 'settled' AND bc.id IS NULL AND NOT COALESCE(buf.billing_mode = 'metering' AND buf.status = 'settled', false))
			OR (br.id IS NOT NULL AND bc.id IS NOT NULL AND ((bc.status = 'settled' AND br.status <> 'settled') OR (bc.status = 'released' AND br.status <> 'released')))
			OR (bc.id IS NULL AND br.status = 'reserved' AND br.created_at <= NOW() - INTERVAL '15 minutes') THEN 'exception'
		WHEN bc.status = 'settled' THEN 'settled'
		WHEN bc.id IS NULL AND br.status = 'reserved' THEN 'reserved'
		WHEN br.status = 'released' OR bc.status = 'released' THEN 'released'
		WHEN bc.id IS NULL AND buf.status = 'settled' AND (br.id IS NULL OR (br.status = 'settled' AND buf.billing_mode = 'metering')) THEN 'settled'
		WHEN bc.id IS NULL AND br.id IS NULL AND buf.status = 'unpriced' THEN 'unpriced'
		WHEN bc.id IS NULL AND br.id IS NULL AND buf.status = 'failed' THEN 'failed'
		WHEN bc.id IS NULL AND br.id IS NULL AND buf.status = 'released' THEN 'released'
		ELSE 'not_billed'
	END
`

// usageBillingStateSQL 是调用明细专用的计费状态：被预算断流拒绝的请求没有账单行，结果只留在
// request_logs.billing_outcome，这里把它们显示成独立状态；其余请求沿用 billingStateSQL 的优先级不变。
const usageBillingStateSQL = `
	CASE
		WHEN rl.billing_outcome IN ('budget_exhausted', 'budget_unpriced', 'budget_unavailable') THEN rl.billing_outcome
		ELSE (` + billingStateSQL + `)
	END
`

const billingAmountSQL = `CASE WHEN bc.id IS NOT NULL THEN bc.amount_micros WHEN br.id IS NULL OR buf.billing_mode = 'metering' THEN buf.billable_amount_micros END`
const billingCurrencySQL = `CASE WHEN bc.id IS NOT NULL THEN bc.currency WHEN br.id IS NULL OR buf.billing_mode = 'metering' THEN buf.currency END`
const billingModeSQL = `CASE WHEN bc.id IS NOT NULL THEN 'prepaid' WHEN buf.billing_mode IS NOT NULL THEN buf.billing_mode WHEN br.id IS NOT NULL THEN 'prepaid' ELSE '' END`

const usageSourceIPSQL = "COALESCE(NULLIF(rl.proxy_source_ip, ''), NULLIF(rl.source_ip, ''), '')"
const UsageRequestStatusSQL = `CASE
 WHEN rl.request_status IN ('success', 'security_replied') THEN 'success'
 WHEN rl.request_status IN ('blocked', 'security_blocked', 'input_blocked', 'output_blocked') THEN 'blocked'
 ELSE 'failed' END`

// 中文解释和供应商错误码复用已有 JSONB，历史记录返回空串。
const UsageErrorHintSQL = "COALESCE(rl.output_audit_result #>> '{response_metadata,upstream_error_hint}', '')"
const UsageUpstreamErrorCodeSQL = "COALESCE(rl.output_audit_result #>> '{response_metadata,upstream_error_code}', '')"

const UsageErrorMessageSQL = "COALESCE(rl.output_audit_result #>> '{response_metadata,error_message}', '')"
const UsageFailureCategorySQL = `CASE
 WHEN (` + UsageRequestStatusSQL + `) = 'blocked' THEN 'security_rejected'
 WHEN (` + UsageRequestStatusSQL + `) = 'success' THEN ''
 WHEN rl.request_status IN ('provider_timeout', 'timeout') THEN 'timeout'
 WHEN rl.request_status = 'model_not_found' THEN 'model_not_found'
 WHEN rl.request_status = 'client_canceled' THEN 'client_canceled'
 WHEN rl.request_status = 'stream_aborted' THEN 'stream_aborted'
 WHEN rl.request_status IN ('quota_exceeded', 'rate_limited') THEN rl.request_status
 ELSE COALESCE((SELECT a->>'failure_category' FROM jsonb_array_elements(
 CASE WHEN jsonb_typeof(rl.routing_decision_json #> '{model_route_v2,attempts}') = 'array'
 THEN rl.routing_decision_json #> '{model_route_v2,attempts}' ELSE '[]'::jsonb END)
 WITH ORDINALITY AS attempts(a, n) WHERE COALESCE(a->>'failure_category', '') <> '' ORDER BY n DESC LIMIT 1),
 CASE WHEN rl.upstream_status_code IN (401,403) THEN 'auth_failed'
 WHEN rl.upstream_status_code = 429 THEN 'rate_limited'
 WHEN rl.upstream_status_code IN (408,504) THEN 'timeout'
 WHEN rl.upstream_status_code >= 500 THEN 'upstream_5xx' ELSE 'unknown' END) END`

func usageRecordFilterWhere(filter UsageRecordFilter, where string, args []interface{}) (string, []interface{}) {
	where += " AND COALESCE(rl.endpoint_type, '') <> 'proxy'"
	where += " AND COALESCE(rl.request_status, '') NOT IN ('received', 'in_progress')"
	where += " AND k.id IS NOT NULL"
	if filter.UserID != "" {
		args = append(args, filter.UserID)
		where += fmt.Sprintf(" AND rl.user_id = $%d", len(args))
	}
	if filter.ClientID != "" {
		args = append(args, filter.ClientID)
		where += fmt.Sprintf(" AND rl.client_id = $%d", len(args))
	}
	if filter.ProjectID != "" {
		args = append(args, filter.ProjectID)
		where += fmt.Sprintf(" AND COALESCE(k.project_id, rl.project_id) = $%d", len(args))
	}
	if filter.ModelID != "" {
		args = append(args, filter.ModelID)
		where += fmt.Sprintf(" AND rl.model_id = $%d", len(args))
	}
	if filter.ProviderID != "" {
		args = append(args, filter.ProviderID)
		where += fmt.Sprintf(" AND rl.provider_id = $%d", len(args))
	}
	if filter.RequestStatus != "" {
		args = append(args, filter.RequestStatus)
		where += fmt.Sprintf(" AND (%s) = $%d", UsageRequestStatusSQL, len(args))
	}
	if filter.SourceIP != "" {
		args = append(args, filter.SourceIP)
		where += fmt.Sprintf(" AND (%s) = $%d", usageSourceIPSQL, len(args))
	}
	if filter.FailureCategory != "" {
		args = append(args, filter.FailureCategory)
		where += fmt.Sprintf(" AND (%s) = $%d", UsageFailureCategorySQL, len(args))
	}
	if filter.HTTPStatus > 0 {
		args = append(args, filter.HTTPStatus)
		where += fmt.Sprintf(" AND rl.upstream_status_code = $%d", len(args))
	}
	if filter.ErrorKeyword != "" {
		args = append(args, filter.ErrorKeyword)
		where += fmt.Sprintf(" AND (%s) <> 'success' AND POSITION(LOWER($%d) IN LOWER(COALESCE(rl.request_status, '') || ' ' || (%s))) > 0", UsageRequestStatusSQL, len(args), UsageErrorMessageSQL)
	}
	if filter.BillingState != "" {
		args = append(args, filter.BillingState)
		where += fmt.Sprintf(" AND (%s) = $%d", usageBillingStateSQL, len(args))
	}
	if filter.FallbackOnly {
		where += " AND COALESCE(rl.routing_decision_json #>> '{model_route_v2,fallback_used}', 'false') = 'true'"
	}
	return where, args
}

// usageRecordJoins 是明细/统计共用的联表片段：
// internal_keys 用于限定“调用明细”只展示网关发放 Key 的模型调用，并还原 Key 前缀与真实归属应用；其余表用于补齐展示名。
const usageRecordJoins = `
	FROM request_logs rl
	LEFT JOIN internal_keys k ON k.id = rl.client_id AND k.tenant_id = rl.tenant_id
	LEFT JOIN users u         ON u.id = COALESCE(k.user_id, rl.user_id) AND u.tenant_id = rl.tenant_id
	LEFT JOIN projects p      ON p.id = COALESCE(k.project_id, rl.project_id) AND p.tenant_id = rl.tenant_id
	LEFT JOIN providers pr    ON pr.id = rl.provider_id AND pr.tenant_id = rl.tenant_id
	LEFT JOIN models m        ON m.id = rl.model_id
	LEFT JOIN billing_reservations br ON br.tenant_id = rl.tenant_id AND br.request_id = rl.request_id
	LEFT JOIN billing_charge_records bc ON bc.tenant_id = rl.tenant_id AND bc.request_id = rl.request_id
	LEFT JOIN billing_usage_facts buf ON buf.tenant_id = rl.tenant_id AND buf.request_id = rl.request_id`

// ListUsageRecords 返回符合 scope + filter 的明细行（按时间倒序分页），以及匹配总数。
// 计费金额和状态优先取 prepaid 扣费记录，否则取统一不可变事实。
func (r *UsageDailyRepository) ListUsageRecords(ctx context.Context, scope UsageScope, filter UsageRecordFilter) ([]UsageRecord, int, error) {
	where, args := usageScopeWhere(scope, filter.StartDate, filter.EndDate)
	where, args = usageRecordFilterWhere(filter, where, args)

	// 退订无界 COUNT(游标分页时):千人级每页全表 COUNT 会卡;total=-1 表示未计。
	total := -1
	if !filter.SkipTotal {
		countQuery := fmt.Sprintf(`
		SELECT COUNT(*)::int
		%s
		WHERE %s
	`, usageRecordJoins, where)
		if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("failed to count usage records: %w", err)
		}
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}

	listArgs := make([]interface{}, len(args))
	copy(listArgs, args)

	// keyset 游标优先(千人级:任意深度恒定快,无 OFFSET 跳过开销);否则沿用 offset。
	// ORDER BY 带 rl.id 次级键,保证游标边界稳定(created_at 并列不丢行/不重行)。
	var pagination string
	if !filter.CursorTime.IsZero() {
		listArgs = append(listArgs, filter.CursorTime, filter.CursorID, limit)
		pagination = fmt.Sprintf(`AND (rl.created_at, rl.id) < ($%d, $%d)
		ORDER BY rl.created_at DESC, rl.id DESC
		LIMIT $%d`, len(args)+1, len(args)+2, len(args)+3)
	} else {
		offset := filter.Offset
		if offset < 0 {
			offset = 0
		}
		listArgs = append(listArgs, limit, offset)
		pagination = fmt.Sprintf(`ORDER BY rl.created_at DESC, rl.id DESC
		LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2)
	}

	query := fmt.Sprintf(`
		SELECT rl.id,
		       rl.request_id,
		       COALESCE(rl.session_id, '') AS session_id,
		       rl.created_at,
		       COALESCE(u.username, '') AS user_name,
		       COALESCE(rl.user_id, '') AS user_id,
		       COALESCE(k.key_prefix, '') AS key_prefix,
		       COALESCE(k.name, '') AS key_name,
		       COALESCE(rl.client_id, '') AS client_id,
		       COALESCE(p.name, '') AS project_name,
		       COALESCE(k.project_id, rl.project_id, '') AS project_id,
		       COALESCE(pr.name, '') AS provider_name,
		       COALESCE(rl.provider_id, '') AS provider_id,
		       COALESCE(NULLIF(m.model_label, ''), m.model_name, '') AS model_name,
		       COALESCE(rl.model_id, '') AS model_id,
		       (`+UsageRequestStatusSQL+`),
		       COALESCE(rl.upstream_status_code, 0) AS upstream_status_code,
		       COALESCE(rl.input_tokens, 0)::bigint AS input_tokens,
		       COALESCE(rl.output_tokens, 0)::bigint AS output_tokens,
		       (COALESCE(rl.input_tokens, 0) + COALESCE(rl.output_tokens, 0))::bigint AS total_tokens,
		       (%s)::bigint AS billing_amount_micros,
		       COALESCE((%s), '') AS billing_currency,
		       (%s) AS billing_state,
		       (%s) AS billing_mode,
		       COALESCE(rl.latency_ms, 0) AS latency_ms,
		       rl.upstream_ttft_ms AS upstream_ttft_ms,
		       COALESCE(rl.routing_decision_json #>> '{model_route_v2,fallback_used}', 'false') = 'true' AS fallback_used,
		       COALESCE(rl.routing_decision_json #>> '{model_route_v2,planned_route,provider_name}', '') AS planned_route_name,
		       COALESCE(rl.routing_decision_json #>> '{model_route_v2,actual_route,provider_name}', '') AS actual_route_name,
		       COALESCE(rl.routing_decision_json -> 'model_route_v2' -> 'attempts', 'null'::jsonb)::text AS attempts_json,
               (`+usageSourceIPSQL+`), COALESCE(rl.request_status, ''), (`+UsageErrorMessageSQL+`), (`+UsageFailureCategorySQL+`), (`+UsageErrorHintSQL+`), (`+UsageUpstreamErrorCodeSQL+`), COALESCE(rl.output_audit_result #> '{response_metadata,timing}', '{}'::jsonb)::text
		%s
		WHERE %s
		%s
	`, billingAmountSQL, billingCurrencySQL, usageBillingStateSQL, billingModeSQL, usageRecordJoins, where, pagination)

	rows, err := r.db.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list usage records: %w", err)
	}
	defer rows.Close()

	records := []UsageRecord{}
	for rows.Next() {
		var rec UsageRecord
		var attemptsText string
		var timingText string
		if err := rows.Scan(
			&rec.ID,
			&rec.RequestID,
			&rec.SessionID,
			&rec.CreatedAt,
			&rec.UserName,
			&rec.UserID,
			&rec.KeyPrefix,
			&rec.KeyName,
			&rec.ClientID,
			&rec.ProjectName,
			&rec.ProjectID,
			&rec.ProviderName,
			&rec.ProviderID,
			&rec.ModelName,
			&rec.ModelID,
			&rec.RequestStatus,
			&rec.UpstreamStatusCode,
			&rec.InputTokens,
			&rec.OutputTokens,
			&rec.TotalTokens,
			&rec.BillingAmountMicros,
			&rec.BillingCurrency,
			&rec.BillingState,
			&rec.BillingMode,
			&rec.LatencyMs,
			&rec.UpstreamTTFTMs,
			&rec.FallbackUsed,
			&rec.PlannedRouteName,
			&rec.ActualRouteName,
			&attemptsText, &rec.SourceIP, &rec.RawStatus, &rec.ErrorMessage, &rec.FailureCategory, &rec.ErrorHint, &rec.UpstreamErrorCode, &timingText,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan usage record: %w", err)
		}
		rec.Attempts = json.RawMessage(attemptsText)
		rec.Timing = parseRequestTiming([]byte(timingText), rec.LatencyMs, rec.UpstreamTTFTMs, rec.OutputTokens)

		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to iterate usage records: %w", err)
	}

	return records, total, nil
}

// SummarizeUsageRecords 返回符合 scope + filter 的明细统计。
// 仅 settled 扣费金额进入合计；其他状态单独计数。
func (r *UsageDailyRepository) SummarizeUsageRecords(ctx context.Context, scope UsageScope, filter UsageRecordFilter) (*UsageRecordsSummary, error) {
	where, args := usageScopeWhere(scope, filter.StartDate, filter.EndDate)
	where, args = usageRecordFilterWhere(filter, where, args)

	query := fmt.Sprintf(`
		SELECT COUNT(*)::int AS requests,
		       COUNT(DISTINCT rl.user_id)::int AS users,
		       COUNT(DISTINCT COALESCE(k.project_id, rl.project_id))::int AS apps,
		       COUNT(DISTINCT rl.client_id)::int AS keys,
		       COALESCE(SUM(COALESCE(rl.input_tokens, 0)), 0)::bigint AS input_tokens,
		       COALESCE(SUM(COALESCE(rl.output_tokens, 0)), 0)::bigint AS output_tokens,
		       COALESCE(SUM(COALESCE(rl.input_tokens, 0) + COALESCE(rl.output_tokens, 0)), 0)::bigint AS total_tokens,
		       (COUNT(*) FILTER (WHERE (`+UsageRequestStatusSQL+`) = 'success'))::int AS success_requests,
		       (COUNT(*) FILTER (WHERE (`+UsageRequestStatusSQL+`) = 'failed'))::int AS failed_requests,
		       COALESCE(SUM((%s)) FILTER (WHERE (%s) = 'settled'), 0)::bigint AS billing_amount_micros,
		       (COUNT(*) FILTER (WHERE (%s) = 'settled'))::int AS settled_requests,
		       (COUNT(*) FILTER (WHERE (%s) = 'reserved'))::int AS reserved_requests,
		       (COUNT(*) FILTER (WHERE (%s) = 'released'))::int AS released_requests,
		       (COUNT(*) FILTER (WHERE (%s) = 'unpriced'))::int AS unpriced_requests,
		       (COUNT(*) FILTER (WHERE (%s) = 'failed'))::int AS billing_failed_requests,
		       (COUNT(*) FILTER (WHERE (%s) = 'exception'))::int AS exception_requests,
		       (COUNT(*) FILTER (WHERE (%s) = 'not_billed'))::int AS not_billed_requests
		%s
		WHERE %s
	`, billingAmountSQL, usageBillingStateSQL, usageBillingStateSQL, usageBillingStateSQL, usageBillingStateSQL, usageBillingStateSQL, usageBillingStateSQL, usageBillingStateSQL, usageBillingStateSQL, usageRecordJoins, where)

	var summary UsageRecordsSummary
	if err := r.db.QueryRow(ctx, query, args...).Scan(
		&summary.Requests,
		&summary.Users,
		&summary.Apps,
		&summary.Keys,
		&summary.InputTokens,
		&summary.OutputTokens,
		&summary.TotalTokens,
		&summary.SuccessRequests,
		&summary.FailedRequests,
		&summary.BillingAmountMicros,
		&summary.SettledRequests,
		&summary.ReservedRequests,
		&summary.ReleasedRequests,
		&summary.UnpricedRequests,
		&summary.BillingFailedRequests,
		&summary.ExceptionRequests,
		&summary.NotBilledRequests,
	); err != nil {
		return nil, fmt.Errorf("failed to summarize usage records: %w", err)
	}

	return &summary, nil
}
