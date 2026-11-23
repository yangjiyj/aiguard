package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StatsRepository handles statistics queries
type StatsRepository struct {
	db *pgxpool.Pool
}

// NewStatsRepository creates a new stats repository
func NewStatsRepository(db *pgxpool.Pool) *StatsRepository {
	return &StatsRepository{db: db}
}

func allStatsScopeBounds() (time.Time, time.Time) {
	return time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)
}

// UserStats represents user statistics
type UserStats struct {
	UserID       string  `json:"user_id"`
	Username     string  `json:"username"`
	TotalTokens  int64   `json:"total_tokens"`
	TotalCost    float64 `json:"total_cost"`
	RequestCount int64   `json:"request_count"`
}

// GetUserTokenRanking returns top users by token consumption
func (r *StatsRepository) GetUserTokenRanking(ctx context.Context, tenantID string, limit int) ([]UserStats, error) {
	return r.GetUserTokenRankingScoped(ctx, UsageScope{TenantID: tenantID, FullTenant: true}, limit)
}

// GetUserTokenRankingScoped returns top users by token consumption within a usage scope.
func (r *StatsRepository) GetUserTokenRankingScoped(ctx context.Context, scope UsageScope, limit int) ([]UserStats, error) {
	start, end := allStatsScopeBounds()
	return r.GetUserTokenRankingScopedBetween(ctx, scope, limit, start, end)
}

// GetUserTokenRankingScopedBetween returns top users by token consumption within a usage scope and time window.
func (r *StatsRepository) GetUserTokenRankingScopedBetween(ctx context.Context, scope UsageScope, limit int, start, end time.Time) ([]UserStats, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := usageScopeWhereRollup(scope, start, end)
	args = append(args, limit)
	limitParam := len(args)

	// 读 rollup 读模型，避免 request_logs 全表扫(数字与原表逐项一致,已实测对账)。
	query := fmt.Sprintf(`
		SELECT rl.user_id, u.username,
		       COALESCE(SUM(rl.input_tokens + rl.output_tokens), 0) as total_tokens,
		       COALESCE(SUM(rl.total_cost), 0) as total_cost,
		       COALESCE(SUM(rl.request_count), 0) as request_count
		FROM usage_rollup_hourly rl
		LEFT JOIN users u ON rl.user_id = u.id
		WHERE %s AND rl.user_id != ''
		GROUP BY rl.user_id, u.username
		ORDER BY total_tokens DESC
		LIMIT $%d
	`, where, limitParam)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get user token ranking: %w", err)
	}
	defer rows.Close()

	stats := []UserStats{}
	for rows.Next() {
		var s UserStats
		var totalCost sql.NullFloat64
		err := rows.Scan(&s.UserID, &s.Username, &s.TotalTokens, &totalCost, &s.RequestCount)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user stats: %w", err)
		}
		if totalCost.Valid {
			s.TotalCost = totalCost.Float64
		}
		stats = append(stats, s)
	}

	return stats, nil
}

// GetUserRequestRanking returns top users by request count
func (r *StatsRepository) GetUserRequestRanking(ctx context.Context, tenantID string, limit int) ([]UserStats, error) {
	return r.GetUserRequestRankingScoped(ctx, UsageScope{TenantID: tenantID, FullTenant: true}, limit)
}

// GetUserRequestRankingScoped returns top users by request count within a usage scope.
func (r *StatsRepository) GetUserRequestRankingScoped(ctx context.Context, scope UsageScope, limit int) ([]UserStats, error) {
	start, end := allStatsScopeBounds()
	return r.GetUserRequestRankingScopedBetween(ctx, scope, limit, start, end)
}

// GetUserRequestRankingScopedBetween returns top users by request count within a usage scope and time window.
func (r *StatsRepository) GetUserRequestRankingScopedBetween(ctx context.Context, scope UsageScope, limit int, start, end time.Time) ([]UserStats, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := usageScopeWhereRollup(scope, start, end)
	args = append(args, limit)
	limitParam := len(args)

	// 读 rollup 读模型，避免 request_logs 全表扫(数字与原表逐项一致,已实测对账)。
	query := fmt.Sprintf(`
		SELECT rl.user_id, u.username,
		       COALESCE(SUM(rl.input_tokens + rl.output_tokens), 0) as total_tokens,
		       COALESCE(SUM(rl.total_cost), 0) as total_cost,
		       COALESCE(SUM(rl.request_count), 0) as request_count
		FROM usage_rollup_hourly rl
		LEFT JOIN users u ON rl.user_id = u.id
		WHERE %s AND rl.user_id != ''
		GROUP BY rl.user_id, u.username
		ORDER BY request_count DESC
		LIMIT $%d
	`, where, limitParam)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get user request ranking: %w", err)
	}
	defer rows.Close()

	stats := []UserStats{}
	for rows.Next() {
		var s UserStats
		var totalCost sql.NullFloat64
		err := rows.Scan(&s.UserID, &s.Username, &s.TotalTokens, &totalCost, &s.RequestCount)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user stats: %w", err)
		}
		if totalCost.Valid {
			s.TotalCost = totalCost.Float64
		}
		stats = append(stats, s)
	}

	return stats, nil
}

// AppStats represents application statistics
type AppStats struct {
	ProjectID    string  `json:"project_id"`
	ProjectName  string  `json:"project_name"`
	RequestCount int64   `json:"request_count"`
	TotalTokens  int64   `json:"total_tokens"`
	TotalCost    float64 `json:"total_cost"`
	UserCount    int64   `json:"user_count"`
	SuccessRate  float64 `json:"success_rate"`
}

// GetAppStats returns top applications by request count
func (r *StatsRepository) GetAppStats(ctx context.Context, tenantID string, limit int) ([]AppStats, error) {
	return r.GetAppStatsScoped(ctx, UsageScope{TenantID: tenantID, FullTenant: true}, limit)
}

// GetAppStatsScoped returns top applications by request count within a usage scope.
func (r *StatsRepository) GetAppStatsScoped(ctx context.Context, scope UsageScope, limit int) ([]AppStats, error) {
	if limit <= 0 {
		limit = 10
	}
	where, args := statsScopeWhereRollup(scope)
	args = append(args, limit)
	limitParam := len(args)

	// 统计页只展示仍存在且未删除的应用。历史 rollup 继续保留审计事实，
	// 但不能把用户已删除的应用重新“复活”到当前应用排行榜。
	query := fmt.Sprintf(`
		SELECT rl.project_id, p.name,
		       COALESCE(SUM(rl.request_count), 0) as request_count,
		       COALESCE(SUM(rl.input_tokens + rl.output_tokens), 0) as total_tokens,
		       COALESCE(SUM(rl.total_cost), 0) as total_cost,
		       COUNT(DISTINCT rl.user_id) FILTER (WHERE rl.user_id != '') as user_count,
		       COALESCE(
		           100.0 * SUM(rl.ai_success_count) / NULLIF(SUM(rl.ai_request_count), 0),
		           0
		       ) as success_rate
		FROM usage_rollup_hourly rl
		JOIN projects p ON rl.project_id = p.id AND p.tenant_id = rl.tenant_id AND p.status <> 'deleted'
		WHERE %s AND rl.project_id != ''
		GROUP BY rl.project_id, p.name
		ORDER BY request_count DESC
		LIMIT $%d
	`, where, limitParam)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get app stats: %w", err)
	}
	defer rows.Close()

	stats := []AppStats{}
	for rows.Next() {
		var s AppStats
		var totalCost sql.NullFloat64
		var totalTokens sql.NullInt64
		err := rows.Scan(&s.ProjectID, &s.ProjectName, &s.RequestCount, &totalTokens, &totalCost, &s.UserCount, &s.SuccessRate)
		if err != nil {
			return nil, fmt.Errorf("failed to scan app stats: %w", err)
		}
		if totalCost.Valid {
			s.TotalCost = totalCost.Float64
		}
		if totalTokens.Valid {
			s.TotalTokens = totalTokens.Int64
		}
		stats = append(stats, s)
	}

	return stats, nil
}

// ModelStats represents model statistics
type ModelStats struct {
	ModelID      string  `json:"model_id"`
	ModelName    string  `json:"model_name"`
	RequestCount int64   `json:"request_count"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	TotalCost    float64 `json:"total_cost"`
	CostPercent  float64 `json:"cost_percent"`
}

// GetModelStats returns top models by request count with cost percentage
func (r *StatsRepository) GetModelStats(ctx context.Context, tenantID string, limit int) ([]ModelStats, error) {
	return r.GetModelStatsScoped(ctx, UsageScope{TenantID: tenantID, FullTenant: true}, limit)
}

// GetModelStatsScoped returns top models by request count within a usage scope.
func (r *StatsRepository) GetModelStatsScoped(ctx context.Context, scope UsageScope, limit int) ([]ModelStats, error) {
	start, end := allStatsScopeBounds()
	return r.GetModelStatsScopedBetween(ctx, scope, limit, start, end)
}

// GetModelStatsScopedBetween returns top models by request count within a usage scope and time window.
func (r *StatsRepository) GetModelStatsScopedBetween(ctx context.Context, scope UsageScope, limit int, start, end time.Time) ([]ModelStats, error) {
	if limit <= 0 {
		limit = 10
	}

	where, args := usageScopeWhereRollup(scope, start, end)
	// 读 rollup 读模型，避免 request_logs 全表扫(数字与原表逐项一致,已实测对账)。
	totalCostQuery := fmt.Sprintf(`
		SELECT COALESCE(SUM(rl.total_cost), 0) as total_cost
		FROM usage_rollup_hourly rl
		WHERE %s
	`, where)
	var tenantTotalCost float64
	err := r.db.QueryRow(ctx, totalCostQuery, args...).Scan(&tenantTotalCost)
	if err != nil {
		return nil, fmt.Errorf("failed to get total cost: %w", err)
	}

	args = append(args, limit)
	limitParam := len(args)
	query := fmt.Sprintf(`
		SELECT rl.model_id,
		       COALESCE(NULLIF(current_model.model_name, ''), NULLIF(model_history.model_name, ''), '未识别模型'),
		       COALESCE(SUM(rl.request_count), 0) as request_count,
		       COALESCE(SUM(rl.input_tokens), 0) as input_tokens,
		       COALESCE(SUM(rl.output_tokens), 0) as output_tokens,
		       COALESCE(SUM(rl.total_cost), 0) as total_cost
		FROM usage_rollup_hourly rl
		LEFT JOIN (
			SELECT m.id, p.tenant_id, m.model_name
			FROM models m
			JOIN providers p ON p.id = m.provider_id
		) current_model
		  ON current_model.id = rl.model_id
		 AND current_model.tenant_id = rl.tenant_id
		LEFT JOIN model_name_history model_history
		  ON model_history.tenant_id = rl.tenant_id
		 AND model_history.model_id = rl.model_id
		WHERE %s AND BTRIM(rl.model_id) != ''
		GROUP BY rl.model_id, current_model.model_name, model_history.model_name
		ORDER BY request_count DESC
		LIMIT $%d
	`, where, limitParam)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get model stats: %w", err)
	}
	defer rows.Close()

	stats := []ModelStats{}
	for rows.Next() {
		var s ModelStats
		var totalCost sql.NullFloat64
		var inputTokens, outputTokens sql.NullInt64
		err := rows.Scan(&s.ModelID, &s.ModelName, &s.RequestCount, &inputTokens, &outputTokens, &totalCost)
		if err != nil {
			return nil, fmt.Errorf("failed to scan model stats: %w", err)
		}
		if totalCost.Valid {
			s.TotalCost = totalCost.Float64
		}
		if inputTokens.Valid {
			s.InputTokens = inputTokens.Int64
		}
		if outputTokens.Valid {
			s.OutputTokens = outputTokens.Int64
		}
		// Calculate cost percentage
		if tenantTotalCost > 0 && s.TotalCost > 0 {
			s.CostPercent = (s.TotalCost / tenantTotalCost) * 100
		}
		stats = append(stats, s)
	}

	return stats, nil
}

// AgentStats represents agent type distribution statistics
type AgentStats struct {
	DetectionSources       []string `json:"detection_sources"`
	AgentType              string   `json:"agent_type"`
	SessionCount           int64    `json:"session_count"`
	RequestCount           int64    `json:"request_count"`
	ContentRequestCount    int64    `json:"content_request_count"`
	ToolBackedRequestCount int64    `json:"tool_backed_request_count"`
	Percent                float64  `json:"percent"`
}

// inferredAgentRequestsCTE 不含平台自建的请求日志（NonBusinessEndpointTypes，2.9.22）。
var inferredAgentRequestsCTE = `
	WITH scoped_requests AS (
		SELECT rl.id,
		       rl.request_id,
		       rl.user_id,
		       rl.session_id,
		       rl.agent_type,
 rl.agent_detection_source,
		       rl.input_tokens,
		       rl.output_tokens,
		       rl.total_cost,
		       rl.proxy_mode,
		       rl.proxy_retention_level,
		       rl.proxy_content_retained,
		       rl.created_at
		FROM request_logs rl
		WHERE rl.tenant_id = $1
		  AND ` + ExcludeNonBusinessEndpointsSQL("rl") + `
	),
	blank_requests AS (
		SELECT id, request_id
		FROM scoped_requests
		WHERE COALESCE(agent_type, '') = ''
	),
	content_agent AS (
		SELECT cl.request_id,
		       (array_agg(cl.session_id ORDER BY cl.created_at DESC) FILTER (WHERE COALESCE(cl.session_id, '') != ''))[1] as session_id,
		       TRUE as has_content_log,
		       bool_or(cl.content ILIKE '%opencode%' OR cl.content ILIKE '%open code%') as has_opencode,
		       bool_or(cl.content ILIKE '%Claude Code%' OR cl.content ILIKE '%cc_version=%') as has_claude_code
		FROM content_logs cl
		JOIN blank_requests br ON br.id = cl.request_id
		GROUP BY cl.request_id
	),
	tool_agent AS (
		SELECT tl.request_id, TRUE as has_tool_call
		FROM tool_call_logs tl
		JOIN scoped_requests sr ON sr.request_id = tl.request_id
		GROUP BY tl.request_id
	),
	agent_requests AS (
		SELECT
			sr.request_id,
 COALESCE(NULLIF(sr.agent_detection_source, ''), 'unrecorded') AS detection_source,
			COALESCE(NULLIF(sr.user_id, ''), '') as user_id,
			COALESCE(NULLIF(sr.session_id, ''), NULLIF(ca.session_id, ''), sr.request_id) as session_id,
			COALESCE(
				NULLIF(sr.agent_type, ''),
				CASE
					WHEN COALESCE(ca.has_opencode, FALSE) THEN 'opencode'
					WHEN COALESCE(ca.has_claude_code, FALSE) THEN 'claude-code'
					WHEN COALESCE(ta.has_tool_call, FALSE) THEN 'agent-tool-call'
					ELSE ''
				END
			) as agent_type,
			COALESCE(sr.input_tokens, 0) as input_tokens,
			COALESCE(sr.output_tokens, 0) as output_tokens,
			COALESCE(sr.total_cost, 0) as total_cost,
			(
				COALESCE(ca.has_content_log, FALSE) OR
				COALESCE(sr.proxy_content_retained, FALSE) OR
				LOWER(COALESCE(sr.proxy_retention_level, '')) = 'content'
			) as content_request,
			COALESCE(ta.has_tool_call, FALSE) as tool_backed_request,
			CASE
				WHEN COALESCE(sr.proxy_mode, '') <> 'forward' THEN TRUE
				WHEN COALESCE(sr.proxy_content_retained, FALSE) THEN TRUE
				WHEN LOWER(COALESCE(sr.proxy_retention_level, '')) = 'content' THEN TRUE
				ELSE COALESCE(ta.has_tool_call, FALSE)
			END as meaningful_agent_request,
			sr.created_at
		FROM scoped_requests sr
		LEFT JOIN content_agent ca ON ca.request_id = sr.id
		LEFT JOIN tool_agent ta ON ta.request_id = sr.request_id
	)
`

func inferredAgentRequestsScopedCTE(scope UsageScope, startDate, endDate time.Time) (string, []interface{}) {
	where, args := usageScopeWhere(scope, startDate, endDate)
	return fmt.Sprintf(`
	WITH scoped_requests AS (
		SELECT rl.id,
		       rl.request_id,
		       rl.user_id,
		       rl.session_id,
		       rl.agent_type,
 rl.agent_detection_source,
		       rl.input_tokens,
		       rl.output_tokens,
		       rl.total_cost,
		       rl.proxy_mode,
		       rl.proxy_retention_level,
		       rl.proxy_content_retained,
		       rl.created_at
		FROM request_logs rl
		WHERE %s
	),
	blank_requests AS (
		SELECT id, request_id
		FROM scoped_requests
		WHERE COALESCE(agent_type, '') = ''
	),
	content_agent AS (
		SELECT cl.request_id,
		       (array_agg(cl.session_id ORDER BY cl.created_at DESC) FILTER (WHERE COALESCE(cl.session_id, '') != ''))[1] as session_id,
		       TRUE as has_content_log,
		       bool_or(cl.content ILIKE '%%opencode%%' OR cl.content ILIKE '%%open code%%') as has_opencode,
		       bool_or(cl.content ILIKE '%%Claude Code%%' OR cl.content ILIKE '%%cc_version=%%') as has_claude_code
		FROM content_logs cl
		JOIN blank_requests br ON br.id = cl.request_id
		GROUP BY cl.request_id
	),
	tool_agent AS (
		SELECT tl.request_id, TRUE as has_tool_call
		FROM tool_call_logs tl
		JOIN scoped_requests sr ON sr.request_id = tl.request_id
		GROUP BY tl.request_id
	),
	agent_requests AS (
		SELECT
			sr.request_id,
 COALESCE(NULLIF(sr.agent_detection_source, ''), 'unrecorded') AS detection_source,
			COALESCE(NULLIF(sr.user_id, ''), '') as user_id,
			COALESCE(NULLIF(sr.session_id, ''), NULLIF(ca.session_id, ''), sr.request_id) as session_id,
			COALESCE(
				NULLIF(sr.agent_type, ''),
				CASE
					WHEN COALESCE(ca.has_opencode, FALSE) THEN 'opencode'
					WHEN COALESCE(ca.has_claude_code, FALSE) THEN 'claude-code'
					WHEN COALESCE(ta.has_tool_call, FALSE) THEN 'agent-tool-call'
					ELSE ''
				END
			) as agent_type,
			COALESCE(sr.input_tokens, 0) as input_tokens,
			COALESCE(sr.output_tokens, 0) as output_tokens,
			COALESCE(sr.total_cost, 0) as total_cost,
			(
				COALESCE(ca.has_content_log, FALSE) OR
				COALESCE(sr.proxy_content_retained, FALSE) OR
				LOWER(COALESCE(sr.proxy_retention_level, '')) = 'content'
			) as content_request,
			COALESCE(ta.has_tool_call, FALSE) as tool_backed_request,
			CASE
				WHEN COALESCE(sr.proxy_mode, '') <> 'forward' THEN TRUE
				WHEN COALESCE(sr.proxy_content_retained, FALSE) THEN TRUE
				WHEN LOWER(COALESCE(sr.proxy_retention_level, '')) = 'content' THEN TRUE
				ELSE COALESCE(ta.has_tool_call, FALSE)
			END as meaningful_agent_request,
			sr.created_at
		FROM scoped_requests sr
		LEFT JOIN content_agent ca ON ca.request_id = sr.id
		LEFT JOIN tool_agent ta ON ta.request_id = sr.request_id
	)
`, where), args
}

// GetAgentStats returns agent type distribution statistics
func (r *StatsRepository) GetAgentStats(ctx context.Context, tenantID string) ([]AgentStats, error) {
	return r.GetAgentStatsScoped(ctx, UsageScope{TenantID: tenantID, FullTenant: true})
}

// GetAgentStatsScoped returns all-time agent type distribution statistics within a usage scope.
func (r *StatsRepository) GetAgentStatsScoped(ctx context.Context, scope UsageScope) ([]AgentStats, error) {
	start, end := allStatsScopeBounds()
	return r.GetAgentStatsScopedBetween(ctx, scope, start, end)
}

// GetAgentStatsScopedBetween returns agent type distribution statistics within a usage scope and time window.
func (r *StatsRepository) GetAgentStatsScopedBetween(ctx context.Context, scope UsageScope, start, end time.Time) ([]AgentStats, error) {
	cte, args := inferredAgentRequestsScopedCTE(scope, start, end)
	query := cte + `,
		grouped AS (
			SELECT agent_type,
 array_agg(DISTINCT detection_source) AS detection_sources,
			       COUNT(DISTINCT session_id) as session_count,
			       COUNT(*) as request_count,
			       (COUNT(*) FILTER (WHERE content_request))::int8 as content_request_count,
			       (COUNT(*) FILTER (WHERE tool_backed_request))::int8 as tool_backed_request_count
			FROM agent_requests
			WHERE agent_type != '' AND meaningful_agent_request
			GROUP BY agent_type
		)
		SELECT agent_type,
		       session_count,
		       request_count,
		       content_request_count,
		       tool_backed_request_count,
		       CASE WHEN SUM(request_count) OVER () > 0
		            THEN request_count::float8 / SUM(request_count) OVER () * 100
		            ELSE 0
		       END as percent, detection_sources
		FROM grouped
		ORDER BY request_count DESC
	`

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent stats: %w", err)
	}
	defer rows.Close()

	stats := []AgentStats{}
	for rows.Next() {
		var s AgentStats
		err := rows.Scan(&s.AgentType, &s.SessionCount, &s.RequestCount, &s.ContentRequestCount, &s.ToolBackedRequestCount, &s.Percent, &s.DetectionSources)
		if err != nil {
			return nil, fmt.Errorf("failed to scan agent stats: %w", err)
		}
		stats = append(stats, s)
	}

	return stats, nil
}

// SystemOverview represents system overview statistics
type SystemOverview struct {
	TodayRequests       int64   `json:"today_requests"`
	TodayRequestsChange float64 `json:"today_requests_change"`
	TodayTokens         int64   `json:"today_tokens"`
	TodayTokensChange   float64 `json:"today_tokens_change"`
	TodayCost           float64 `json:"today_cost"`
	TodayCostChange     float64 `json:"today_cost_change"`
	YesterdayRequests   int64   `json:"yesterday_requests"`
	YesterdayTokens     int64   `json:"yesterday_tokens"`
	YesterdayCost       float64 `json:"yesterday_cost"`
	TotalRequests       int64   `json:"total_requests"`
	TotalTokens         int64   `json:"total_tokens"`
	TotalCost           float64 `json:"total_cost"`
	ActiveProjects      int64   `json:"active_projects"`
	SecurityBlocks      int64   `json:"security_blocks"`
	SecurityEvents      int64   `json:"security_events"`
}

// GetSystemOverview returns system overview statistics with day-over-day comparison
func (r *StatsRepository) GetSystemOverview(ctx context.Context, tenantID string) (*SystemOverview, error) {
	return r.GetSystemOverviewScoped(ctx, UsageScope{TenantID: tenantID, FullTenant: true})
}

// GetSystemOverviewScoped returns system overview statistics within a usage scope.
func (r *StatsRepository) GetSystemOverviewScoped(ctx context.Context, scope UsageScope) (*SystemOverview, error) {
	loc, _ := ReportLocation("")
	return r.GetSystemOverviewScopedIn(ctx, scope, loc)
}

// GetSystemOverviewScopedIn 按指定统计时区（租户时区）切今日/昨日日界。
func (r *StatsRepository) GetSystemOverviewScopedIn(ctx context.Context, scope UsageScope, loc *time.Location) (*SystemOverview, error) {
	if loc == nil {
		loc, _ = ReportLocation("")
	}
	var err error
	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	tomorrow := today.AddDate(0, 0, 1)
	yesterday := today.AddDate(0, 0, -1)

	overview := &SystemOverview{}

	// Today's requests (读 rollup 读模型,避免 request_logs 全表扫)
	todayWhere, todayArgs := usageScopeWhereRollup(scope, today, tomorrow)
	todayQuery := fmt.Sprintf(`
		SELECT COALESCE(SUM(request_count), 0) as requests,
		       COALESCE(SUM(total_cost), 0) as cost,
		       COALESCE(SUM(input_tokens + output_tokens), 0) as tokens
		FROM usage_rollup_hourly rl
		WHERE %s
	`, todayWhere)
	err = r.db.QueryRow(ctx, todayQuery, todayArgs...).Scan(
		&overview.TodayRequests, &overview.TodayCost, &overview.TodayTokens)
	if err != nil {
		return nil, fmt.Errorf("failed to get today's stats: %w", err)
	}

	// Yesterday's requests (读 rollup 读模型)
	yesterdayWhere, yesterdayArgs := usageScopeWhereRollup(scope, yesterday, today)
	yesterdayQuery := fmt.Sprintf(`
		SELECT COALESCE(SUM(request_count), 0) as requests,
		       COALESCE(SUM(total_cost), 0) as cost,
		       COALESCE(SUM(input_tokens + output_tokens), 0) as tokens
		FROM usage_rollup_hourly rl
		WHERE %s
	`, yesterdayWhere)
	err = r.db.QueryRow(ctx, yesterdayQuery, yesterdayArgs...).Scan(
		&overview.YesterdayRequests, &overview.YesterdayCost, &overview.YesterdayTokens)
	if err != nil {
		return nil, fmt.Errorf("failed to get yesterday's stats: %w", err)
	}

	// 累计统计:读 rollup 读模型,消灭 request_logs 全表扫(50万行→几百行 rollup)
	totalWhere, totalArgs := statsScopeWhereRollup(scope)
	totalQuery := fmt.Sprintf(`
		SELECT COALESCE(SUM(request_count), 0) as requests,
		       COALESCE(SUM(total_cost), 0) as cost,
		       COALESCE(SUM(input_tokens + output_tokens), 0) as tokens
		FROM usage_rollup_hourly rl
		WHERE %s
	`, totalWhere)
	err = r.db.QueryRow(ctx, totalQuery, totalArgs...).Scan(
		&overview.TotalRequests, &overview.TotalCost, &overview.TotalTokens)
	if err != nil {
		return nil, fmt.Errorf("failed to get total stats: %w", err)
	}

	// Calculate percentage change
	if overview.YesterdayRequests > 0 {
		overview.TodayRequestsChange = ((float64(overview.TodayRequests) - float64(overview.YesterdayRequests)) / float64(overview.YesterdayRequests)) * 100
	} else if overview.TodayRequests > 0 {
		overview.TodayRequestsChange = 100 // From 0 to non-zero is 100% increase
	}

	if overview.YesterdayTokens > 0 {
		overview.TodayTokensChange = ((float64(overview.TodayTokens) - float64(overview.YesterdayTokens)) / float64(overview.YesterdayTokens)) * 100
	} else if overview.TodayTokens > 0 {
		overview.TodayTokensChange = 100
	}

	if overview.YesterdayCost > 0 {
		overview.TodayCostChange = ((overview.TodayCost - overview.YesterdayCost) / overview.YesterdayCost) * 100
	} else if overview.TodayCost > 0 {
		overview.TodayCostChange = 100
	}

	// Active projects (today, 与今日请求同口径;空 project_id 不计)
	activeWhere, activeArgs := usageScopeWhereRollup(scope, today, tomorrow)
	activeProjectsQuery := fmt.Sprintf(`
		SELECT COUNT(DISTINCT NULLIF(project_id, ''))
		FROM usage_rollup_hourly rl
		WHERE %s AND request_count > 0
	`, activeWhere)
	err = r.db.QueryRow(ctx, activeProjectsQuery, activeArgs...).Scan(&overview.ActiveProjects)
	if err != nil {
		return nil, fmt.Errorf("failed to get active projects: %w", err)
	}

	// Security blocks (today, 与今日请求同口径)
	securityWhere, securityArgs := securityEventScopeWhere(scope, today)
	securityBlocksQuery := fmt.Sprintf(`
		SELECT COALESCE(COUNT(*), 0)
		FROM security_events
		WHERE %s AND action_taken = 'block'
	`, securityWhere)
	err = r.db.QueryRow(ctx, securityBlocksQuery, securityArgs...).Scan(&overview.SecurityBlocks)
	if err != nil {
		return nil, fmt.Errorf("failed to get security blocks: %w", err)
	}

	securityEventsQuery := fmt.Sprintf(`
		SELECT COALESCE(COUNT(*), 0)
		FROM security_events
		WHERE %s
	`, securityWhere)
	err = r.db.QueryRow(ctx, securityEventsQuery, securityArgs...).Scan(&overview.SecurityEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to get security events: %w", err)
	}

	return overview, nil
}

func securityEventScopeWhere(scope UsageScope, since time.Time) (string, []interface{}) {
	args := []interface{}{scope.TenantID, since}
	where := "tenant_id = $1 AND created_at >= $2"
	if !scope.FullTenant && len(scope.ProjectIDs) > 0 {
		args = append(args, scope.ProjectIDs)
		where += fmt.Sprintf(" AND project_id = ANY($%d)", len(args))
	}
	if !scope.FullTenant && len(scope.ProjectIDs) == 0 && scope.UserID != "" {
		args = append(args, scope.UserID)
		where += fmt.Sprintf(" AND user_id = $%d", len(args))
	}
	return where, args
}

// usageScopeWhereRollup 同 usageScopeWhere，但时间列用 usage_rollup_hourly 的 bucket_start，
// 供态势总览等聚合改读 rollup 读模型(避免 request_logs 全表扫)。维度列名 rollup 与原表一致。
func usageScopeWhereRollup(scope UsageScope, startDate, endDate time.Time) (string, []interface{}) {
	args := []interface{}{scope.TenantID, startDate, endDate}
	where := "rl.tenant_id = $1 AND rl.bucket_start >= $2 AND rl.bucket_start < $3"
	if !scope.FullTenant && len(scope.ProjectIDs) > 0 {
		args = append(args, scope.ProjectIDs)
		where += fmt.Sprintf(" AND rl.project_id = ANY($%d)", len(args))
	}
	if !scope.FullTenant && len(scope.ProjectIDs) == 0 && scope.UserID != "" {
		args = append(args, scope.UserID)
		where += fmt.Sprintf(" AND rl.user_id = $%d", len(args))
	}
	return where, args
}

func statsScopeWhereRollup(scope UsageScope) (string, []interface{}) {
	start, end := allStatsScopeBounds()
	return usageScopeWhereRollup(scope, start, end)
}

// UserAgentDetail represents agent usage details for a specific user
type UserAgentDetail struct {
	AgentType    string  `json:"agent_type"`
	RequestCount int64   `json:"request_count"`
	TotalTokens  int64   `json:"total_tokens"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	TotalCost    float64 `json:"total_cost"`
	FirstUse     string  `json:"first_use"`
	LastUse      string  `json:"last_use"`
}

// GetUserAgentDetail returns agent usage details for a specific user
func (r *StatsRepository) GetUserAgentDetail(ctx context.Context, tenantID, userID string) ([]UserAgentDetail, error) {
	start, end := allStatsScopeBounds()
	return r.GetUserAgentDetailBetween(ctx, tenantID, userID, start, end)
}

// GetUserAgentDetailBetween returns agent usage details for a specific user and time window.
func (r *StatsRepository) GetUserAgentDetailBetween(ctx context.Context, tenantID, userID string, start, end time.Time) ([]UserAgentDetail, error) {
	cte, args := inferredAgentRequestsScopedCTE(UsageScope{TenantID: tenantID, FullTenant: true}, start, end)
	args = append(args, userID)
	userParam := len(args)
	query := cte + fmt.Sprintf(`
		SELECT agent_type,
		       COUNT(*) as request_count,
		       SUM(input_tokens + output_tokens) as total_tokens,
		       SUM(input_tokens) as input_tokens,
		       SUM(output_tokens) as output_tokens,
		       SUM(total_cost) as total_cost,
		       to_char(MIN(created_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as first_use,
		       to_char(MAX(created_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as last_use
		FROM agent_requests
		WHERE user_id = $%d AND agent_type != '' AND meaningful_agent_request
		GROUP BY agent_type
		ORDER BY request_count DESC
	`, userParam)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get user agent detail: %w", err)
	}
	defer rows.Close()

	stats := []UserAgentDetail{}
	for rows.Next() {
		var s UserAgentDetail
		err := rows.Scan(&s.AgentType, &s.RequestCount, &s.TotalTokens, &s.InputTokens, &s.OutputTokens, &s.TotalCost, &s.FirstUse, &s.LastUse)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user agent detail: %w", err)
		}
		stats = append(stats, s)
	}

	return stats, nil
}

// AgentSessionByType represents a session with agent type info
type AgentSessionByType struct {
	SessionID   string  `json:"session_id"`
	UserID      string  `json:"user_id"`
	AgentType   string  `json:"agent_type"`
	TotalTokens int64   `json:"total_tokens"`
	TotalCost   float64 `json:"total_cost"`
	StartTime   string  `json:"start_time"`
	EndTime     string  `json:"end_time"`
}

// ListAgentSessionsByType returns sessions filtered by agent type and/or user
func (r *StatsRepository) ListAgentSessionsByType(ctx context.Context, tenantID, agentType, userID string, limit, offset int) ([]AgentSessionByType, int, error) {
	// Build base query
	baseQuery := `
		FROM agent_requests ar
		WHERE ar.agent_type != '' AND ar.meaningful_agent_request
	`
	args := []interface{}{tenantID}
	argIdx := 2

	if agentType != "" {
		baseQuery += fmt.Sprintf(" AND ar.agent_type = $%d", argIdx)
		args = append(args, agentType)
		argIdx++
	}
	if userID != "" {
		baseQuery += fmt.Sprintf(" AND ar.user_id = $%d", argIdx)
		args = append(args, userID)
		argIdx++
	}

	// Get total count
	totalQuery := inferredAgentRequestsCTE + "SELECT COUNT(DISTINCT ar.session_id) " + baseQuery
	var total int
	err := r.db.QueryRow(ctx, totalQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get total sessions: %w", err)
	}

	// Get sessions with aggregation
	query := inferredAgentRequestsCTE + fmt.Sprintf(`
		SELECT ar.session_id, ar.user_id, ar.agent_type,
		       SUM(ar.input_tokens + ar.output_tokens) as total_tokens,
		       SUM(ar.total_cost) as total_cost,
		       to_char(MIN(ar.created_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as start_time,
		       to_char(MAX(ar.created_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as end_time
		%s
		GROUP BY ar.session_id, ar.user_id, ar.agent_type
		ORDER BY start_time DESC
		LIMIT $%d OFFSET $%d
	`, baseQuery, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list agent sessions: %w", err)
	}
	defer rows.Close()

	sessions := []AgentSessionByType{}
	for rows.Next() {
		var s AgentSessionByType
		err := rows.Scan(&s.SessionID, &s.UserID, &s.AgentType, &s.TotalTokens, &s.TotalCost, &s.StartTime, &s.EndTime)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan agent session: %w", err)
		}
		sessions = append(sessions, s)
	}

	return sessions, total, nil
}

// AgentTypeDistribution represents distribution data for pie chart
type AgentTypeDistribution struct {
	AgentType string `json:"agent_type"`
	Count     int64  `json:"count"`
}

// GetAgentTypeDistribution returns pie chart data for agent types
func (r *StatsRepository) GetAgentTypeDistribution(ctx context.Context, tenantID string) ([]AgentTypeDistribution, error) {
	return r.GetAgentTypeDistributionScoped(ctx, UsageScope{TenantID: tenantID, FullTenant: true})
}

// GetAgentTypeDistributionScoped returns pie chart data for agent types within a usage scope (all-time).
func (r *StatsRepository) GetAgentTypeDistributionScoped(ctx context.Context, scope UsageScope) ([]AgentTypeDistribution, error) {
	start, end := allStatsScopeBounds()
	return r.GetAgentTypeDistributionScopedBetween(ctx, scope, start, end)
}

// GetAgentTypeDistributionScopedBetween returns pie chart data for agent types within a usage scope and time window.
func (r *StatsRepository) GetAgentTypeDistributionScopedBetween(ctx context.Context, scope UsageScope, start, end time.Time) ([]AgentTypeDistribution, error) {
	cte, args := inferredAgentRequestsScopedCTE(scope, start, end)
	query := cte + `
		SELECT agent_type, COUNT(*) as count
		FROM agent_requests
		WHERE agent_type != '' AND meaningful_agent_request
		GROUP BY agent_type
		ORDER BY count DESC
	`

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent type distribution: %w", err)
	}
	defer rows.Close()

	distribution := []AgentTypeDistribution{}
	for rows.Next() {
		var d AgentTypeDistribution
		err := rows.Scan(&d.AgentType, &d.Count)
		if err != nil {
			return nil, fmt.Errorf("failed to scan distribution: %w", err)
		}
		distribution = append(distribution, d)
	}

	return distribution, nil
}
