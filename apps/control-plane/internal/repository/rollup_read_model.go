package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type RollupReadModelRepository struct {
	db *pgxpool.Pool
}

func NewRollupReadModelRepository(db *pgxpool.Pool) *RollupReadModelRepository {
	return &RollupReadModelRepository{db: db}
}

// RollupRefreshWindow describes an hourly read-model recomputation window.
type RollupRefreshWindow struct {
	TenantID string
	From     time.Time
	To       time.Time
}

type UsageRollupInput struct {
	TenantID           string
	BucketStart        time.Time
	ProjectID          string
	UserID             string
	ClientID           string
	ProviderID         string
	ModelID            string
	RequestCount       int
	SuccessCount       int
	PricedRequestCount int
	InputTokens        int64
	OutputTokens       int64
	TotalCost          float64
	LatencyMsSum       int64
	FirstSeenAt        time.Time
	LastSeenAt         time.Time
}

type UsageRollupSummary struct {
	Requests        int
	SuccessRequests int
	PricedRequests  int
	InputTokens     int64
	OutputTokens    int64
	TotalCost       float64
	LatencyMsSum    int64
	DataFreshUntil  *time.Time
}

func (s UsageRollupSummary) TotalTokens() int64 {
	return s.InputTokens + s.OutputTokens
}

type AccessRollupInput struct {
	TenantID             string
	BucketStart          time.Time
	Direction            string
	AccessType           string
	Provider             string
	TargetHost           string
	RiskState            string
	RequestCount         int
	NormalCount          int
	RiskCount            int
	BlockedCount         int
	LLMCount             int
	AIIdeCount           int
	NormalPublicCount    int
	RetainedContentCount int
	ForwardCount         int
	ReverseCount         int
	DeviceCount          int
}

func (r *RollupReadModelRepository) RefreshUsageHourly(ctx context.Context, win RollupRefreshWindow) error {
	if r == nil || r.db == nil {
		return errors.New("rollup repository db is nil")
	}
	tenantID, from, to, err := normalizeRollupRefreshWindow(win)
	if err != nil {
		return err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		DELETE FROM usage_rollup_hourly
		WHERE tenant_id = $1 AND bucket_start >= $2 AND bucket_start < $3
	`, tenantID, from, to); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, usageHourlyRollupInsertSQL, tenantID, from, to); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *RollupReadModelRepository) RefreshAccessHourly(ctx context.Context, win RollupRefreshWindow) error {
	if r == nil || r.db == nil {
		return errors.New("rollup repository db is nil")
	}
	tenantID, from, to, err := normalizeRollupRefreshWindow(win)
	if err != nil {
		return err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		DELETE FROM access_rollup_hourly
		WHERE tenant_id = $1 AND bucket_start >= $2 AND bucket_start < $3
	`, tenantID, from, to); err != nil {
		return err
	}

	accessTypeExpr := forwardProxyAccessTypeExpr()
	riskExpr := forwardProxyRiskExpr()
	hasContentExpr := forwardProxyHasRetainedContentExpr()
	targetHostExpr := forwardProxyRowTargetHostExpr()
	query := fmt.Sprintf(`
		WITH source AS (
			SELECT
				rl.tenant_id,
				date_trunc('hour', rl.created_at) AS bucket_start,
				CASE
					WHEN COALESCE(rl.proxy_mode, '') = 'forward' THEN 'forward'
					WHEN COALESCE(rl.proxy_mode, '') = 'reverse' THEN 'reverse'
					ELSE 'chat_completion'
				END AS access_direction,
				%s AS access_type,
				COALESCE(NULLIF(rl.proxy_provider, ''), rl.provider_id, '') AS provider,
				%s AS target_host,
				%s AS risk_state,
				%s AS has_retained_content
			FROM request_logs rl
			WHERE rl.tenant_id = $1 AND rl.created_at >= $2 AND rl.created_at < $3
		)
		INSERT INTO access_rollup_hourly (
			tenant_id, bucket_start, access_direction, access_type, provider, target_host, risk_state,
			request_count, normal_count, risk_count, blocked_count, llm_count, ai_ide_count,
			normal_public_count, retained_content_count, forward_count, reverse_count, device_count, updated_at
		)
		SELECT
			tenant_id,
			bucket_start,
			access_direction,
			access_type,
			provider,
			target_host,
			risk_state,
			COUNT(*)::int AS request_count,
			(COUNT(*) FILTER (WHERE risk_state = 'normal'))::int AS normal_count,
			(COUNT(*) FILTER (WHERE risk_state = 'risk'))::int AS risk_count,
			(COUNT(*) FILTER (WHERE risk_state = 'blocked'))::int AS blocked_count,
			(COUNT(*) FILTER (WHERE access_type = 'llm'))::int AS llm_count,
			(COUNT(*) FILTER (WHERE access_type = 'ai_ide'))::int AS ai_ide_count,
			(COUNT(*) FILTER (WHERE access_type = 'normal_public'))::int AS normal_public_count,
			(COUNT(*) FILTER (WHERE has_retained_content))::int AS retained_content_count,
			(COUNT(*) FILTER (WHERE access_direction = 'forward'))::int AS forward_count,
			(COUNT(*) FILTER (WHERE access_direction = 'reverse'))::int AS reverse_count,
			(COUNT(*) FILTER (WHERE access_type = 'device'))::int AS device_count,
			NOW() AS updated_at
		FROM source
		GROUP BY tenant_id, bucket_start, access_direction, access_type, provider, target_host, risk_state
	`, accessTypeExpr, targetHostExpr, riskExpr, hasContentExpr)
	if _, err := tx.Exec(ctx, query, tenantID, from, to); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func normalizeRollupRefreshWindow(win RollupRefreshWindow) (string, time.Time, time.Time, error) {
	tenantID := strings.TrimSpace(win.TenantID)
	if tenantID == "" || !win.From.Before(win.To) {
		return "", time.Time{}, time.Time{}, errors.New("tenant id and valid refresh window are required")
	}
	from := win.From.UTC().Truncate(time.Hour)
	to := win.To.UTC().Truncate(time.Hour)
	if !to.Equal(win.To.UTC()) {
		to = to.Add(time.Hour)
	}
	if !from.Before(to) {
		return "", time.Time{}, time.Time{}, errors.New("tenant id and valid refresh window are required")
	}
	return tenantID, from, to, nil
}

func (r *RollupReadModelRepository) UpsertUsageHourly(ctx context.Context, input UsageRollupInput) error {
	if r == nil || r.db == nil {
		return errors.New("rollup repository db is nil")
	}
	if strings.TrimSpace(input.TenantID) == "" || input.BucketStart.IsZero() {
		return errors.New("tenant id and bucket start are required")
	}
	bucket := input.BucketStart.UTC().Truncate(time.Hour)
	firstSeen := nullableTime(input.FirstSeenAt)
	lastSeen := nullableTime(input.LastSeenAt)
	_, err := r.db.Exec(ctx, `
        INSERT INTO usage_rollup_hourly (
            tenant_id, bucket_start, project_id, user_id, client_id, provider_id, model_id,
            request_count, success_count, priced_request_count, input_tokens, output_tokens,
            total_cost, latency_ms_sum, first_seen_at, last_seen_at, updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NOW())
        ON CONFLICT (tenant_id, bucket_start, project_id, user_id, client_id, provider_id, model_id)
        DO UPDATE SET
            request_count = EXCLUDED.request_count,
            success_count = EXCLUDED.success_count,
            priced_request_count = EXCLUDED.priced_request_count,
            input_tokens = EXCLUDED.input_tokens,
            output_tokens = EXCLUDED.output_tokens,
            total_cost = EXCLUDED.total_cost,
            latency_ms_sum = EXCLUDED.latency_ms_sum,
            first_seen_at = EXCLUDED.first_seen_at,
            last_seen_at = EXCLUDED.last_seen_at,
            updated_at = NOW()
    `, input.TenantID, bucket, normalizeRollupDim(input.ProjectID), normalizeRollupDim(input.UserID), normalizeRollupDim(input.ClientID), normalizeRollupDim(input.ProviderID), normalizeRollupDim(input.ModelID), input.RequestCount, input.SuccessCount, input.PricedRequestCount, input.InputTokens, input.OutputTokens, input.TotalCost, input.LatencyMsSum, firstSeen, lastSeen)
	return err
}

func (r *RollupReadModelRepository) GetUsageSummaryScoped(ctx context.Context, scope UsageScope, start, end time.Time) (*UsageRollupSummary, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("rollup repository db is nil")
	}
	if strings.TrimSpace(scope.TenantID) == "" || !start.Before(end) {
		return nil, errors.New("tenant id and valid time range are required")
	}
	where, args := usageRollupScopeWhere(scope, start, end)
	query := fmt.Sprintf(`
		SELECT COALESCE(SUM(request_count), 0)::int,
		       COALESCE(SUM(success_count), 0)::int,
		       COALESCE(SUM(priced_request_count), 0)::int,
		       COALESCE(SUM(input_tokens), 0)::bigint,
		       COALESCE(SUM(output_tokens), 0)::bigint,
		       COALESCE(SUM(total_cost), 0)::float,
		       COALESCE(SUM(latency_ms_sum), 0)::bigint,
		       MAX(last_seen_at)
		FROM usage_rollup_hourly ur
		WHERE %s
	`, where)

	var summary UsageRollupSummary
	var freshUntil *time.Time
	if err := r.db.QueryRow(ctx, query, args...).Scan(&summary.Requests, &summary.SuccessRequests, &summary.PricedRequests, &summary.InputTokens, &summary.OutputTokens, &summary.TotalCost, &summary.LatencyMsSum, &freshUntil); err != nil {
		return nil, err
	}
	summary.DataFreshUntil = freshUntil
	return &summary, nil
}

func usageRollupScopeWhere(scope UsageScope, start, end time.Time) (string, []interface{}) {
	args := []interface{}{scope.TenantID, start.UTC(), end.UTC()}
	where := "ur.tenant_id = $1 AND ur.bucket_start >= $2 AND ur.bucket_start < $3"
	if !scope.FullTenant && len(scope.ProjectIDs) > 0 {
		args = append(args, scope.ProjectIDs)
		where += fmt.Sprintf(" AND ur.project_id = ANY($%d)", len(args))
	}
	if !scope.FullTenant && len(scope.ProjectIDs) == 0 && scope.UserID != "" {
		args = append(args, scope.UserID)
		where += fmt.Sprintf(" AND ur.user_id = $%d", len(args))
	}
	return where, args
}

func (r *RollupReadModelRepository) GetUsageSummary(ctx context.Context, tenantID string, start, end time.Time) (*UsageRollupSummary, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("rollup repository db is nil")
	}
	if strings.TrimSpace(tenantID) == "" || !start.Before(end) {
		return nil, errors.New("tenant id and valid time range are required")
	}
	var summary UsageRollupSummary
	var freshUntil *time.Time
	err := r.db.QueryRow(ctx, `
        SELECT COALESCE(SUM(request_count), 0)::int,
               COALESCE(SUM(success_count), 0)::int,
               COALESCE(SUM(priced_request_count), 0)::int,
               COALESCE(SUM(input_tokens), 0)::bigint,
               COALESCE(SUM(output_tokens), 0)::bigint,
               COALESCE(SUM(total_cost), 0)::float,
               COALESCE(SUM(latency_ms_sum), 0)::bigint,
               MAX(last_seen_at)
        FROM usage_rollup_hourly
        WHERE tenant_id = $1 AND bucket_start >= $2 AND bucket_start < $3
    `, tenantID, start.UTC(), end.UTC()).Scan(&summary.Requests, &summary.SuccessRequests, &summary.PricedRequests, &summary.InputTokens, &summary.OutputTokens, &summary.TotalCost, &summary.LatencyMsSum, &freshUntil)
	if err != nil {
		return nil, err
	}
	summary.DataFreshUntil = freshUntil
	return &summary, nil
}

func (r *RollupReadModelRepository) UpsertAccessHourly(ctx context.Context, input AccessRollupInput) error {
	if r == nil || r.db == nil {
		return errors.New("rollup repository db is nil")
	}
	if strings.TrimSpace(input.TenantID) == "" || input.BucketStart.IsZero() {
		return errors.New("tenant id and bucket start are required")
	}
	bucket := input.BucketStart.UTC().Truncate(time.Hour)
	_, err := r.db.Exec(ctx, `
        INSERT INTO access_rollup_hourly (
            tenant_id, bucket_start, access_direction, access_type, provider, target_host, risk_state,
            request_count, normal_count, risk_count, blocked_count, llm_count, ai_ide_count,
            normal_public_count, retained_content_count, forward_count, reverse_count, device_count, updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW())
        ON CONFLICT (tenant_id, bucket_start, access_direction, access_type, provider, target_host, risk_state)
        DO UPDATE SET
            request_count = EXCLUDED.request_count,
            normal_count = EXCLUDED.normal_count,
            risk_count = EXCLUDED.risk_count,
            blocked_count = EXCLUDED.blocked_count,
            llm_count = EXCLUDED.llm_count,
            ai_ide_count = EXCLUDED.ai_ide_count,
            normal_public_count = EXCLUDED.normal_public_count,
            retained_content_count = EXCLUDED.retained_content_count,
            forward_count = EXCLUDED.forward_count,
            reverse_count = EXCLUDED.reverse_count,
            device_count = EXCLUDED.device_count,
            updated_at = NOW()
    `, input.TenantID, bucket, normalizeRollupDim(input.Direction), normalizeRollupDim(input.AccessType), normalizeRollupDim(input.Provider), normalizeRollupDim(input.TargetHost), normalizeRollupDim(input.RiskState), input.RequestCount, input.NormalCount, input.RiskCount, input.BlockedCount, input.LLMCount, input.AIIdeCount, input.NormalPublicCount, input.RetainedContentCount, input.ForwardCount, input.ReverseCount, input.DeviceCount)
	return err
}

func (r *RollupReadModelRepository) GetAccessSummaryFiltered(ctx context.Context, tenantID string, filter ForwardProxyAccessFilter) (ForwardProxyAccessSummary, error) {
	if r == nil || r.db == nil {
		return ForwardProxyAccessSummary{}, errors.New("rollup repository db is nil")
	}
	if strings.TrimSpace(tenantID) == "" {
		return ForwardProxyAccessSummary{}, errors.New("tenant id is required")
	}
	filter = normalizeForwardProxyFilter(filter)
	where, args := accessRollupFilterWhere(tenantID, filter)
	summary, err := r.getAccessSummaryByWhere(ctx, where, args)
	if err != nil {
		return ForwardProxyAccessSummary{}, err
	}
	providers, err := r.accessDimensionsByWhere(ctx, where, args, "provider")
	if err != nil {
		return ForwardProxyAccessSummary{}, err
	}
	targets, err := r.accessDimensionsByWhere(ctx, where, args, "target_host")
	if err != nil {
		return ForwardProxyAccessSummary{}, err
	}
	summary.TopProviders = providers
	summary.TopTargets = targets
	return summary, nil
}

func accessRollupFilterWhere(tenantID string, filter ForwardProxyAccessFilter) (string, []interface{}) {
	args := []interface{}{tenantID}
	where := []string{"tenant_id = $1"}
	switch filter.Direction {
	case "forward", "reverse":
		args = append(args, filter.Direction)
		where = append(where, fmt.Sprintf("access_direction = $%d", len(args)))
	case "device":
		where = append(where, "1 = 0")
	}
	if filter.Provider != "" {
		args = append(args, strings.ToLower(filter.Provider))
		where = append(where, fmt.Sprintf("LOWER(provider) = $%d", len(args)))
	}
	if isKnownForwardProxyAccessType(filter.AccessType) {
		args = append(args, filter.AccessType)
		where = append(where, fmt.Sprintf("access_type = $%d", len(args)))
	} else {
		// 与 buildForwardProxyWhere 同口径：默认只看大模型流量，排除 normal_public 噪声。
		where = append(where, "access_type IN ('llm', 'ai_ide')")
	}
	if filter.TargetHost != "" {
		args = append(args, "%"+strings.ToLower(filter.TargetHost)+"%")
		where = append(where, fmt.Sprintf("LOWER(target_host) LIKE $%d", len(args)))
	}
	if !filter.StartTime.IsZero() {
		args = append(args, filter.StartTime.UTC())
		where = append(where, fmt.Sprintf("bucket_start >= $%d", len(args)))
	}
	if !filter.EndTime.IsZero() {
		args = append(args, filter.EndTime.UTC())
		where = append(where, fmt.Sprintf("bucket_start <= $%d", len(args)))
	}
	switch filter.RiskState {
	case "normal", "risk", "blocked":
		args = append(args, filter.RiskState)
		where = append(where, fmt.Sprintf("risk_state = $%d", len(args)))
	case "attention":
		args = append(args, "risk", "blocked")
		where = append(where, fmt.Sprintf("risk_state IN ($%d, $%d)", len(args)-1, len(args)))
	}
	return strings.Join(where, " AND "), args
}

func (r *RollupReadModelRepository) getAccessSummaryByWhere(ctx context.Context, where string, args []interface{}) (ForwardProxyAccessSummary, error) {
	var summary ForwardProxyAccessSummary
	var freshUntil *time.Time
	if err := r.db.QueryRow(ctx, `
		SELECT COALESCE(SUM(request_count), 0)::int,
		       COALESCE(SUM(normal_count), 0)::int,
		       COALESCE(SUM(risk_count), 0)::int,
		       COALESCE(SUM(blocked_count), 0)::int,
		       COALESCE(SUM(llm_count), 0)::int,
		       COALESCE(SUM(ai_ide_count), 0)::int,
		       COALESCE(SUM(normal_public_count), 0)::int,
		       COALESCE(SUM(retained_content_count), 0)::int,
		       COALESCE(SUM(forward_count), 0)::int,
		       COALESCE(SUM(reverse_count), 0)::int,
		       COALESCE(SUM(device_count), 0)::int,
		       MAX(bucket_start + INTERVAL '1 hour')
		FROM access_rollup_hourly
		WHERE `+where, args...).Scan(&summary.Total, &summary.NormalCount, &summary.RiskCount, &summary.BlockedCount, &summary.LLMCount, &summary.AIIdeCount, &summary.NormalPublicCount, &summary.RetainedContentCount, &summary.ForwardCount, &summary.ReverseCount, &summary.DeviceCount, &freshUntil); err != nil {
		return ForwardProxyAccessSummary{}, err
	}
	summary.DataFreshUntil = freshUntil
	return summary, nil
}

func (r *RollupReadModelRepository) accessDimensionsByWhere(ctx context.Context, where string, args []interface{}, column string) ([]ForwardProxyAccessDimension, error) {
	if column != "provider" && column != "target_host" {
		return nil, errors.New("invalid access rollup dimension")
	}

	var query string
	if column == "target_host" {
		// 对 model_xxx 形式的 target_host（反向代理内部模型）LEFT JOIN models 表拿可读模型名
		query = `
			SELECT COALESCE(m.model_label, m.model_name, arh.target_host) AS name,
			       COALESCE(SUM(arh.request_count), 0)::int AS count,
			       COALESCE(SUM(arh.risk_count + arh.blocked_count), 0)::int AS risk_count
			FROM access_rollup_hourly arh
			LEFT JOIN models m ON arh.target_host = m.id
			WHERE ` + where + ` AND arh.target_host <> ''
			GROUP BY arh.target_host, m.model_label, m.model_name
			ORDER BY count DESC, risk_count DESC, name ASC
			LIMIT 10
		`
	} else {
		// provider 空值归类为「直连调用」，不再显示空串导致前端 unknown
		query = `
			SELECT CASE WHEN ` + column + ` = '' THEN '直连调用' ELSE ` + column + ` END AS name,
			       COALESCE(SUM(request_count), 0)::int AS count,
			       COALESCE(SUM(risk_count + blocked_count), 0)::int AS risk_count
			FROM access_rollup_hourly
			WHERE ` + where + `
			GROUP BY CASE WHEN ` + column + ` = '' THEN '直连调用' ELSE ` + column + ` END
			ORDER BY count DESC, risk_count DESC, name ASC
			LIMIT 10
		`
	}
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	dims := []ForwardProxyAccessDimension{}
	for rows.Next() {
		var item ForwardProxyAccessDimension
		if err := rows.Scan(&item.Name, &item.Count, &item.RiskCount); err != nil {
			return nil, err
		}
		dims = append(dims, item)
	}
	return dims, rows.Err()
}

func (r *RollupReadModelRepository) GetAccessSummary(ctx context.Context, tenantID string, start, end time.Time) (ForwardProxyAccessSummary, error) {
	if r == nil || r.db == nil {
		return ForwardProxyAccessSummary{}, errors.New("rollup repository db is nil")
	}
	if strings.TrimSpace(tenantID) == "" || !start.Before(end) {
		return ForwardProxyAccessSummary{}, errors.New("tenant id and valid time range are required")
	}
	var summary ForwardProxyAccessSummary
	if err := r.db.QueryRow(ctx, `
        SELECT COALESCE(SUM(request_count), 0)::int,
               COALESCE(SUM(normal_count), 0)::int,
               COALESCE(SUM(risk_count), 0)::int,
               COALESCE(SUM(blocked_count), 0)::int,
               COALESCE(SUM(llm_count), 0)::int,
               COALESCE(SUM(ai_ide_count), 0)::int,
               COALESCE(SUM(normal_public_count), 0)::int,
               COALESCE(SUM(retained_content_count), 0)::int,
               COALESCE(SUM(forward_count), 0)::int,
               COALESCE(SUM(reverse_count), 0)::int,
               COALESCE(SUM(device_count), 0)::int
        FROM access_rollup_hourly
        WHERE tenant_id = $1 AND bucket_start >= $2 AND bucket_start < $3
    `, tenantID, start.UTC(), end.UTC()).Scan(&summary.Total, &summary.NormalCount, &summary.RiskCount, &summary.BlockedCount, &summary.LLMCount, &summary.AIIdeCount, &summary.NormalPublicCount, &summary.RetainedContentCount, &summary.ForwardCount, &summary.ReverseCount, &summary.DeviceCount); err != nil {
		return ForwardProxyAccessSummary{}, err
	}
	providers, err := r.accessDimensions(ctx, tenantID, start, end, "provider")
	if err != nil {
		return ForwardProxyAccessSummary{}, err
	}
	targets, err := r.accessDimensions(ctx, tenantID, start, end, "target_host")
	if err != nil {
		return ForwardProxyAccessSummary{}, err
	}
	summary.TopProviders = providers
	summary.TopTargets = targets
	return summary, nil
}

func (r *RollupReadModelRepository) accessDimensions(ctx context.Context, tenantID string, start, end time.Time, column string) ([]ForwardProxyAccessDimension, error) {
	if column != "provider" && column != "target_host" {
		return nil, errors.New("invalid access rollup dimension")
	}
	rows, err := r.db.Query(ctx, `
        SELECT `+column+` AS name,
               COALESCE(SUM(request_count), 0)::int AS count,
               COALESCE(SUM(risk_count + blocked_count), 0)::int AS risk_count
        FROM access_rollup_hourly
        WHERE tenant_id = $1 AND bucket_start >= $2 AND bucket_start < $3 AND `+column+` <> ''
        GROUP BY `+column+`
        ORDER BY count DESC, risk_count DESC, name ASC
        LIMIT 10
    `, tenantID, start.UTC(), end.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	dims := []ForwardProxyAccessDimension{}
	for rows.Next() {
		var item ForwardProxyAccessDimension
		if err := rows.Scan(&item.Name, &item.Count, &item.RiskCount); err != nil {
			return nil, err
		}
		dims = append(dims, item)
	}
	return dims, rows.Err()
}

func normalizeRollupDim(value string) string {
	return strings.TrimSpace(value)
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	v := value.UTC()
	return v
}

// usageHourlyRollupInsertSQL 把 request_logs 汇总进 usage_rollup_hourly（$1 租户，$2/$3 时间窗）；
// 平台自建的请求日志（NonBusinessEndpointTypes）不算业务请求，不进汇总。
var usageHourlyRollupInsertSQL = `
		INSERT INTO usage_rollup_hourly (
			tenant_id, bucket_start, project_id, user_id, client_id, provider_id, model_id,
			request_count, success_count, priced_request_count, ai_request_count, non_ai_request_count, ai_success_count, input_tokens, output_tokens,
			total_cost, latency_ms_sum, latency_count, first_priced_at, first_seen_at, last_seen_at, updated_at
		)
		SELECT
			rl.tenant_id,
			date_trunc('hour', rl.created_at) AS bucket_start,
			COALESCE(rl.project_id, '') AS project_id,
			COALESCE(rl.user_id, '') AS user_id,
			COALESCE(rl.client_id, '') AS client_id,
			COALESCE(rl.provider_id, '') AS provider_id,
			COALESCE(rl.model_id, '') AS model_id,
			COUNT(*)::int AS request_count,
			(COUNT(*) FILTER (WHERE COALESCE(rl.request_status, '') = 'success'))::int AS success_count,
			(COUNT(*) FILTER (WHERE rl.total_cost IS NOT NULL))::int AS priced_request_count,
			(COUNT(*) FILTER (WHERE COALESCE(rl.endpoint_type, '') <> 'proxy' OR rl.proxy_access_type_resolved IN ('llm', 'ai_ide')))::int AS ai_request_count,
			(COUNT(*) FILTER (WHERE COALESCE(rl.endpoint_type, '') = 'proxy' AND COALESCE(rl.proxy_access_type_resolved, '') NOT IN ('llm', 'ai_ide')))::int AS non_ai_request_count,
			(COUNT(*) FILTER (WHERE (COALESCE(rl.endpoint_type, '') <> 'proxy' OR rl.proxy_access_type_resolved IN ('llm', 'ai_ide')) AND COALESCE(rl.request_status, '') = 'success'))::int AS ai_success_count,
			COALESCE(SUM(COALESCE(rl.input_tokens, 0)), 0)::bigint AS input_tokens,
			COALESCE(SUM(COALESCE(rl.output_tokens, 0)), 0)::bigint AS output_tokens,
			COALESCE(SUM(COALESCE(rl.total_cost, 0)), 0)::numeric AS total_cost,
			COALESCE(SUM(COALESCE(rl.latency_ms, 0)), 0)::bigint AS latency_ms_sum,
			(COUNT(*) FILTER (WHERE rl.latency_ms IS NOT NULL))::bigint AS latency_count,
			MIN(rl.created_at) FILTER (WHERE rl.total_cost IS NOT NULL) AS first_priced_at,
			MIN(rl.created_at) AS first_seen_at,
			MAX(rl.created_at) AS last_seen_at,
			NOW() AS updated_at
		FROM request_logs rl
		WHERE rl.tenant_id = $1 AND rl.created_at >= $2 AND rl.created_at < $3
		  AND ` + ExcludeNonBusinessEndpointsSQL("rl") + `
		GROUP BY
			rl.tenant_id,
			date_trunc('hour', rl.created_at),
			COALESCE(rl.project_id, ''),
			COALESCE(rl.user_id, ''),
			COALESCE(rl.client_id, ''),
			COALESCE(rl.provider_id, ''),
			COALESCE(rl.model_id, '')
	`
