package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type UsageScope struct {
	TenantID   string
	UserID     string
	ProjectIDs []string
	TeamIDs    []string
	FullTenant bool
}

type CostCoverage struct {
	TotalRequests        int
	PricedRequests       int
	UnpricedRequests     int
	CoverageRate         float64
	UnpricedModelCount   int
	CostTrustedStartDate string
}

type CostDimension struct {
	ID               string
	Name             string
	ProviderName     string
	ProviderType     string
	ModelID          string
	ProjectID        string
	ProjectName      string
	UserID           string
	Username         string
	KeyPrefix        string
	Requests         int
	InputTokens      int64
	OutputTokens     int64
	TotalCost        float64
	CostPercent      float64
	AverageCost      float64
	SuccessRate      float64
	BudgetUsageRate  float64
	AverageLatencyMs float64
	ModelCount       int
	LastCalledAt     *time.Time
	AbnormalGrowth   bool
}

type CostRecommendation struct {
	ID           string
	Severity     string
	Problem      string
	Impact       string
	ImpactCost   float64
	ImpactTokens int64
	ProjectID    string
	UserID       string
	ModelID      string
	Suggestion   string
}

var defaultCostThresholds = struct {
	HighPriceShare       float64
	SimpleRequestTokens  int64
	LongContextTokens    int64
	BudgetNearRate       float64
	BudgetOverRate       float64
	FailureRate          float64
	MinFailureSampleSize int
	AnomalyCostFloor     float64
	AnomalyMultiplier    float64
}{
	HighPriceShare:       0.40,
	SimpleRequestTokens:  800,
	LongContextTokens:    8000,
	BudgetNearRate:       0.80,
	BudgetOverRate:       1.00,
	FailureRate:          0.10,
	MinFailureSampleSize: 20,
	AnomalyCostFloor:     1,
	AnomalyMultiplier:    3,
}

func usageScopeWhere(scope UsageScope, startDate, endDate time.Time) (string, []interface{}) {
	args := []interface{}{scope.TenantID, startDate, endDate}
	// 平台自建的请求日志不算业务用量（用量治理建议、用量明细、按范围的智能体统计共用）。
	where := "rl.tenant_id = $1 AND rl.created_at >= $2 AND rl.created_at < $3 AND " + ExcludeNonBusinessEndpointsSQL("rl")
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

func (r *UsageDailyRepository) GetSummaryScoped(ctx context.Context, scope UsageScope, startDate, endDate time.Time) (*UsageSummary, error) {
	// 读 rollup 读模型(窗口为 Asia/Shanghai 日界=UTC 整点,与 bucket_start 对齐;实测对账请求/token/成本逐项一致)。
	where, args := usageScopeWhereRollup(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT COALESCE(SUM(rl.request_count), 0)::int,
		       COALESCE(SUM(rl.input_tokens), 0)::bigint,
		       COALESCE(SUM(rl.output_tokens), 0)::bigint,
		       COALESCE(SUM(rl.total_cost), 0)::float
		FROM usage_rollup_hourly rl
		WHERE %s
	`, where)

	var summary UsageSummary
	summary.TenantID = scope.TenantID
	if err := r.db.QueryRow(ctx, query, args...).Scan(&summary.Requests, &summary.InputTokens, &summary.OutputTokens, &summary.TotalCost); err != nil {
		return nil, fmt.Errorf("failed to get scoped usage summary: %w", err)
	}
	return &summary, nil
}

func (r *UsageDailyRepository) GetCostCoverage(ctx context.Context, scope UsageScope, startDate, endDate time.Time) (*CostCoverage, error) {
	// 读 rollup 读模型(latency_count/first_priced_at 由迁移 090 补列+回填,worker 持续刷新)。
	where, args := usageScopeWhereRollup(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT COALESCE(SUM(rl.request_count), 0)::int,
		       COALESCE(SUM(rl.priced_request_count), 0)::int,
		       (COALESCE(SUM(rl.request_count), 0) - COALESCE(SUM(rl.priced_request_count), 0))::int,
		       CASE WHEN SUM(rl.request_count) = 0 THEN 0 ELSE SUM(rl.priced_request_count)::float / SUM(rl.request_count)::float END,
		       COUNT(DISTINCT rl.model_id) FILTER (WHERE rl.model_id <> '' AND rl.request_count > rl.priced_request_count)::int,
		       COALESCE(TO_CHAR(MIN(rl.first_priced_at) AT TIME ZONE 'Asia/Shanghai', 'YYYY-MM-DD'), '')
		FROM usage_rollup_hourly rl
		WHERE %s
	`, where)

	var coverage CostCoverage
	if err := r.db.QueryRow(ctx, query, args...).Scan(
		&coverage.TotalRequests,
		&coverage.PricedRequests,
		&coverage.UnpricedRequests,
		&coverage.CoverageRate,
		&coverage.UnpricedModelCount,
		&coverage.CostTrustedStartDate,
	); err != nil {
		return nil, fmt.Errorf("failed to get cost coverage: %w", err)
	}
	return &coverage, nil
}

func (r *UsageDailyRepository) GetByProjectScoped(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostDimension, error) {
	// 读 rollup 读模型(同上,additive 度量逐项一致;success 有 ~1 行最终一致性滞后,看板无感)。
	where, args := usageScopeWhereRollup(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT COALESCE(p.id, rl.project_id, '') AS id,
		       COALESCE(p.name, rl.project_id, '未归属应用') AS name,
		       COALESCE(SUM(rl.request_count), 0)::int AS requests,
		       COALESCE(SUM(rl.input_tokens), 0)::bigint AS input_tokens,
		       COALESCE(SUM(rl.output_tokens), 0)::bigint AS output_tokens,
		       COALESCE(SUM(rl.total_cost), 0)::float AS total_cost,
		       CASE WHEN SUM(SUM(rl.total_cost)) OVER () = 0 THEN 0 ELSE COALESCE(SUM(rl.total_cost), 0)::float / SUM(SUM(rl.total_cost)) OVER () END AS cost_percent,
		       CASE WHEN SUM(rl.request_count) = 0 THEN 0 ELSE COALESCE(SUM(rl.total_cost), 0)::float / SUM(rl.request_count) END AS average_cost,
		       CASE WHEN SUM(rl.request_count) = 0 THEN 0 ELSE SUM(rl.success_count)::float / SUM(rl.request_count)::float END AS success_rate,
		       CASE WHEN COALESCE(qp.monthly_budget_limit, 0) <= 0 THEN 0 ELSE COALESCE(SUM(rl.total_cost), 0)::float / qp.monthly_budget_limit END AS budget_usage_rate
		FROM usage_rollup_hourly rl
		LEFT JOIN projects p ON p.id = rl.project_id
		LEFT JOIN quota_policies qp ON qp.project_id = rl.project_id AND qp.scope_type = 'project' AND qp.status = 'active'
		WHERE %s
		GROUP BY p.id, p.name, rl.project_id, qp.monthly_budget_limit
		ORDER BY total_cost DESC, requests DESC
	`, where)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage by project: %w", err)
	}
	defer rows.Close()

	var result []*CostDimension
	for rows.Next() {
		var item CostDimension
		if err := rows.Scan(&item.ID, &item.Name, &item.Requests, &item.InputTokens, &item.OutputTokens, &item.TotalCost, &item.CostPercent, &item.AverageCost, &item.SuccessRate, &item.BudgetUsageRate); err != nil {
			return nil, err
		}
		item.ProjectID = item.ID
		item.ProjectName = item.Name
		result = append(result, &item)
	}
	return result, rows.Err()
}

func (r *UsageDailyRepository) GetByModel(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostDimension, error) {
	// Only attributed model calls belong in this dimension. Empty model IDs include
	// proxy/IDE/public traffic and do not mean a model was deleted. Historical
	// model names remain available through model_name_history.
	where, args := usageScopeWhereRollup(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT COALESCE(current_model.id, model_history.model_id, rl.model_id, '') AS id,
		       COALESCE(NULLIF(current_model.model_name, ''), NULLIF(model_history.model_name, ''), '未识别模型') AS name,
		       COALESCE(pv.name, '') AS provider_name,
		       COALESCE(pv.provider_type, '') AS provider_type,
		       COALESCE(SUM(rl.request_count), 0)::int,
		       COALESCE(SUM(rl.input_tokens), 0)::bigint,
		       COALESCE(SUM(rl.output_tokens), 0)::bigint,
		       COALESCE(SUM(rl.total_cost), 0)::float,
		       CASE WHEN SUM(SUM(rl.total_cost)) OVER () = 0 THEN 0 ELSE COALESCE(SUM(rl.total_cost), 0)::float / SUM(SUM(rl.total_cost)) OVER () END,
		       CASE WHEN SUM(rl.request_count) = 0 THEN 0 ELSE COALESCE(SUM(rl.total_cost), 0)::float / SUM(rl.request_count) END,
		       CASE WHEN SUM(rl.request_count) = 0 THEN 0 ELSE SUM(rl.success_count)::float / SUM(rl.request_count)::float END
		FROM usage_rollup_hourly rl
		LEFT JOIN (
			SELECT m.id, m.provider_id, p.tenant_id, m.model_name
			FROM models m
			JOIN providers p ON p.id = m.provider_id
		) current_model
		  ON current_model.id = rl.model_id
		 AND current_model.tenant_id = rl.tenant_id
		LEFT JOIN model_name_history model_history
		  ON model_history.tenant_id = rl.tenant_id
		 AND model_history.model_id = rl.model_id
		LEFT JOIN providers pv
		  ON pv.id = COALESCE(current_model.provider_id, model_history.provider_id, rl.provider_id)
		 AND pv.tenant_id = rl.tenant_id
		WHERE %s AND BTRIM(rl.model_id) != ''
		GROUP BY current_model.id, current_model.model_name,
		         model_history.model_id, model_history.model_name,
		         rl.model_id, pv.name, pv.provider_type
		ORDER BY 8 DESC, 5 DESC
	`, where)
	return r.scanCostDimensions(ctx, query, args, "model")
}

func (r *UsageDailyRepository) GetByUser(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostDimension, error) {
	// 读 rollup 读模型(同上,additive 度量逐项一致)。
	where, args := usageScopeWhereRollup(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT COALESCE(u.id, rl.user_id, '') AS id,
		       COALESCE(u.username, rl.user_id, '未知用户') AS name,
		       COALESCE(SUM(rl.request_count), 0)::int,
		       COALESCE(SUM(rl.input_tokens), 0)::bigint,
		       COALESCE(SUM(rl.output_tokens), 0)::bigint,
		       COALESCE(SUM(rl.total_cost), 0)::float,
		       CASE WHEN SUM(SUM(rl.total_cost)) OVER () = 0 THEN 0 ELSE COALESCE(SUM(rl.total_cost), 0)::float / SUM(SUM(rl.total_cost)) OVER () END,
		       CASE WHEN SUM(rl.request_count) = 0 THEN 0 ELSE COALESCE(SUM(rl.total_cost), 0)::float / SUM(rl.request_count) END,
		       CASE WHEN SUM(rl.request_count) = 0 THEN 0 ELSE SUM(rl.success_count)::float / SUM(rl.request_count)::float END
		FROM usage_rollup_hourly rl
		LEFT JOIN users u ON u.id = rl.user_id
		WHERE %s
		GROUP BY u.id, u.username, rl.user_id
		ORDER BY 6 DESC, 3 DESC
	`, where)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage by user: %w", err)
	}
	defer rows.Close()

	var result []*CostDimension
	for rows.Next() {
		var item CostDimension
		if err := rows.Scan(&item.ID, &item.Name, &item.Requests, &item.InputTokens, &item.OutputTokens, &item.TotalCost, &item.CostPercent, &item.AverageCost, &item.SuccessRate); err != nil {
			return nil, err
		}
		item.UserID = item.ID
		item.Username = item.Name
		result = append(result, &item)
	}
	return result, rows.Err()
}

func (r *UsageDailyRepository) GetByKey(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostDimension, error) {
	// 当前密钥统计只展示仍存在的密钥。删除密钥不会删除历史 rollup 审计事实，
	// 但历史 client_id 不应继续作为“当前密钥”出现在统计页。
	where, args := usageScopeWhereRollup(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT k.id AS id,
		       k.key_prefix AS key_prefix,
		       COALESCE(p.id, k.project_id, '') AS project_id,
		       COALESCE(p.name, '') AS project_name,
		       COALESCE(u.id, k.user_id, '') AS user_id,
		       COALESCE(u.username, '') AS username,
		       COALESCE(SUM(rl.request_count), 0)::int,
		       COALESCE(SUM(rl.input_tokens), 0)::bigint,
		       COALESCE(SUM(rl.output_tokens), 0)::bigint,
		       COALESCE(SUM(rl.total_cost), 0)::float,
		       CASE WHEN SUM(SUM(rl.total_cost)) OVER () = 0 THEN 0 ELSE COALESCE(SUM(rl.total_cost), 0)::float / SUM(SUM(rl.total_cost)) OVER () END,
		       CASE WHEN SUM(rl.request_count) = 0 THEN 0 ELSE COALESCE(SUM(rl.total_cost), 0)::float / SUM(rl.request_count) END,
		       CASE WHEN SUM(rl.request_count) = 0 THEN 0 ELSE SUM(rl.success_count)::float / SUM(rl.request_count)::float END,
		       MAX(rl.bucket_start)
		FROM usage_rollup_hourly rl
		JOIN internal_keys k ON k.id = rl.client_id AND k.tenant_id = rl.tenant_id
		LEFT JOIN projects p ON p.id = k.project_id AND p.tenant_id = k.tenant_id AND p.status <> 'deleted'
		LEFT JOIN users u ON u.id = k.user_id AND u.tenant_id = k.tenant_id
		WHERE %s
		GROUP BY k.id, k.key_prefix, p.id, p.name, k.project_id, u.id, u.username, k.user_id
		ORDER BY 10 DESC, 7 DESC
	`, where)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage by key: %w", err)
	}
	defer rows.Close()

	var result []*CostDimension
	for rows.Next() {
		var item CostDimension
		var last sql.NullTime
		if err := rows.Scan(&item.ID, &item.KeyPrefix, &item.ProjectID, &item.ProjectName, &item.UserID, &item.Username, &item.Requests, &item.InputTokens, &item.OutputTokens, &item.TotalCost, &item.CostPercent, &item.AverageCost, &item.SuccessRate, &last); err != nil {
			return nil, err
		}
		item.Name = item.KeyPrefix
		if last.Valid {
			item.LastCalledAt = &last.Time
		}
		result = append(result, &item)
	}
	return result, rows.Err()
}

func (r *UsageDailyRepository) GetByProvider(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostDimension, error) {
	// 读 rollup 读模型;AVG 延迟用 latency_ms_sum/latency_count(避免 NULL 延迟被零填稀释),
	// model_count 用 FILTER(<>'') 防 rollup 维度 NULL/空折叠多算。
	where, args := usageScopeWhereRollup(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT COALESCE(pv.id, rl.provider_id, '') AS id,
		       COALESCE(pv.name, rl.provider_id, '未知供应商') AS name,
		       COALESCE(pv.provider_type, '') AS provider_type,
		       COUNT(DISTINCT rl.model_id) FILTER (WHERE rl.model_id <> '')::int AS model_count,
		       COALESCE(SUM(rl.request_count), 0)::int,
		       COALESCE(SUM(rl.input_tokens), 0)::bigint,
		       COALESCE(SUM(rl.output_tokens), 0)::bigint,
		       COALESCE(SUM(rl.total_cost), 0)::float,
		       CASE WHEN SUM(SUM(rl.total_cost)) OVER () = 0 THEN 0 ELSE COALESCE(SUM(rl.total_cost), 0)::float / SUM(SUM(rl.total_cost)) OVER () END,
		       CASE WHEN SUM(rl.request_count) = 0 THEN 0 ELSE COALESCE(SUM(rl.total_cost), 0)::float / SUM(rl.request_count) END,
		       CASE WHEN SUM(rl.request_count) = 0 THEN 0 ELSE SUM(rl.success_count)::float / SUM(rl.request_count)::float END,
		       CASE WHEN SUM(rl.latency_count) = 0 THEN 0 ELSE SUM(rl.latency_ms_sum)::float / SUM(rl.latency_count) END
		FROM usage_rollup_hourly rl
		LEFT JOIN providers pv ON pv.id = rl.provider_id
		WHERE %s
		GROUP BY pv.id, pv.name, pv.provider_type, rl.provider_id
		ORDER BY 8 DESC, 5 DESC
	`, where)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage by provider: %w", err)
	}
	defer rows.Close()

	var result []*CostDimension
	for rows.Next() {
		var item CostDimension
		if err := rows.Scan(&item.ID, &item.Name, &item.ProviderType, &item.ModelCount, &item.Requests, &item.InputTokens, &item.OutputTokens, &item.TotalCost, &item.CostPercent, &item.AverageCost, &item.SuccessRate, &item.AverageLatencyMs); err != nil {
			return nil, err
		}
		item.ProviderName = item.Name
		result = append(result, &item)
	}
	return result, rows.Err()
}

func (r *UsageDailyRepository) scanCostDimensions(ctx context.Context, query string, args []interface{}, dimension string) ([]*CostDimension, error) {
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage by %s: %w", dimension, err)
	}
	defer rows.Close()

	var result []*CostDimension
	for rows.Next() {
		var item CostDimension
		if err := rows.Scan(&item.ID, &item.Name, &item.ProviderName, &item.ProviderType, &item.Requests, &item.InputTokens, &item.OutputTokens, &item.TotalCost, &item.CostPercent, &item.AverageCost, &item.SuccessRate); err != nil {
			return nil, err
		}
		item.ModelID = item.ID
		result = append(result, &item)
	}
	return result, rows.Err()
}

func (r *UsageDailyRepository) GetCostRecommendations(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostRecommendation, error) {
	recommendations := []*CostRecommendation{}

	generators := []func(context.Context, UsageScope, time.Time, time.Time) ([]*CostRecommendation, error){
		r.getBudgetRecommendations,
		r.getUnpricedRecommendations,
		r.getFailureWasteRecommendations,
		r.getHighPriceShareRecommendations,
		r.getSimpleHighPriceRecommendations,
		r.getLongContextRecommendations,
		r.getModelFailureRateRecommendations,
		r.getAnomalyRecommendations,
	}

	for _, generator := range generators {
		items, err := generator(ctx, scope, startDate, endDate)
		if err != nil {
			return nil, err
		}
		recommendations = append(recommendations, items...)
	}
	return recommendations, nil
}

func (r *UsageDailyRepository) getBudgetRecommendations(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostRecommendation, error) {
	where, args := usageScopeWhere(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT rl.project_id,
		       COALESCE(SUM(COALESCE(rl.total_cost, 0)), 0)::float AS cost,
		       COALESCE(qp.monthly_budget_limit, 0)::float AS budget
		FROM request_logs rl
		JOIN quota_policies qp ON qp.project_id = rl.project_id AND qp.scope_type = 'project' AND qp.status = 'active'
		WHERE %s
		GROUP BY rl.project_id, qp.monthly_budget_limit
		HAVING COALESCE(qp.monthly_budget_limit, 0) > 0
		   AND COALESCE(SUM(COALESCE(rl.total_cost, 0)), 0)::float / qp.monthly_budget_limit >= $%d
	`, where, len(args)+1)
	args = append(args, defaultCostThresholds.BudgetNearRate)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get budget recommendations: %w", err)
	}
	defer rows.Close()

	var recs []*CostRecommendation
	for rows.Next() {
		var projectID string
		var cost, budget float64
		if err := rows.Scan(&projectID, &cost, &budget); err != nil {
			return nil, err
		}
		rate := cost / budget
		id := "budget_near_limit"
		severity := "warning"
		problem := "应用费用接近月预算"
		if rate >= defaultCostThresholds.BudgetOverRate {
			id = "budget_over_limit"
			severity = "critical"
			problem = "应用费用已超过月预算"
		}
		recs = append(recs, &CostRecommendation{
			ID:         id,
			Severity:   severity,
			Problem:    problem,
			Impact:     fmt.Sprintf("已使用月预算 %.0f%%", rate*100),
			ImpactCost: cost,
			ProjectID:  projectID,
			Suggestion: "检查高价模型调用占比，必要时调整默认模型或提高预算。",
		})
	}
	return recs, rows.Err()
}

func (r *UsageDailyRepository) getUnpricedRecommendations(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostRecommendation, error) {
	where, args := usageScopeWhere(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT COALESCE(rl.model_id, ''), COUNT(*)::int, COALESCE(SUM(COALESCE(rl.input_tokens,0)+COALESCE(rl.output_tokens,0)),0)::bigint
		FROM request_logs rl
		WHERE %s AND rl.total_cost IS NULL
		GROUP BY rl.model_id
	`, where)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get unpriced recommendations: %w", err)
	}
	defer rows.Close()

	var recs []*CostRecommendation
	for rows.Next() {
		var modelID string
		var requests int
		var tokens int64
		if err := rows.Scan(&modelID, &requests, &tokens); err != nil {
			return nil, err
		}
		recs = append(recs, &CostRecommendation{
			ID:           "unpriced_model_usage",
			Severity:     "warning",
			Problem:      "存在未配置价格的模型调用",
			Impact:       fmt.Sprintf("%d 次请求未计入费用", requests),
			ImpactTokens: tokens,
			ModelID:      modelID,
			Suggestion:   "为模型补充输入/输出单价；补齐前不要把费用汇总作为完整账单使用。",
		})
	}
	return recs, rows.Err()
}

func (r *UsageDailyRepository) getFailureWasteRecommendations(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostRecommendation, error) {
	where, args := usageScopeWhere(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT rl.project_id, COUNT(*)::int, COALESCE(SUM(COALESCE(rl.total_cost,0)),0)::float
		FROM request_logs rl
		WHERE %s AND rl.request_status <> 'success' AND rl.total_cost IS NOT NULL AND rl.total_cost > 0
		GROUP BY rl.project_id
	`, where)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get failure waste recommendations: %w", err)
	}
	defer rows.Close()
	return scanProjectCostRecommendations(rows, "failure_cost_waste", "失败请求产生了模型费用", "优化重试、超时和上游错误处理，减少失败调用费用。")
}

func (r *UsageDailyRepository) getHighPriceShareRecommendations(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostRecommendation, error) {
	where, args := usageScopeWhere(scope, startDate, endDate)
	query := fmt.Sprintf(`
		WITH model_cost AS (
			SELECT rl.project_id, rl.model_id, COALESCE(SUM(COALESCE(rl.total_cost,0)),0)::float AS cost
			FROM request_logs rl
			WHERE %s
			GROUP BY rl.project_id, rl.model_id
		), project_cost AS (
			SELECT project_id, COALESCE(SUM(cost),0)::float AS cost
			FROM model_cost
			GROUP BY project_id
		)
		SELECT mc.project_id, COALESCE(mc.model_id, ''), mc.cost, pc.cost
		FROM model_cost mc
		JOIN project_cost pc ON pc.project_id = mc.project_id
		WHERE pc.cost > 0 AND mc.cost / pc.cost > $%d
	`, where, len(args)+1)
	args = append(args, defaultCostThresholds.HighPriceShare)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get high price share recommendations: %w", err)
	}
	defer rows.Close()

	var recs []*CostRecommendation
	for rows.Next() {
		var projectID, modelID string
		var modelCost, projectCost float64
		if err := rows.Scan(&projectID, &modelID, &modelCost, &projectCost); err != nil {
			return nil, err
		}
		recs = append(recs, &CostRecommendation{
			ID:         "high_price_model_share",
			Severity:   "warning",
			Problem:    "高价模型费用占比过高",
			Impact:     fmt.Sprintf("该模型占应用费用 %.0f%%", modelCost/projectCost*100),
			ImpactCost: modelCost,
			ProjectID:  projectID,
			ModelID:    modelID,
			Suggestion: "评估简单场景是否可切换到低成本模型，并保留高价模型给高优先级业务。",
		})
	}
	return recs, rows.Err()
}

func (r *UsageDailyRepository) getSimpleHighPriceRecommendations(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostRecommendation, error) {
	where, args := usageScopeWhere(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT rl.project_id, COALESCE(rl.model_id, ''), COUNT(*)::int, COALESCE(SUM(COALESCE(rl.total_cost,0)),0)::float
		FROM request_logs rl
		WHERE %s
		  AND COALESCE(rl.input_tokens,0) + COALESCE(rl.output_tokens,0) < $%d
		GROUP BY rl.project_id, rl.model_id
		HAVING COALESCE(SUM(COALESCE(rl.total_cost,0)),0) > 0
	`, where, len(args)+1)
	args = append(args, defaultCostThresholds.SimpleRequestTokens)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get simple high-price recommendations: %w", err)
	}
	defer rows.Close()
	return scanModelCostRecommendations(rows, "simple_request_high_price_model", "简单请求使用了付费模型", "将短文本、低风险请求路由到更低成本模型。")
}

func (r *UsageDailyRepository) getLongContextRecommendations(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostRecommendation, error) {
	where, args := usageScopeWhere(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT rl.project_id, COUNT(*)::int, COALESCE(SUM(COALESCE(rl.input_tokens,0)),0)::bigint
		FROM request_logs rl
		WHERE %s AND COALESCE(rl.input_tokens,0) > $%d
		GROUP BY rl.project_id
	`, where, len(args)+1)
	args = append(args, defaultCostThresholds.LongContextTokens)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get long context recommendations: %w", err)
	}
	defer rows.Close()

	var recs []*CostRecommendation
	for rows.Next() {
		var projectID string
		var requests int
		var tokens int64
		if err := rows.Scan(&projectID, &requests, &tokens); err != nil {
			return nil, err
		}
		recs = append(recs, &CostRecommendation{
			ID:           "long_context_usage",
			Severity:     "info",
			Problem:      "长上下文请求较多",
			Impact:       fmt.Sprintf("%d 次请求输入 Token 超过 8000", requests),
			ImpactTokens: tokens,
			ProjectID:    projectID,
			Suggestion:   "压缩历史消息、摘要长文档，避免重复传入无效上下文。",
		})
	}
	return recs, rows.Err()
}

func (r *UsageDailyRepository) getModelFailureRateRecommendations(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostRecommendation, error) {
	where, args := usageScopeWhere(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT COALESCE(rl.model_id, ''),
		       COUNT(*)::int AS requests,
		       SUM(CASE WHEN rl.request_status <> 'success' THEN 1 ELSE 0 END)::int AS failures
		FROM request_logs rl
		WHERE %s
		GROUP BY rl.model_id
		HAVING COUNT(*) >= $%d
		   AND SUM(CASE WHEN rl.request_status <> 'success' THEN 1 ELSE 0 END)::float / COUNT(*)::float > $%d
	`, where, len(args)+1, len(args)+2)
	args = append(args, defaultCostThresholds.MinFailureSampleSize, defaultCostThresholds.FailureRate)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get model failure recommendations: %w", err)
	}
	defer rows.Close()

	var recs []*CostRecommendation
	for rows.Next() {
		var modelID string
		var requests, failures int
		if err := rows.Scan(&modelID, &requests, &failures); err != nil {
			return nil, err
		}
		recs = append(recs, &CostRecommendation{
			ID:         "model_failure_rate_high",
			Severity:   "warning",
			Problem:    "模型失败率偏高但仍在大量调用",
			Impact:     fmt.Sprintf("%d/%d 次请求失败", failures, requests),
			ModelID:    modelID,
			Suggestion: "检查上游供应商状态、模型路由和超时设置，必要时切换备用模型。",
		})
	}
	return recs, rows.Err()
}

func (r *UsageDailyRepository) getAnomalyRecommendations(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*CostRecommendation, error) {
	where, args := usageScopeWhere(scope, startDate, endDate)
	// portal 机器通道的无归属 key 会产生 user_id=NULL 且有真实费用的行：
	// NULL 分组必须 COALESCE 成空串，否则一旦费用过 AnomalyCostFloor，
	// Scan NULL 进 *string 报错会打挂整个 GetCostRecommendations；
	// 且 LEFT JOIN 的 NULL=NULL 永假会让 NULL 组永远匹配不上自己的 baseline。
	query := fmt.Sprintf(`
		WITH current_hour AS (
			SELECT COALESCE(rl.user_id, '') AS user_id, COALESCE(SUM(COALESCE(rl.total_cost,0)),0)::float AS cost
			FROM request_logs rl
			WHERE %s AND rl.created_at >= NOW() - INTERVAL '1 hour'
			GROUP BY COALESCE(rl.user_id, '')
		), baseline AS (
			SELECT COALESCE(rl.user_id, '') AS user_id, COALESCE(SUM(COALESCE(rl.total_cost,0)),0)::float / 7 AS avg_cost
			FROM request_logs rl
			WHERE %s
			  AND rl.created_at >= NOW() - INTERVAL '7 day'
			  AND EXTRACT(HOUR FROM rl.created_at AT TIME ZONE 'Asia/Shanghai') = EXTRACT(HOUR FROM NOW() AT TIME ZONE 'Asia/Shanghai')
			GROUP BY COALESCE(rl.user_id, '')
		)
		SELECT ch.user_id, ch.cost, COALESCE(b.avg_cost,0)::float
		FROM current_hour ch
		LEFT JOIN baseline b ON b.user_id = ch.user_id
		WHERE ch.cost > $%d AND ch.cost > COALESCE(b.avg_cost,0) * $%d
	`, where, where, len(args)+1, len(args)+2)
	args = append(args, defaultCostThresholds.AnomalyCostFloor, defaultCostThresholds.AnomalyMultiplier)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get anomaly recommendations: %w", err)
	}
	defer rows.Close()

	var recs []*CostRecommendation
	for rows.Next() {
		var userID string
		var cost, avg float64
		if err := rows.Scan(&userID, &cost, &avg); err != nil {
			return nil, err
		}
		recs = append(recs, &CostRecommendation{
			ID:         "user_cost_anomaly",
			Severity:   "warning",
			Problem:    "用户短时间费用异常增长",
			Impact:     fmt.Sprintf("近 1 小时费用 %.2f，历史同小时均值 %.2f", cost, avg),
			ImpactCost: cost,
			UserID:     userID,
			Suggestion: "检查该用户或 Key 是否存在异常任务、循环调用或凭证泄露风险。",
		})
	}
	return recs, rows.Err()
}

type projectCostRows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Err() error
}

func scanProjectCostRecommendations(rows projectCostRows, id, problem, suggestion string) ([]*CostRecommendation, error) {
	var recs []*CostRecommendation
	for rows.Next() {
		var projectID string
		var requests int
		var cost float64
		if err := rows.Scan(&projectID, &requests, &cost); err != nil {
			return nil, err
		}
		recs = append(recs, &CostRecommendation{
			ID:         id,
			Severity:   "warning",
			Problem:    problem,
			Impact:     fmt.Sprintf("%d 次请求，费用 %.4f", requests, cost),
			ImpactCost: cost,
			ProjectID:  projectID,
			Suggestion: suggestion,
		})
	}
	return recs, rows.Err()
}

func scanModelCostRecommendations(rows projectCostRows, id, problem, suggestion string) ([]*CostRecommendation, error) {
	var recs []*CostRecommendation
	for rows.Next() {
		var projectID, modelID string
		var requests int
		var cost float64
		if err := rows.Scan(&projectID, &modelID, &requests, &cost); err != nil {
			return nil, err
		}
		recs = append(recs, &CostRecommendation{
			ID:         id,
			Severity:   "info",
			Problem:    problem,
			Impact:     fmt.Sprintf("%d 次请求，费用 %.4f", requests, cost),
			ImpactCost: cost,
			ProjectID:  projectID,
			ModelID:    modelID,
			Suggestion: suggestion,
		})
	}
	return recs, rows.Err()
}

// UsageTrendPoint is one day in a usage trend series.
type UsageTrendPoint struct {
	Date         string  `json:"date"`
	Requests     int     `json:"requests"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	TotalCost    float64 `json:"total_cost"`
}

// GetTrendScoped returns a daily usage trend (requests/tokens/cost) within the date range.
func (r *UsageDailyRepository) GetTrendScoped(ctx context.Context, scope UsageScope, startDate, endDate time.Time) ([]*UsageTrendPoint, error) {
	where, args := usageScopeWhereRollup(scope, startDate, endDate)
	query := fmt.Sprintf(`
		SELECT TO_CHAR(rl.bucket_start AT TIME ZONE 'Asia/Shanghai', 'YYYY-MM-DD') AS d,
		       COALESCE(SUM(rl.request_count), 0)::int,
		       COALESCE(SUM(rl.input_tokens), 0)::bigint,
		       COALESCE(SUM(rl.output_tokens), 0)::bigint,
		       COALESCE(SUM(rl.total_cost), 0)::float
		FROM usage_rollup_hourly rl
		WHERE %s
		GROUP BY d
		ORDER BY d
	`, where)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage trend: %w", err)
	}
	defer rows.Close()
	var points []*UsageTrendPoint
	for rows.Next() {
		var p UsageTrendPoint
		if err := rows.Scan(&p.Date, &p.Requests, &p.InputTokens, &p.OutputTokens, &p.TotalCost); err != nil {
			return nil, err
		}
		points = append(points, &p)
	}
	return points, rows.Err()
}
