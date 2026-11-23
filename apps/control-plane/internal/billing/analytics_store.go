package billing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrMixedCurrency rejects an analytics selection whose facts span more than
// one currency. Micros totals across different currencies are not summable,
// so every micro-summing aggregate refuses the whole selection with this
// typed error instead of summing raw numbers and flagging the result
// afterwards. Re-run the aggregation scoped to a single currency.
var ErrMixedCurrency = errors.New("billing analytics selection spans multiple currencies; micros totals are not summable")

type AnalyticsFilter struct {
	Currency            string
	TenantID            string
	Start               time.Time
	End                 time.Time
	TeamIDs             []string
	ProjectIDs          []string
	UserID              string
	FullTenant          bool
	FilterDepartmentIDs []string
	FilterProjectIDs    []string
	FilterUserIDs       []string
	FilterModelIDs      []string
	FilterProviderIDs   []string
	FilterAgentTypes    []string
}

type AnalyticsSummary struct {
	EstimatedRequests int64 `json:"estimated_requests"`
	ImageCount        int64 `json:"image_count"`
	ToolCallCount     int64 `json:"tool_call_count"`
	Requests          int64 `json:"requests"`
	// PricedRequests keeps the legacy non-unpriced definition for existing
	// consumers; SettledRequests and FailedRequests carry the settled and
	// failed outcomes as separate counters. usage_unknown facts (forward proxy
	// traffic whose token usage could not be parsed) are neither priced nor
	// unpriced: they are counted only in UsageUnknownRequests.
	PricedRequests            int64    `json:"priced_requests"`
	UnpricedRequests          int64    `json:"unpriced_requests"`
	UsageUnknownRequests      int64    `json:"usage_unknown_requests"`
	SettledRequests           int64    `json:"settled_requests"`
	FailedRequests            int64    `json:"failed_requests"`
	PromptTokens              int64    `json:"prompt_tokens"`
	CachedInputTokens         int64    `json:"cached_input_tokens"`
	CacheWriteInputTokens     int64    `json:"cache_write_input_tokens"`
	OutputTokens              int64    `json:"output_tokens"`
	ReasoningTokens           int64    `json:"reasoning_tokens"`
	TotalTokens               int64    `json:"total_tokens"`
	BillableMicros            Micros   `json:"billable_micros"`
	UpstreamCostMicros        Micros   `json:"upstream_cost_micros"`
	UpstreamCostKnownRequests int64    `json:"upstream_cost_known_requests"`
	Currency                  string   `json:"currency"`
	OtherCurrencies           []string `json:"other_currencies"`
}

type AnalyticsBreakdown struct {
	ImageCount                int64   `json:"image_count"`
	ToolCallCount             int64   `json:"tool_call_count"`
	ID                        string  `json:"id"`
	Name                      string  `json:"name"`
	ModelName                 string  `json:"model_name,omitempty"`
	ModelLabel                string  `json:"model_label,omitempty"`
	Secondary                 string  `json:"secondary,omitempty"`
	Requests                  int64   `json:"requests"`
	PricedRequests            int64   `json:"priced_requests"`
	UsageUnknownRequests      int64   `json:"usage_unknown_requests"`
	PromptTokens              int64   `json:"prompt_tokens"`
	CachedInputTokens         int64   `json:"cached_input_tokens"`
	CacheWriteInputTokens     int64   `json:"cache_write_input_tokens"`
	OutputTokens              int64   `json:"output_tokens"`
	ReasoningTokens           int64   `json:"reasoning_tokens"`
	TotalTokens               int64   `json:"total_tokens"`
	BillableMicros            Micros  `json:"billable_micros"`
	UpstreamCostMicros        Micros  `json:"upstream_cost_micros"`
	UpstreamCostKnownRequests int64   `json:"upstream_cost_known_requests"`
	CostShare                 float64 `json:"cost_share"`
}

type AnalyticsSeriesPoint struct {
	Bucket             time.Time `json:"bucket"`
	Requests           int64     `json:"requests"`
	TotalTokens        int64     `json:"total_tokens"`
	BillableMicros     Micros    `json:"billable_micros"`
	UpstreamCostMicros Micros    `json:"upstream_cost_micros"`
}

type AnalyticsTimeProfile struct {
	Weekday        int    `json:"weekday"`
	MinuteOfDay    int    `json:"minute_of_day"`
	TariffBand     string `json:"tariff_band"`
	Requests       int64  `json:"requests"`
	TotalTokens    int64  `json:"total_tokens"`
	BillableMicros Micros `json:"billable_micros"`
}

type AnalyticsMatrixCell struct {
	DepartmentID   string `json:"department_id"`
	DepartmentName string `json:"department_name"`
	ProviderID     string `json:"provider_id"`
	ProviderName   string `json:"provider_name"`
	Requests       int64  `json:"requests"`
	TotalTokens    int64  `json:"total_tokens"`
	BillableMicros Micros `json:"billable_micros"`
}

const analyticsAgentTypeExpr = `COALESCE((
	SELECT MIN(NULLIF(BTRIM(agent_dimension.agent_type),''))
	FROM request_logs agent_dimension
	WHERE agent_dimension.tenant_id = billing_usage_facts.tenant_id
	  AND agent_dimension.request_id = billing_usage_facts.request_id
),'non-agent')`

func analyticsWhere(filter AnalyticsFilter) (string, []any, error) {
	filter.TenantID = strings.TrimSpace(filter.TenantID)
	if filter.TenantID == "" || filter.Start.IsZero() || filter.End.IsZero() || !filter.End.After(filter.Start) {
		return "", nil, ErrInvalidUsage
	}
	args := []any{filter.TenantID, filter.Start, filter.End}
	where := "tenant_id=$1 AND usage_source NOT IN ('forward_proxy','reverse_proxy') AND occurred_at >= $2 AND occurred_at < $3"
	if filter.Currency != "" {
		if filter.Currency != "USD" && filter.Currency != "CNY" {
			return "", nil, ErrInvalidUsage
		}
		args = append(args, filter.Currency)
		// 无金额的记录（未定价/用量未知/失败/释放）不带可加总的金额，按币种标签过滤会把
		// 历史请求数和 Token 数丢掉；金额仍只在所选币种内汇总。
		where += fmt.Sprintf(" AND (currency = $%d OR status IN ('unpriced','usage_unknown','failed','released'))", len(args))
	}
	if !filter.FullTenant {
		switch {
		case len(filter.TeamIDs) > 0:
			args = append(args, filter.TeamIDs)
			where += fmt.Sprintf(" AND department_id = ANY($%d)", len(args))
		case len(filter.ProjectIDs) > 0:
			args = append(args, filter.ProjectIDs)
			where += fmt.Sprintf(" AND project_id = ANY($%d)", len(args))
		case strings.TrimSpace(filter.UserID) != "":
			args = append(args, strings.TrimSpace(filter.UserID))
			where += fmt.Sprintf(" AND user_id = $%d", len(args))
		default:
			where += " AND FALSE"
		}
	}
	appendIDs := func(column string, values []string) {
		if len(values) == 0 {
			return
		}
		args = append(args, values)
		where += fmt.Sprintf(" AND %s = ANY($%d)", column, len(args))
	}
	appendIDs("department_id", filter.FilterDepartmentIDs)
	appendIDs("project_id", filter.FilterProjectIDs)
	appendIDs("user_id", filter.FilterUserIDs)
	appendIDs("model_id", filter.FilterModelIDs)
	appendIDs("provider_id", filter.FilterProviderIDs)
	if len(filter.FilterAgentTypes) > 0 {
		args = append(args, filter.FilterAgentTypes)
		where += fmt.Sprintf(" AND %s = ANY($%d)", analyticsAgentTypeExpr, len(args))
	}
	return where, args, nil
}

func (s *Store) GetAnalyticsSummary(ctx context.Context, filter AnalyticsFilter) (*AnalyticsSummary, error) {
	filter, err := s.analyticsFilterCurrency(ctx, filter)
	if err != nil {
		return nil, err
	}
	where, args, err := analyticsWhere(filter)
	if err != nil {
		return nil, err
	}
	// 先限定币种再聚合，同一 SQL 快照内不会混加不同面额。
	fallbackCurrency := filter.Currency
	args = append(args, fallbackCurrency)
	var distinctCurrencies int64
	var result AnalyticsSummary
	err = s.db.QueryRow(ctx, `
		SELECT COUNT(*)::bigint,
		       COUNT(*) FILTER (WHERE status NOT IN ('unpriced','usage_unknown'))::bigint,
		       COUNT(*) FILTER (WHERE status = 'unpriced')::bigint,
		       COUNT(*) FILTER (WHERE status = 'usage_unknown')::bigint,
		       COUNT(*) FILTER (WHERE status = 'settled')::bigint,
		       COUNT(*) FILTER (WHERE status = 'failed')::bigint,
		       COALESCE(SUM(prompt_tokens),0)::bigint,
		       COALESCE(SUM(cached_input_tokens),0)::bigint,
		       COALESCE(SUM(cache_write_input_tokens),0)::bigint,
		       COALESCE(SUM(output_tokens),0)::bigint,
		       COALESCE(SUM(reasoning_tokens),0)::bigint,
		       COALESCE(SUM(prompt_tokens+output_tokens),0)::bigint,
		       COALESCE(SUM(billable_amount_micros) FILTER (WHERE status='settled'),0)::bigint,
		       COUNT(upstream_cost_micros) FILTER (WHERE status='settled')::bigint,
		       COALESCE(SUM(upstream_cost_micros) FILTER (WHERE status='settled'),0)::bigint,
		       COALESCE(SUM(COALESCE((usage_extras->>'image_count')::bigint,0)),0)::bigint,
               COALESCE(SUM((SELECT COALESCE(SUM(value::bigint),0) FROM jsonb_each_text(COALESCE(usage_extras->'tool_calls','{}'::jsonb)))),0)::bigint,
               COALESCE(MIN(currency) FILTER (WHERE status='settled'), `+fmt.Sprintf("$%d", len(args))+`),
		       COUNT(DISTINCT currency) FILTER (WHERE status='settled')::bigint,
		       COUNT(*) FILTER (WHERE estimated)::bigint
		FROM billing_usage_facts WHERE `+where, args...).Scan(
		&result.Requests, &result.PricedRequests, &result.UnpricedRequests, &result.UsageUnknownRequests,
		&result.SettledRequests, &result.FailedRequests,
		&result.PromptTokens, &result.CachedInputTokens, &result.CacheWriteInputTokens,
		&result.OutputTokens, &result.ReasoningTokens, &result.TotalTokens,
		&result.BillableMicros, &result.UpstreamCostKnownRequests,
		&result.UpstreamCostMicros, &result.ImageCount, &result.ToolCallCount, &result.Currency, &distinctCurrencies, &result.EstimatedRequests,
	)
	if err != nil {
		return nil, fmt.Errorf("billing analytics summary: %w", err)
	}
	if distinctCurrencies > 1 {
		return nil, ErrMixedCurrency
	}
	result.OtherCurrencies, err = s.AnalyticsOtherCurrencies(ctx, filter)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// analyticsFilterCurrency 让未显式选择的统计跟随租户系统币种。
func (s *Store) analyticsFilterCurrency(ctx context.Context, filter AnalyticsFilter) (AnalyticsFilter, error) {
	filter.Currency = strings.ToUpper(strings.TrimSpace(filter.Currency))
	if filter.Currency == "" {
		currency, err := s.BillingCurrencyForTenant(ctx, filter.TenantID)
		if err != nil {
			return filter, err
		}
		filter.Currency = currency
	}
	if filter.Currency != "CNY" && filter.Currency != "USD" {
		return filter, ErrInvalidUsage
	}
	return filter, nil
}

// AnalyticsOtherCurrencies 沿用相同时间窗与权限范围，仅返回未纳入的币种名。
func (s *Store) AnalyticsOtherCurrencies(ctx context.Context, filter AnalyticsFilter) ([]string, error) {
	selected := filter.Currency
	filter.Currency = ""
	where, args, err := analyticsWhere(filter)
	if err != nil {
		return nil, err
	}
	args = append(args, selected)
	rows, err := s.db.Query(ctx, `SELECT DISTINCT currency FROM billing_usage_facts WHERE `+where+fmt.Sprintf(" AND currency<>$%d AND currency<>'' AND status NOT IN ('unpriced','usage_unknown','failed','released') ORDER BY currency", len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var currency string
		if err := rows.Scan(&currency); err != nil {
			return nil, err
		}
		result = append(result, currency)
	}
	return result, rows.Err()
}

func analyticsDimensionSQL(dimension string) (id, name, secondary string, ok bool) {
	switch dimension {
	case "department":
		return "COALESCE(department_id,'')", "COALESCE(NULLIF(department_name,''),'未归属部门')", "''", true
	case "provider", "channel":
		return "COALESCE(provider_id,'')", "COALESCE(NULLIF(provider_name,''),'未知渠道')", "COALESCE(provider_type,'')", true
	case "model":
		return "COALESCE(model_id,'')", "COALESCE(NULLIF(model_name,''),'未知模型')", "COALESCE(provider_name,'')", true
	case "project":
		return "COALESCE(project_id,'')", "COALESCE(NULLIF(project_name,''),'未归属项目')", "''", true
	case "user":
		return "COALESCE(user_id,'')", "COALESCE(NULLIF(user_name,''),'未知用户')", "COALESCE(department_name,'')", true
	case "agent", "agent_type":
		agentName := "CASE WHEN " + analyticsAgentTypeExpr + "='non-agent' THEN '非智能体调用' ELSE " + analyticsAgentTypeExpr + " END"
		return analyticsAgentTypeExpr, agentName, "''", true
	case "tariff_band":
		return "tariff_band", "tariff_band", "''", true
	default:
		return "", "", "", false
	}
}

func (s *Store) GetAnalyticsBreakdown(ctx context.Context, filter AnalyticsFilter, dimension string, limit int) ([]AnalyticsBreakdown, error) {
	idExpr, nameExpr, secondaryExpr, ok := analyticsDimensionSQL(dimension)
	if !ok {
		return nil, ErrInvalidUsage
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	filter, err := s.analyticsFilterCurrency(ctx, filter)
	if err != nil {
		return nil, err
	}
	where, args, err := analyticsWhere(filter)
	if err != nil {
		return nil, err
	}
	// Mixed-currency detection rides in the SAME statement (same snapshot) as
	// the grouped sums via a scalar subquery over the identical filter: a
	// mixed selection is rejected in Go and no rows ever leave the store.
	args = append(args, limit)
	query := fmt.Sprintf(`
		SELECT %s AS id,%s AS name,%s AS secondary,
		       COUNT(*)::bigint,COUNT(*) FILTER (WHERE status NOT IN ('unpriced','usage_unknown'))::bigint,
		       COUNT(*) FILTER (WHERE status = 'usage_unknown')::bigint,
		       COALESCE(SUM(prompt_tokens),0)::bigint,
		       COALESCE(SUM(cached_input_tokens),0)::bigint,
		       COALESCE(SUM(cache_write_input_tokens),0)::bigint,
		       COALESCE(SUM(output_tokens),0)::bigint,
		       COALESCE(SUM(reasoning_tokens),0)::bigint,
		       COALESCE(SUM(prompt_tokens+output_tokens),0)::bigint,
		       COALESCE(SUM(billable_amount_micros) FILTER (WHERE status='settled'),0)::bigint,
		       COUNT(upstream_cost_micros) FILTER (WHERE status='settled')::bigint,
		       COALESCE(SUM(upstream_cost_micros) FILTER (WHERE status='settled'),0)::bigint,
		       COALESCE(SUM(COALESCE((usage_extras->>'image_count')::bigint,0)),0)::bigint,
               COALESCE(SUM((SELECT COALESCE(SUM(value::bigint),0) FROM jsonb_each_text(COALESCE(usage_extras->'tool_calls','{}'::jsonb)))),0)::bigint,
               (SELECT COUNT(DISTINCT currency) FILTER (WHERE status='settled') FROM billing_usage_facts WHERE %s)::bigint AS selection_currencies
		FROM billing_usage_facts WHERE %s
		GROUP BY 1,2,3 ORDER BY 13 DESC,4 DESC LIMIT $%d
	`, idExpr, nameExpr, secondaryExpr, where, where, len(args))
	if dimension == "model" {
		// Enrich the already-grouped financial projection with one metadata
		// scalar. Including disabled models preserves historical labels; the
		// tenant guard and LIMIT 1 prevent leakage and duplicate financial sums.
		query = `SELECT breakdown.*, breakdown.name AS model_name,
			COALESCE((SELECT NULLIF(BTRIM(m.model_label), '')
			 FROM models m JOIN providers p ON p.id=m.provider_id
			 WHERE p.tenant_id=$1 AND (m.id=breakdown.id OR m.model_name=breakdown.name)
			 ORDER BY CASE WHEN m.id=breakdown.id THEN 0 ELSE 1 END, m.id
			 LIMIT 1), '') AS model_label
			FROM (` + query + `) AS breakdown ORDER BY 13 DESC,4 DESC`
	}
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("billing analytics breakdown: %w", err)
	}
	defer rows.Close()
	result := make([]AnalyticsBreakdown, 0)
	var total Micros
	var selectionCurrencies int64
	for rows.Next() {
		var row AnalyticsBreakdown
		scanTargets := []any{
			&row.ID, &row.Name, &row.Secondary, &row.Requests, &row.PricedRequests, &row.UsageUnknownRequests,
			&row.PromptTokens, &row.CachedInputTokens, &row.CacheWriteInputTokens,
			&row.OutputTokens, &row.ReasoningTokens, &row.TotalTokens,
			&row.BillableMicros, &row.UpstreamCostKnownRequests, &row.UpstreamCostMicros,
			&row.ImageCount, &row.ToolCallCount, &selectionCurrencies,
		}
		if dimension == "model" {
			scanTargets = append(scanTargets, &row.ModelName, &row.ModelLabel)
		}
		if err := rows.Scan(scanTargets...); err != nil {
			return nil, err
		}
		if selectionCurrencies > 1 {
			return nil, ErrMixedCurrency
		}
		total += row.BillableMicros
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if total > 0 {
		for index := range result {
			result[index].CostShare = float64(result[index].BillableMicros) / float64(total)
		}
	}
	return result, nil
}

func (s *Store) GetAnalyticsSeries(ctx context.Context, filter AnalyticsFilter, granularity string) ([]AnalyticsSeriesPoint, error) {
	if granularity != "hour" && granularity != "day" {
		return nil, ErrInvalidUsage
	}
	filter, err := s.analyticsFilterCurrency(ctx, filter)
	if err != nil {
		return nil, err
	}
	where, args, err := analyticsWhere(filter)
	if err != nil {
		return nil, err
	}
	// 按计费时区（默认北京时间）切日/切小时，桶起点仍以带时区时间返回，界面按北京时间显示不会错位一天。
	args = append(args, granularity, billingTimeZone())
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
		SELECT date_trunc($%[1]d, occurred_at AT TIME ZONE $%[2]d) AT TIME ZONE $%[2]d AS bucket,COUNT(*)::bigint,
		       COALESCE(SUM(prompt_tokens+output_tokens),0)::bigint,
		       COALESCE(SUM(billable_amount_micros) FILTER (WHERE status='settled'),0)::bigint,
		       COALESCE(SUM(upstream_cost_micros) FILTER (WHERE status='settled'),0)::bigint,
		       (SELECT COUNT(DISTINCT currency) FILTER (WHERE status='settled') FROM billing_usage_facts WHERE %s)::bigint AS selection_currencies
		FROM billing_usage_facts WHERE %s
		GROUP BY 1 ORDER BY 1
	`, len(args)-1, len(args), where, where), args...)
	if err != nil {
		return nil, fmt.Errorf("billing analytics series: %w", err)
	}
	defer rows.Close()
	result := make([]AnalyticsSeriesPoint, 0)
	var selectionCurrencies int64
	for rows.Next() {
		var row AnalyticsSeriesPoint
		if err := rows.Scan(&row.Bucket, &row.Requests, &row.TotalTokens, &row.BillableMicros, &row.UpstreamCostMicros, &selectionCurrencies); err != nil {
			return nil, err
		}
		if selectionCurrencies > 1 {
			return nil, ErrMixedCurrency
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *Store) GetAnalyticsTimeProfile(ctx context.Context, filter AnalyticsFilter, timezone string, intervalMinutes int) ([]AnalyticsTimeProfile, error) {
	if _, err := time.LoadLocation(timezone); err != nil || (intervalMinutes != 15 && intervalMinutes != 30 && intervalMinutes != 60) {
		return nil, ErrInvalidUsage
	}
	filter, err := s.analyticsFilterCurrency(ctx, filter)
	if err != nil {
		return nil, err
	}
	where, args, err := analyticsWhere(filter)
	if err != nil {
		return nil, err
	}
	args = append(args, timezone, intervalMinutes)
	tzArg, intervalArg := len(args)-1, len(args)
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
		SELECT EXTRACT(ISODOW FROM occurred_at AT TIME ZONE $%d)::int AS weekday,
		       (EXTRACT(HOUR FROM occurred_at AT TIME ZONE $%d)::int*60 +
		        FLOOR(EXTRACT(MINUTE FROM occurred_at AT TIME ZONE $%d)/$%d)::int*$%d) AS minute_of_day,
		       tariff_band,COUNT(*)::bigint,
		       COALESCE(SUM(prompt_tokens+output_tokens),0)::bigint,
		       COALESCE(SUM(billable_amount_micros) FILTER (WHERE status='settled'),0)::bigint,
		       (SELECT COUNT(DISTINCT currency) FILTER (WHERE status='settled') FROM billing_usage_facts WHERE %s)::bigint AS selection_currencies
		FROM billing_usage_facts WHERE %s
		GROUP BY 1,2,3 ORDER BY 1,2,3
	`, tzArg, tzArg, tzArg, intervalArg, intervalArg, where, where), args...)
	if err != nil {
		return nil, fmt.Errorf("billing analytics time profile: %w", err)
	}
	defer rows.Close()
	result := make([]AnalyticsTimeProfile, 0)
	var selectionCurrencies int64
	for rows.Next() {
		var row AnalyticsTimeProfile
		if err := rows.Scan(&row.Weekday, &row.MinuteOfDay, &row.TariffBand, &row.Requests, &row.TotalTokens, &row.BillableMicros, &selectionCurrencies); err != nil {
			return nil, err
		}
		if selectionCurrencies > 1 {
			return nil, ErrMixedCurrency
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *Store) GetAnalyticsDepartmentProviderMatrix(ctx context.Context, filter AnalyticsFilter) ([]AnalyticsMatrixCell, error) {
	filter, err := s.analyticsFilterCurrency(ctx, filter)
	if err != nil {
		return nil, err
	}
	where, args, err := analyticsWhere(filter)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `
		SELECT COALESCE(department_id,''),COALESCE(NULLIF(department_name,''),'未归属部门'),
		       COALESCE(provider_id,''),COALESCE(NULLIF(provider_name,''),'未知渠道'),
		       COUNT(*)::bigint,COALESCE(SUM(prompt_tokens+output_tokens),0)::bigint,
		       COALESCE(SUM(billable_amount_micros) FILTER (WHERE status='settled'),0)::bigint,
		       (SELECT COUNT(DISTINCT currency) FILTER (WHERE status='settled') FROM billing_usage_facts WHERE `+where+`)::bigint AS selection_currencies
		FROM billing_usage_facts WHERE `+where+`
		GROUP BY 1,2,3,4 ORDER BY 7 DESC,1,3
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("billing analytics department provider matrix: %w", err)
	}
	defer rows.Close()
	result := make([]AnalyticsMatrixCell, 0)
	var selectionCurrencies int64
	for rows.Next() {
		var row AnalyticsMatrixCell
		if err := rows.Scan(&row.DepartmentID, &row.DepartmentName, &row.ProviderID, &row.ProviderName, &row.Requests, &row.TotalTokens, &row.BillableMicros, &selectionCurrencies); err != nil {
			return nil, err
		}
		if selectionCurrencies > 1 {
			return nil, ErrMixedCurrency
		}
		result = append(result, row)
	}
	return result, rows.Err()
}
