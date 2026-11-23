package repository

import (
	"context"
	"encoding/json"
	"fmt"
)

// RouteRecentMetrics 是一条线路（model × provider）在近窗口内的运行指标，
// 用于模型路由页展示每条线路的首 token 延迟与失败情况。
type RouteRecentMetrics struct {
	ModelName  string
	ProviderID string
	AvgTTFTMs  *int64
	Samples    int
	Failures   int
}

// RoutePrice 是一条线路的定价（美元 / 百万 Token，与模型管理定价口径一致）。
type RoutePrice struct {
	InputPerMillion  *float64
	OutputPerMillion *float64
}

// RecentRouteMetrics 聚合近 windowMinutes 分钟内每条线路的平均首 token 延迟、
// 样本数和失败数。上游没有记录 TTFT 的线路 AvgTTFTMs 为 nil，前端显示「-」。
func (r *ModelRoutingRepository) RecentRouteMetrics(ctx context.Context, tenantID string, windowMinutes int) (map[string]RouteRecentMetrics, error) {
	if windowMinutes <= 0 || windowMinutes > 1440 {
		windowMinutes = 30
	}
	rows, err := r.db.Query(ctx, `
		SELECT m.model_name, rl.provider_id,
		       AVG(rl.upstream_ttft_ms)::bigint AS avg_ttft,
		       COUNT(*)::int AS samples,
		       COUNT(*) FILTER (WHERE rl.request_status = 'failed')::int AS failures
		FROM request_logs rl
		JOIN models m ON m.id = rl.model_id
		WHERE rl.tenant_id = $1
		  AND rl.provider_id IS NOT NULL AND rl.provider_id <> ''
		  AND rl.created_at > now() - make_interval(mins => $2)
		GROUP BY m.model_name, rl.provider_id`, tenantID, windowMinutes)
	if err != nil {
		return nil, fmt.Errorf("recent route metrics: %w", err)
	}
	defer rows.Close()
	out := make(map[string]RouteRecentMetrics)
	for rows.Next() {
		var item RouteRecentMetrics
		if err := rows.Scan(&item.ModelName, &item.ProviderID, &item.AvgTTFTMs, &item.Samples, &item.Failures); err != nil {
			return nil, fmt.Errorf("scan recent route metrics: %w", err)
		}
		out[routeMetricsKey(item.ModelName, item.ProviderID)] = item
	}
	return out, rows.Err()
}

// RoutePrices 返回当前启用模型在各渠道下的定价，键为 routeMetricsKey(model, provider)。
// 未定价线路不出现在结果中，前端标注「未定价，不参与成本比较」。
func (r *ModelRoutingRepository) RoutePrices(ctx context.Context, tenantID string) (map[string]RoutePrice, error) {
	rows, err := r.db.Query(ctx, `
		SELECT m.model_name, m.provider_id, COALESCE(m.pricing_json, '{}'::jsonb)
		FROM models m
		JOIN providers p ON p.id = m.provider_id
		WHERE p.tenant_id = $1 AND m.status = 'active'`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("route prices: %w", err)
	}
	defer rows.Close()
	out := make(map[string]RoutePrice)
	for rows.Next() {
		var modelName, providerID string
		var raw []byte
		if err := rows.Scan(&modelName, &providerID, &raw); err != nil {
			return nil, fmt.Errorf("scan route price: %w", err)
		}
		var pricing struct {
			Input  *float64 `json:"input"`
			Output *float64 `json:"output"`
		}
		if err := json.Unmarshal(raw, &pricing); err != nil {
			continue
		}
		out[routeMetricsKey(modelName, providerID)] = RoutePrice{InputPerMillion: pricing.Input, OutputPerMillion: pricing.Output}
	}
	return out, rows.Err()
}

// TodayFallbackCount 统计今天（Asia/Shanghai 日界，与明细口径一致）发生
// 自动切换（备用线路救场）的请求数——这是「容灾在工作」的直接证据。
func (r *ModelRoutingRepository) TodayFallbackCount(ctx context.Context, tenantID string) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)::int
		FROM request_logs
		WHERE tenant_id = $1
		  AND created_at >= (date_trunc('day', now() AT TIME ZONE 'Asia/Shanghai') AT TIME ZONE 'Asia/Shanghai')
		  AND COALESCE(routing_decision_json #>> '{model_route_v2,fallback_used}', 'false') = 'true'`, tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("today fallback count: %w", err)
	}
	return count, nil
}

func routeMetricsKey(modelName, providerID string) string {
	return modelName + "\x00" + providerID
}

// RouteMetricsKeyFor 暴露键构造，便于 handler 组装展示数据。
func RouteMetricsKeyFor(modelName, providerID string) string {
	return routeMetricsKey(modelName, providerID)
}
