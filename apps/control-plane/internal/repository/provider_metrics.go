package repository

import (
	"context"
	"fmt"
)

// ProviderRecentMetrics 是一个上游渠道的运行概况：
// 线路数（启用模型数）、近窗口的平均首 token 延迟、失败线路数与鉴权失败数。
// 鉴权失败（401/403）单独计数，用于在模型上游页提示「Key 可能失效」。
type ProviderRecentMetrics struct {
	RouteCount        int
	AvgTTFTMs         *int64
	Samples           int
	FailingRouteCount int
	AuthFailures      int
}

// RecentProviderMetrics 按渠道聚合近 windowMinutes 分钟的运行指标。
// 没有流量的渠道 AvgTTFTMs 为 nil、计数为 0，前端显示「-」。
func (r *ProviderRepository) RecentProviderMetrics(ctx context.Context, tenantID string, windowMinutes int) (map[string]ProviderRecentMetrics, error) {
	if windowMinutes <= 0 || windowMinutes > 1440 {
		windowMinutes = 30
	}
	rows, err := r.db.Query(ctx, `
		WITH route_counts AS (
			SELECT m.provider_id, COUNT(*)::int AS route_count
			FROM models m
			JOIN providers p ON p.id = m.provider_id
			WHERE p.tenant_id = $1 AND m.status = 'active'
			GROUP BY m.provider_id
		),
		recent AS (
			SELECT rl.provider_id,
			       AVG(rl.upstream_ttft_ms)::bigint AS avg_ttft,
			       COUNT(*)::int AS samples,
			       COUNT(DISTINCT rl.model_id) FILTER (WHERE rl.request_status = 'failed')::int AS failing_routes,
			       COUNT(*) FILTER (WHERE rl.upstream_status_code IN (401, 403))::int AS auth_failures
			FROM request_logs rl
			WHERE rl.tenant_id = $1
			  AND rl.provider_id IS NOT NULL AND rl.provider_id <> ''
			  AND rl.created_at > now() - make_interval(mins => $2)
			GROUP BY rl.provider_id
		)
		SELECT p.id,
		       COALESCE(rc.route_count, 0),
		       r.avg_ttft,
		       COALESCE(r.samples, 0),
		       COALESCE(r.failing_routes, 0),
		       COALESCE(r.auth_failures, 0)
		FROM providers p
		LEFT JOIN route_counts rc ON rc.provider_id = p.id
		LEFT JOIN recent r ON r.provider_id = p.id
		WHERE p.tenant_id = $1`, tenantID, windowMinutes)
	if err != nil {
		return nil, fmt.Errorf("recent provider metrics: %w", err)
	}
	defer rows.Close()
	out := make(map[string]ProviderRecentMetrics)
	for rows.Next() {
		var providerID string
		var item ProviderRecentMetrics
		if err := rows.Scan(&providerID, &item.RouteCount, &item.AvgTTFTMs, &item.Samples, &item.FailingRouteCount, &item.AuthFailures); err != nil {
			return nil, fmt.Errorf("scan recent provider metrics: %w", err)
		}
		out[providerID] = item
	}
	return out, rows.Err()
}
