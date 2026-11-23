package handler

import (
	"encoding/json"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
)

// providerMetricsDTO 是模型上游页每行的运行概况。
type providerMetricsDTO struct {
	ProviderID        string `json:"provider_id"`
	RouteCount        int    `json:"route_count"`
	AvgTTFTMs         *int64 `json:"avg_ttft_ms"`
	Samples           int    `json:"samples"`
	FailingRouteCount int    `json:"failing_route_count"`
	AuthFailures      int    `json:"auth_failures"`
}

// GetProvidersMetrics 返回各上游渠道近 30 分钟的运行指标：
// 线路数、平均首 token 延迟、失败线路数、鉴权失败数。
// 鉴权失败（401/403）>0 时前端在凭据列给出「近期鉴权失败」红标，提示 Key 可能失效。
func GetProvidersMetrics(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if deps == nil || deps.ProviderRepo == nil {
			writeError(w, "internal_error", "provider repository unavailable")
			return
		}
		metrics, err := deps.ProviderRepo.RecentProviderMetrics(r.Context(), user.TenantID, 30)
		if err != nil {
			writeError(w, "internal_error", "failed to load provider metrics")
			return
		}
		data := make([]providerMetricsDTO, 0, len(metrics))
		for providerID, m := range metrics {
			data = append(data, providerMetricsDTO{
				ProviderID:        providerID,
				RouteCount:        m.RouteCount,
				AvgTTFTMs:         m.AvgTTFTMs,
				Samples:           m.Samples,
				FailingRouteCount: m.FailingRouteCount,
				AuthFailures:      m.AuthFailures,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data, "window_minutes": 30})
	}
}
