package handler

import (
	"encoding/json"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
)

// providerPriceSnapshotDTO 显式 snake_case 序列化（仓库结构体无 json tag）。
type providerPriceSnapshotDTO struct {
	SnapshotDate string  `json:"snapshot_date"`
	ProviderID   string  `json:"provider_id"`
	ModelID      string  `json:"model_id"`
	InputPrice   float64 `json:"input_price"`
	OutputPrice  float64 `json:"output_price"`
	Currency     string  `json:"currency"`
}

// ListProviderPriceSnapshots handles GET /admin/v1/provider-price-snapshots
// 只读：供应商价格快照历史（P2-2, task 1.9）。
// 可选 query 参数 date=YYYY-MM-DD；缺省取最新日期。
// 返回 {dates, date, snapshots}：dates 为日期下拉选项，date 为当前所选，snapshots 为该日明细。
func ListProviderPriceSnapshots(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.ProviderPriceSnapshotRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "price snapshots not configured")
			return
		}

		dates, err := deps.ProviderPriceSnapshotRepo.ListDates(r.Context())
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		date := r.URL.Query().Get("date")
		if date == "" && len(dates) > 0 {
			date = dates[0]
		}

		snapshots := []providerPriceSnapshotDTO{}
		if date != "" {
			rows, err := deps.ProviderPriceSnapshotRepo.ListByDate(r.Context(), date)
			if err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
				return
			}
			for _, s := range rows {
				snapshots = append(snapshots, providerPriceSnapshotDTO{
					SnapshotDate: s.SnapshotDate,
					ProviderID:   s.ProviderID,
					ModelID:      s.ModelID,
					InputPrice:   s.InputPrice,
					OutputPrice:  s.OutputPrice,
					Currency:     s.Currency,
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"dates":     dates,
			"date":      date,
			"snapshots": snapshots,
		})
	}
}
