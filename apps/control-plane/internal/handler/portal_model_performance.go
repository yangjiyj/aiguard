package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/modelops"
)

type PortalModelPerformanceReader interface {
	PortalPerformance(context.Context, string, int, []string) (modelops.ModelPerformanceReport, error)
}

// GetPortalModelPerformance 是门户「模型」页与对话页模型选择器的性能读模型。BFF 通过重复的
// ?model= 传入员工授权模型；响应只含租户级按模型聚合，不含渠道和个人数据。
func GetPortalModelPerformance(reader PortalModelPerformanceReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		if reader == nil {
			portalNotConfigured(w, "model performance")
			return
		}
		q := r.URL.Query()
		models := q["model"]
		if len(models) > 500 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "too many models")
			return
		}
		window := 168
		if raw := q.Get("window_hours"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || (n != 24 && n != 168) {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "window_hours must be 24 or 168")
				return
			}
			window = n
		}
		report, err := reader.PortalPerformance(r.Context(), tenantID, window, models)
		if errors.Is(err, modelops.ErrInvalid) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid model performance query")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "model_performance_unavailable", "model performance is unavailable")
			return
		}
		writeJSON(w, report)
	}
}
