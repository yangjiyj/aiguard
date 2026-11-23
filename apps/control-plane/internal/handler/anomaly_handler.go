package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// AnomalyEventRepo is the interface for anomaly_events persistence.
type AnomalyEventRepo interface {
	ListByTenant(ctx context.Context, tenantID, dimension string, sinceDays int) ([]*repository.AnomalyEvent, error)
	Ack(ctx context.Context, id string) error
}

// AnomalyScanner is the interface for the anomaly detection scanner.
type AnomalyScanner interface {
	RunOnce(ctx context.Context) (int, error)
}

// ListAnomalies handles GET /admin/v1/anomalies
// Query params: range=30&dimension=
func ListAnomalies(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.AnomalyEventRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "anomaly module not configured")
			return
		}

		sinceDays := 30
		if s := r.URL.Query().Get("range"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				sinceDays = n
			}
		}
		dimension := r.URL.Query().Get("dimension")

		items, err := deps.AnomalyEventRepo.ListByTenant(r.Context(), user.TenantID, dimension, sinceDays)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if items == nil {
			items = []*repository.AnomalyEvent{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"items": items,
			"total": len(items),
		})
	}
}

// AckAnomaly handles POST /admin/v1/anomalies/{id}/ack
func AckAnomaly(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.AnomalyEventRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "anomaly module not configured")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}

		if err := deps.AnomalyEventRepo.Ack(r.Context(), id); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "anomaly.ack", map[string]interface{}{"anomaly_id": id}, "anomaly", id)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}
}
