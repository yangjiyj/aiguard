package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/forecast"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// ForecastJobRepo is the interface for forecast_jobs persistence.
type ForecastJobRepo interface {
	Create(ctx context.Context, job *repository.ForecastJob) error
	Get(ctx context.Context, id string) (*repository.ForecastJob, error)
	ListByTenant(ctx context.Context, tenantID string, limit int) ([]*repository.ForecastJob, error)
	ClaimPending(ctx context.Context) (*repository.ForecastJob, error)
	Finish(ctx context.Context, id, status string, result map[string]any, errMsg string) error
}

// ForecastWorker is the interface for the async forecast worker.
type ForecastWorker interface {
	RunPending(ctx context.Context) (int, error)
}

// CreateForecastJob handles POST /admin/v1/forecast/jobs
func CreateForecastJob(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.ForecastJobRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "forecast module not configured")
			return
		}

		var req struct {
			RangeDays   int                   `json:"range_days"`
			QuotaParams forecast.QuotaParams  `json:"quota_params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if req.RangeDays <= 0 {
			req.RangeDays = 30
		}

		jobID := "fcst_" + uuid.New().String()[:12]
		job := &repository.ForecastJob{
			ID:       jobID,
			TenantID: user.TenantID,
			ParamsJSON: map[string]any{
				"range_days":   req.RangeDays,
				"quota_params": req.QuotaParams,
			},
			CreatedBy: user.ID,
		}

		if err := deps.ForecastJobRepo.Create(r.Context(), job); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "forecast.create", map[string]interface{}{
			"job_id":    jobID,
			"range_days": req.RangeDays,
		}, "forecast_job", jobID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":     jobID,
			"status": "pending",
		})
	}
}

// ListForecastJobs handles GET /admin/v1/forecast/jobs
func ListForecastJobs(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.ForecastJobRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "forecast module not configured")
			return
		}

		jobs, err := deps.ForecastJobRepo.ListByTenant(r.Context(), user.TenantID, 50)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if jobs == nil {
			jobs = []*repository.ForecastJob{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"items": jobs,
			"total": len(jobs),
		})
	}
}

// GetForecastJob handles GET /admin/v1/forecast/jobs/{id}
func GetForecastJob(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.ForecastJobRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "forecast module not configured")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}

		job, err := deps.ForecastJobRepo.Get(r.Context(), id)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if job == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "forecast job not found")
			return
		}
		// Enforce tenant isolation
		if job.TenantID != user.TenantID {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "forecast job not found")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(job)
	}
}
