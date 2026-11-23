package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// SavingsConfigRepo is the interface for cost_governance_config persistence.
type SavingsConfigRepo interface {
	Get(ctx context.Context, tenantID string) (*repository.CostGovernanceConfig, error)
	Upsert(ctx context.Context, cfg *repository.CostGovernanceConfig) error
}

// GetSavingsConfig handles GET /admin/v1/savings/config
func GetSavingsConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		cfg, err := deps.SavingsConfigRepo.Get(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	}
}

// UpdateSavingsConfig handles PUT /admin/v1/savings/config
func UpdateSavingsConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}

		var req struct {
			SelfResearchSavingMonthly *float64 `json:"self_research_saving_monthly"`
			LaborHourlyRate           *float64 `json:"labor_hourly_rate"`
			LaborHoursPerOp           *float64 `json:"labor_hours_per_op"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		// Load current (or default) config and apply partial updates.
		cfg, err := deps.SavingsConfigRepo.Get(r.Context(), user.TenantID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		cfg.TenantID = user.TenantID
		if req.SelfResearchSavingMonthly != nil {
			cfg.SelfResearchSavingMonthly = *req.SelfResearchSavingMonthly
		}
		if req.LaborHourlyRate != nil {
			cfg.LaborHourlyRate = *req.LaborHourlyRate
		}
		if req.LaborHoursPerOp != nil {
			cfg.LaborHoursPerOp = *req.LaborHoursPerOp
		}

		if err := deps.SavingsConfigRepo.Upsert(r.Context(), cfg); err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "savings_config.update", map[string]any{
			"self_research_saving_monthly": cfg.SelfResearchSavingMonthly,
			"labor_hourly_rate":            cfg.LaborHourlyRate,
			"labor_hours_per_op":           cfg.LaborHoursPerOp,
		}, "savings_config", user.TenantID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	}
}
