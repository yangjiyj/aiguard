package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CostGovernanceConfig represents per-tenant cost governance configuration.
type CostGovernanceConfig struct {
	TenantID                  string
	SelfResearchSavingMonthly float64
	LaborHourlyRate           float64
	LaborHoursPerOp           float64
	UpdatedAt                 time.Time
}

// CostGovernanceConfigRepository handles cost_governance_config DB ops.
type CostGovernanceConfigRepository struct {
	db *pgxpool.Pool
}

// NewCostGovernanceConfigRepository creates a new repository.
func NewCostGovernanceConfigRepository(db *pgxpool.Pool) *CostGovernanceConfigRepository {
	return &CostGovernanceConfigRepository{db: db}
}

// defaultConfig returns the default config for any tenant.
func defaultConfig(tenantID string) *CostGovernanceConfig {
	return &CostGovernanceConfig{
		TenantID:                  tenantID,
		SelfResearchSavingMonthly: 0,
		LaborHourlyRate:           250,
		LaborHoursPerOp:           0.5,
		UpdatedAt:                 time.Time{},
	}
}

// Get returns the config for the tenant. Returns default values if no row exists.
func (r *CostGovernanceConfigRepository) Get(ctx context.Context, tenantID string) (*CostGovernanceConfig, error) {
	cfg := &CostGovernanceConfig{}
	err := r.db.QueryRow(ctx, `
		SELECT tenant_id,
		       COALESCE(self_research_saving_monthly, 0),
		       COALESCE(labor_hourly_rate, 250),
		       COALESCE(labor_hours_per_op, 0.5),
		       updated_at
		FROM cost_governance_config
		WHERE tenant_id = $1
	`, tenantID).Scan(
		&cfg.TenantID,
		&cfg.SelfResearchSavingMonthly,
		&cfg.LaborHourlyRate,
		&cfg.LaborHoursPerOp,
		&cfg.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return defaultConfig(tenantID), nil
		}
		return nil, fmt.Errorf("cost_governance_config get: %w", err)
	}
	return cfg, nil
}

// Upsert inserts or updates the config for the tenant.
func (r *CostGovernanceConfigRepository) Upsert(ctx context.Context, cfg *CostGovernanceConfig) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO cost_governance_config
			(tenant_id, self_research_saving_monthly, labor_hourly_rate, labor_hours_per_op, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (tenant_id) DO UPDATE
		SET self_research_saving_monthly = EXCLUDED.self_research_saving_monthly,
		    labor_hourly_rate            = EXCLUDED.labor_hourly_rate,
		    labor_hours_per_op           = EXCLUDED.labor_hours_per_op,
		    updated_at                   = NOW()
	`, cfg.TenantID, cfg.SelfResearchSavingMonthly, cfg.LaborHourlyRate, cfg.LaborHoursPerOp)
	if err != nil {
		return fmt.Errorf("cost_governance_config upsert: %w", err)
	}
	return nil
}

// GetLaborConfig returns the labor hourly rate and hours per op for a tenant.
// Implements saving_v2.LaborConfigReader interface.
func (r *CostGovernanceConfigRepository) GetLaborConfig(ctx context.Context, tenantID string) (hourlyRateCNY, hoursPerOp float64, err error) {
	cfg, err := r.Get(ctx, tenantID)
	if err != nil {
		return 0, 0, err
	}
	return cfg.LaborHourlyRate, cfg.LaborHoursPerOp, nil
}
