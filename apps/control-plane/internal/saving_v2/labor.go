package saving_v2

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// LaborFxProvider returns current USD→CNY exchange rate.
type LaborFxProvider interface {
	Current(ctx context.Context) (float64, error)
}

// LaborWatermarkStore persists incremental processing progress.
type LaborWatermarkStore interface {
	Init(ctx context.Context) error
	Get(ctx context.Context, worker string) (time.Time, error)
	Set(ctx context.Context, worker string, t time.Time) error
}

// LaborConfigReader reads per-tenant cost_governance_config for hourly rate / hours per op.
type LaborConfigReader interface {
	GetLaborConfig(ctx context.Context, tenantID string) (hourlyRateCNY, hoursPerOp float64, err error)
}

const laborWorker = "saving_labor"

// defaultLaborHourlyRate and defaultLaborHoursPerOp are fallbacks when no config exists.
const defaultLaborHourlyRate = 250.0 // CNY/hour
const defaultLaborHoursPerOp = 0.5   // hours per operation

// Labor aggregates key_mgmt_labor savings from audit_operations.
// Source: 'key_mgmt_labor'.
//
// Qualifying action_types (automation replaces these manual ops):
//   - budget.pause_key / budget.unpause_key
//   - quota_policy.update
//   - notify_channel.create / notify_channel.update / notify_channel.delete
//
// Saving per op (CNY) = labor_hours_per_op × labor_hourly_rate (from cost_governance_config or defaults).
// saving_cny = ops_count × saving_per_op
// saving_usd = saving_cny / fxRate
type Labor struct {
	db           *pgxpool.Pool
	fx           LaborFxProvider
	wm           LaborWatermarkStore
	configReader LaborConfigReader
}

// NewLabor creates a new Labor with optional configReader (nil → use defaults always).
func NewLabor(db *pgxpool.Pool, fx LaborFxProvider, wm LaborWatermarkStore, cr LaborConfigReader) *Labor {
	return &Labor{db: db, fx: fx, wm: wm, configReader: cr}
}

// laborQualifiedActions is the set of action_types that count as automated labor savings.
var laborQualifiedActions = []string{
	"budget.pause_key",
	"budget.unpause_key",
	"quota_policy.update",
	"notify_channel.create",
	"notify_channel.update",
	"notify_channel.delete",
}

// RunOnce scans audit_operations and writes saving_metrics(source='key_mgmt_labor').
// Returns the number of rows upserted.
func (l *Labor) RunOnce(ctx context.Context) (int, error) {
	_ = l.wm.Init(ctx)
	last, err := l.wm.Get(ctx, laborWorker)
	if err != nil {
		last = time.Now().UTC().AddDate(0, 0, -30)
	}
	now := time.Now().UTC()

	fxRate, _ := l.fx.Current(ctx)
	if fxRate <= 0 {
		fxRate = 7.20
	}

	// Build placeholder list for IN clause.
	// Using explicit list since it's small and fixed.
	rows, err := l.db.Query(ctx, `
		SELECT u.tenant_id, DATE(ao.created_at) AS date, COUNT(*) AS op_count
		FROM audit_operations ao
		JOIN users u ON u.id = ao.user_id
		WHERE ao.created_at > $1 AND ao.created_at <= $2
		  AND ao.action_type IN (
		      'budget.pause_key', 'budget.unpause_key',
		      'quota_policy.update',
		      'notify_channel.create', 'notify_channel.update', 'notify_channel.delete'
		  )
		GROUP BY u.tenant_id, DATE(ao.created_at)
	`, last, now)
	if err != nil {
		return 0, fmt.Errorf("labor query: %w", err)
	}
	defer rows.Close()

	type laborAgg struct {
		tenantID string
		date     time.Time
		opCount  int
	}
	var aggRows []laborAgg
	for rows.Next() {
		var a laborAgg
		if err := rows.Scan(&a.tenantID, &a.date, &a.opCount); err != nil {
			continue
		}
		aggRows = append(aggRows, a)
	}
	rows.Close()

	rowCount := 0
	for _, a := range aggRows {
		// Get per-tenant config or defaults.
		hourlyRate := defaultLaborHourlyRate
		hoursPerOp := defaultLaborHoursPerOp
		if l.configReader != nil {
			if h, p, err := l.configReader.GetLaborConfig(ctx, a.tenantID); err == nil {
				if h > 0 {
					hourlyRate = h
				}
				if p > 0 {
					hoursPerOp = p
				}
			}
		}

		savingCNY := float64(a.opCount) * hoursPerOp * hourlyRate
		savingUSD := 0.0
		if fxRate > 0 {
			savingUSD = savingCNY / fxRate
		}

		_, err = l.db.Exec(ctx, `
			INSERT INTO saving_metrics (tenant_id, team_id, project_id, user_id, date, source, saving_usd, saving_cny, request_count)
			VALUES ($1, '', '', '', $2, 'key_mgmt_labor', $3, $4, $5)
			ON CONFLICT (tenant_id, team_id, project_id, user_id, date, source) DO UPDATE
			SET saving_usd    = saving_metrics.saving_usd    + EXCLUDED.saving_usd,
			    saving_cny    = saving_metrics.saving_cny    + EXCLUDED.saving_cny,
			    request_count = saving_metrics.request_count + EXCLUDED.request_count
		`, a.tenantID, a.date, savingUSD, savingCNY, a.opCount)
		if err != nil {
			log.Printf("[labor] upsert failed tenant=%s: %v", a.tenantID, err)
			continue
		}
		rowCount++
	}

	_ = l.wm.Set(ctx, laborWorker, now)
	return rowCount, nil
}
