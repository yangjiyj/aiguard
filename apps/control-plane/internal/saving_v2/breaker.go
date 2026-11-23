package saving_v2

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BreakerFxProvider returns current USD→CNY exchange rate.
type BreakerFxProvider interface {
	Current(ctx context.Context) (float64, error)
}

// BreakerWatermarkStore persists incremental processing progress.
type BreakerWatermarkStore interface {
	Init(ctx context.Context) error
	Get(ctx context.Context, worker string) (time.Time, error)
	Set(ctx context.Context, worker string, t time.Time) error
}

const breakerWorker = "saving_breaker"

// Breaker aggregates circuit_breaker savings from alert_inbox governor events.
// Saving per interception = average single-request cost for the tenant in the same period.
// Source: 'circuit_breaker'.
//
// Governor event types written by gateway-core (governor_integration.go):
//   - "rate_limit"  (ActionRateLimit)
//   - "pause_key"   (ActionPauseKey)
//
// These are looked for in alert_inbox.type via LIKE '%rate_limit%' OR LIKE '%pause_key%'.
type Breaker struct {
	db *pgxpool.Pool
	fx BreakerFxProvider
	wm BreakerWatermarkStore
}

// NewBreaker creates a new Breaker.
func NewBreaker(db *pgxpool.Pool, fx BreakerFxProvider, wm BreakerWatermarkStore) *Breaker {
	return &Breaker{db: db, fx: fx, wm: wm}
}

type breakerAggrow struct {
	tenantID     string
	date         time.Time
	interceptCount int
}

// RunOnce scans alert_inbox for governor interception events and writes saving_metrics(source='circuit_breaker').
// Returns the number of rows upserted.
func (b *Breaker) RunOnce(ctx context.Context) (int, error) {
	_ = b.wm.Init(ctx)
	last, err := b.wm.Get(ctx, breakerWorker)
	if err != nil {
		last = time.Now().UTC().AddDate(0, 0, -30)
	}
	now := time.Now().UTC()

	fxRate, _ := b.fx.Current(ctx)
	if fxRate <= 0 {
		fxRate = 7.20
	}

	// Count governor interception events grouped by (tenant, date).
	rows, err := b.db.Query(ctx, `
		SELECT tenant_id, DATE(created_at) AS date, COUNT(*) AS intercept_count
		FROM alert_inbox
		WHERE created_at > $1 AND created_at <= $2
		  AND (type LIKE '%rate_limit%' OR type LIKE '%pause_key%')
		GROUP BY tenant_id, DATE(created_at)
	`, last, now)
	if err != nil {
		return 0, fmt.Errorf("breaker query: %w", err)
	}
	defer rows.Close()

	var events []breakerAggrow
	for rows.Next() {
		var a breakerAggrow
		if err := rows.Scan(&a.tenantID, &a.date, &a.interceptCount); err != nil {
			continue
		}
		events = append(events, a)
	}
	rows.Close()

	rowCount := 0
	for _, a := range events {
		// Estimate average single-request cost for this tenant in the current month.
		// Use request_logs total_cost / count from the last 30 days.
		var avgCostUSD float64
		err := b.db.QueryRow(ctx, `
			SELECT CASE WHEN COUNT(*) > 0
			            THEN COALESCE(SUM(total_cost), 0) / COUNT(*)
			            ELSE 0
			       END
			FROM request_logs
			WHERE tenant_id = $1
			  AND created_at >= DATE_TRUNC('month', $2::timestamp)
			  AND created_at <= $2
		`, a.tenantID, now).Scan(&avgCostUSD)
		if err != nil {
			log.Printf("[breaker] avg cost query failed tenant=%s: %v", a.tenantID, err)
			avgCostUSD = 0
		}

		savingUSD := avgCostUSD * float64(a.interceptCount)
		if savingUSD < 0 {
			savingUSD = 0
		}
		savingCNY := savingUSD * fxRate

		_, err = b.db.Exec(ctx, `
			INSERT INTO saving_metrics (tenant_id, team_id, project_id, user_id, date, source, saving_usd, saving_cny, request_count)
			VALUES ($1, '', '', '', $2, 'circuit_breaker', $3, $4, $5)
			ON CONFLICT (tenant_id, team_id, project_id, user_id, date, source) DO UPDATE
			SET saving_usd    = saving_metrics.saving_usd    + EXCLUDED.saving_usd,
			    saving_cny    = saving_metrics.saving_cny    + EXCLUDED.saving_cny,
			    request_count = saving_metrics.request_count + EXCLUDED.request_count
		`, a.tenantID, a.date, savingUSD, savingCNY, a.interceptCount)
		if err != nil {
			log.Printf("[breaker] upsert failed tenant=%s: %v", a.tenantID, err)
			continue
		}
		rowCount++
	}

	_ = b.wm.Set(ctx, breakerWorker, now)
	return rowCount, nil
}
