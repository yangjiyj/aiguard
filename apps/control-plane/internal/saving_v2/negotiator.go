package saving_v2

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NegotiatorFxProvider returns current USD→CNY exchange rate.
type NegotiatorFxProvider interface {
	Current(ctx context.Context) (float64, error)
}

// NegotiatorWatermarkStore persists incremental processing progress.
type NegotiatorWatermarkStore interface {
	Init(ctx context.Context) error
	Get(ctx context.Context, worker string) (time.Time, error)
	Set(ctx context.Context, worker string, t time.Time) error
}

const negotiatorWorker = "saving_negotiator"

// Negotiator aggregates negotiated_price savings from request_logs.
// Saving = (max_competitor_input_price - actual_input_price) * input_tokens / 1M
//        + (max_competitor_output_price - actual_output_price) * output_tokens / 1M
// per request, grouped by (tenant, team, project, user, date).
type Negotiator struct {
	db *pgxpool.Pool
	fx NegotiatorFxProvider
	wm NegotiatorWatermarkStore
}

// NewNegotiator creates a new Negotiator.
func NewNegotiator(db *pgxpool.Pool, fx NegotiatorFxProvider, wm NegotiatorWatermarkStore) *Negotiator {
	return &Negotiator{db: db, fx: fx, wm: wm}
}

type negAggrow struct {
	tenantID, teamID, projectID, userID string
	date                                time.Time
	savingUSD                           float64
	requestCount                        int
}

// RunOnce incrementally processes request_logs and writes saving_metrics(source='negotiated_price').
// Returns the number of saving_metrics rows upserted.
func (n *Negotiator) RunOnce(ctx context.Context) (int, error) {
	_ = n.wm.Init(ctx)
	last, err := n.wm.Get(ctx, negotiatorWorker)
	if err != nil {
		last = time.Now().UTC().AddDate(0, 0, -30)
	}
	now := time.Now().UTC()

	fxRate, _ := n.fx.Current(ctx)
	if fxRate <= 0 {
		fxRate = 7.20
	}

	// Query request_logs with provider/model pricing joined.
	rows, err := n.db.Query(ctx, `
		SELECT
			rl.tenant_id,
			COALESCE(p.team_id, '') AS team_id,
			rl.project_id,
			COALESCE(rl.user_id, '') AS user_id,
			DATE(rl.created_at) AS date,
			COALESCE(rl.input_tokens, 0),
			COALESCE(rl.output_tokens, 0),
			COALESCE(rl.provider_id, '') AS provider_id,
			COALESCE(rl.model_id, '') AS model_id,
			COALESCE(m.pricing_json, '{}')
		FROM request_logs rl
		LEFT JOIN models m ON m.id = rl.model_id
		LEFT JOIN projects p ON p.id = rl.project_id
		WHERE rl.created_at > $1 AND rl.created_at <= $2
		  AND rl.model_id IS NOT NULL
		  AND rl.provider_id IS NOT NULL
	`, last, now)
	if err != nil {
		return 0, fmt.Errorf("negotiator query: %w", err)
	}
	defer rows.Close()

	agg := make(map[string]negAggrow)
	for rows.Next() {
		var tenantID, teamID, projectID, userID, providerID, modelID string
		var date time.Time
		var inputTokens, outputTokens int
		var pricingJSON []byte

		if err := rows.Scan(&tenantID, &teamID, &projectID, &userID, &date,
			&inputTokens, &outputTokens, &providerID, &modelID, &pricingJSON); err != nil {
			continue
		}

		dateStr := date.Format("2006-01-02")

		// Get actual pricing for this model/provider from pricing_json.
		actualInput, actualOutput := pricingFromJSON(pricingJSON)

		// Get max competitor prices for this model on this date (excluding this provider).
		var maxInput, maxOutput float64
		if err := n.db.QueryRow(ctx, `
			SELECT COALESCE(MAX(input_price), 0)
			FROM provider_price_snapshots
			WHERE model_id = $1 AND snapshot_date = $2 AND provider_id != $3
		`, modelID, dateStr, providerID).Scan(&maxInput); err != nil {
			continue
		}
		if err := n.db.QueryRow(ctx, `
			SELECT COALESCE(MAX(output_price), 0)
			FROM provider_price_snapshots
			WHERE model_id = $1 AND snapshot_date = $2 AND provider_id != $3
		`, modelID, dateStr, providerID).Scan(&maxOutput); err != nil {
			continue
		}

		// If no competing providers with higher prices, saving = 0.
		savingInput := (maxInput - actualInput) * float64(inputTokens) / 1_000_000
		savingOutput := (maxOutput - actualOutput) * float64(outputTokens) / 1_000_000
		saving := savingInput + savingOutput
		if saving <= 0 {
			continue
		}

		key := tenantID + "|" + teamID + "|" + projectID + "|" + userID + "|" + dateStr + "|negotiated_price"
		a := agg[key]
		a.tenantID = tenantID
		a.teamID = teamID
		a.projectID = projectID
		a.userID = userID
		a.date = date
		a.savingUSD += saving
		a.requestCount++
		agg[key] = a
	}
	rows.Close()

	rowCount := 0
	for _, a := range agg {
		savingCNY := a.savingUSD * fxRate
		_, err := n.db.Exec(ctx, `
			INSERT INTO saving_metrics (tenant_id, team_id, project_id, user_id, date, source, saving_usd, saving_cny, request_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (tenant_id, team_id, project_id, user_id, date, source) DO UPDATE
			SET saving_usd    = saving_metrics.saving_usd    + EXCLUDED.saving_usd,
			    saving_cny    = saving_metrics.saving_cny    + EXCLUDED.saving_cny,
			    request_count = saving_metrics.request_count + EXCLUDED.request_count
		`, a.tenantID, a.teamID, a.projectID, a.userID, a.date, "negotiated_price",
			a.savingUSD, savingCNY, a.requestCount)
		if err != nil {
			log.Printf("[negotiator] upsert failed: %v", err)
			continue
		}
		rowCount++
	}

	_ = n.wm.Set(ctx, negotiatorWorker, now)
	return rowCount, nil
}
