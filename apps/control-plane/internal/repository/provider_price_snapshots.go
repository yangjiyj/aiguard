package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ProviderPriceSnapshot represents one row in provider_price_snapshots.
type ProviderPriceSnapshot struct {
	SnapshotDate string  // YYYY-MM-DD
	ProviderID   string
	ModelID      string
	InputPrice   float64
	OutputPrice  float64
	Currency     string
}

// ProviderPriceSnapshotRepository handles provider_price_snapshots DB ops.
type ProviderPriceSnapshotRepository struct {
	db *pgxpool.Pool
}

// NewProviderPriceSnapshotRepository creates a new repository.
func NewProviderPriceSnapshotRepository(db *pgxpool.Pool) *ProviderPriceSnapshotRepository {
	return &ProviderPriceSnapshotRepository{db: db}
}

// Upsert inserts or updates a snapshot row.
// ON CONFLICT (snapshot_date, provider_id, model_id) DO UPDATE.
func (r *ProviderPriceSnapshotRepository) Upsert(ctx context.Context, s *ProviderPriceSnapshot) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO provider_price_snapshots
			(snapshot_date, provider_id, model_id, input_price, output_price, currency)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (snapshot_date, provider_id, model_id) DO UPDATE
		SET input_price  = EXCLUDED.input_price,
		    output_price = EXCLUDED.output_price,
		    currency     = EXCLUDED.currency
	`, s.SnapshotDate, s.ProviderID, s.ModelID, s.InputPrice, s.OutputPrice, s.Currency)
	if err != nil {
		return fmt.Errorf("provider_price_snapshots upsert: %w", err)
	}
	return nil
}

// ListByDate returns all snapshots for the given date (YYYY-MM-DD).
func (r *ProviderPriceSnapshotRepository) ListByDate(ctx context.Context, date string) ([]*ProviderPriceSnapshot, error) {
	rows, err := r.db.Query(ctx, `
		SELECT snapshot_date, provider_id, model_id,
		       COALESCE(input_price, 0), COALESCE(output_price, 0), COALESCE(currency, 'USD')
		FROM provider_price_snapshots
		WHERE snapshot_date = $1
		ORDER BY provider_id, model_id
	`, date)
	if err != nil {
		return nil, fmt.Errorf("provider_price_snapshots list: %w", err)
	}
	defer rows.Close()

	var result []*ProviderPriceSnapshot
	for rows.Next() {
		s := &ProviderPriceSnapshot{}
		var snapDate time.Time
		if err := rows.Scan(&snapDate, &s.ProviderID, &s.ModelID,
			&s.InputPrice, &s.OutputPrice, &s.Currency); err != nil {
			return nil, err
		}
		s.SnapshotDate = snapDate.Format("2006-01-02")
		result = append(result, s)
	}
	return result, rows.Err()
}

// GetMaxInputPriceByModelAndDate returns the maximum input_price across all providers
// for a given model_id on a given date. Returns 0 and pgx.ErrNoRows if no rows found.
func (r *ProviderPriceSnapshotRepository) GetMaxInputPriceByModelAndDate(ctx context.Context, modelID, date string) (float64, error) {
	var maxPrice float64
	err := r.db.QueryRow(ctx, `
		SELECT COALESCE(MAX(input_price), 0)
		FROM provider_price_snapshots
		WHERE model_id = $1 AND snapshot_date = $2
	`, modelID, date).Scan(&maxPrice)
	if err != nil {
		if err == pgx.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("get max input price: %w", err)
	}
	return maxPrice, nil
}

// GetMaxOutputPriceByModelAndDate returns the maximum output_price across all providers.
func (r *ProviderPriceSnapshotRepository) GetMaxOutputPriceByModelAndDate(ctx context.Context, modelID, date string) (float64, error) {
	var maxPrice float64
	err := r.db.QueryRow(ctx, `
		SELECT COALESCE(MAX(output_price), 0)
		FROM provider_price_snapshots
		WHERE model_id = $1 AND snapshot_date = $2
	`, modelID, date).Scan(&maxPrice)
	if err != nil {
		if err == pgx.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("get max output price: %w", err)
	}
	return maxPrice, nil
}

// ListDates 返回快照表中所有去重的日期（YYYY-MM-DD），按日期倒序（最新在前）。
func (r *ProviderPriceSnapshotRepository) ListDates(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx, `SELECT DISTINCT snapshot_date FROM provider_price_snapshots ORDER BY snapshot_date DESC`)
	if err != nil {
		return nil, fmt.Errorf("provider_price_snapshots list dates: %w", err)
	}
	defer rows.Close()
	dates := []string{}
	for rows.Next() {
		var d time.Time
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		dates = append(dates, d.Format("2006-01-02"))
	}
	return dates, rows.Err()
}
