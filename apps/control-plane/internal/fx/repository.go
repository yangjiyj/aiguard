package fx

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository handles fx_rates DB operations.
type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// Insert inserts a new fx rate record. ratePPM is converted to DECIMAL inside
// PostgreSQL so the stored value is exactly ratePPM / 1e6.
func (r *Repository) Insert(ctx context.Context, base, target string, ratePPM int64, eff time.Time, by string) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO fx_rates (base_currency, target_currency, rate, effective_at, created_by)
		VALUES ($1, $2, $3::numeric / 1000000, $4, $5)`, base, target, ratePPM, eff, by)
	return err
}

// LatestEffective returns the most recent rate (ppm) effective at or before `at`.
func (r *Repository) LatestEffective(ctx context.Context, at time.Time) (int64, error) {
	var ratePPM int64
	err := r.db.QueryRow(ctx, `
		SELECT (rate * 1000000)::bigint FROM fx_rates
		WHERE effective_at <= $1 ORDER BY effective_at DESC LIMIT 1`, at).Scan(&ratePPM)
	if err != nil {
		return 0, err
	}
	return ratePPM, nil
}

// History returns the last `limit` rates ordered by effective_at DESC.
func (r *Repository) History(ctx context.Context, limit int) ([]Rate, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, base_currency, target_currency, (rate * 1000000)::bigint, effective_at, COALESCE(created_by,''), created_at
		FROM fx_rates ORDER BY effective_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rate
	for rows.Next() {
		var rec Rate
		if err := rows.Scan(&rec.ID, &rec.BaseCurrency, &rec.TargetCurrency, &rec.RatePPM, &rec.EffectiveAt, &rec.CreatedBy, &rec.CreatedAt); err != nil {
			return nil, err
		}
		rec.Rate = FormatRatePPM(rec.RatePPM)
		out = append(out, rec)
	}
	return out, rows.Err()
}
