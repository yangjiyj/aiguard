package budget

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Watermark persists incremental processing progress for background workers.
// Each worker identifies itself by a unique name and records the last
// processed timestamp so restarts can resume without reprocessing.
type Watermark struct {
	db *pgxpool.Pool
}

// NewWatermark creates a new Watermark backed by the given PostgreSQL pool.
func NewWatermark(db *pgxpool.Pool) *Watermark { return &Watermark{db: db} }

// Init creates the watermarks table if it does not already exist.
func (w *Watermark) Init(ctx context.Context) error {
	_, err := w.db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS watermarks (
			worker_name        VARCHAR(64) PRIMARY KEY,
			last_processed_at  TIMESTAMP WITH TIME ZONE NOT NULL,
			updated_at         TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`)
	return err
}

// Get returns the last processed timestamp for the given worker.
// Returns (time.Time{}, pgx.ErrNoRows) if no record exists yet.
func (w *Watermark) Get(ctx context.Context, worker string) (time.Time, error) {
	var t time.Time
	err := w.db.QueryRow(ctx,
		`SELECT last_processed_at FROM watermarks WHERE worker_name = $1`, worker,
	).Scan(&t)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, pgx.ErrNoRows
		}
		return time.Time{}, err
	}
	return t, nil
}

// Set upserts the last processed timestamp for the given worker.
func (w *Watermark) Set(ctx context.Context, worker string, t time.Time) error {
	_, err := w.db.Exec(ctx, `
		INSERT INTO watermarks (worker_name, last_processed_at)
		VALUES ($1, $2)
		ON CONFLICT (worker_name) DO UPDATE
			SET last_processed_at = EXCLUDED.last_processed_at,
			    updated_at        = NOW()
	`, worker, t)
	return err
}
