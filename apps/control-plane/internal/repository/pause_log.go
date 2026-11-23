package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PauseLog records a key-prefix pause/unpause lifecycle event.
type PauseLog struct {
	ID           string
	KeyPrefix    string
	TenantID     string
	PausedBy     string
	PausedReason string
	PausedAt     time.Time
	UnpausedBy   *string
	UnpausedAt   *time.Time
}

// PauseLogRepository handles pause_log database operations.
type PauseLogRepository struct {
	db *pgxpool.Pool
}

// NewPauseLogRepository creates a new PauseLogRepository.
func NewPauseLogRepository(db *pgxpool.Pool) *PauseLogRepository {
	return &PauseLogRepository{db: db}
}

// Pause inserts a new pause record and returns the created entry.
func (r *PauseLogRepository) Pause(ctx context.Context, id, tenantID, keyPrefix, by, reason string) (*PauseLog, error) {
	now := time.Now().UTC()
	_, err := r.db.Exec(ctx, `
		INSERT INTO pause_log (id, key_prefix, tenant_id, paused_by, paused_reason, paused_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, id, keyPrefix, tenantID, nullableString(by), nullableString(reason), now)
	if err != nil {
		return nil, err
	}
	return &PauseLog{
		ID:           id,
		KeyPrefix:    keyPrefix,
		TenantID:     tenantID,
		PausedBy:     by,
		PausedReason: reason,
		PausedAt:     now,
	}, nil
}

// Unpause marks the most recent active pause record for the given key_prefix
// as resolved. Returns pgx.ErrNoRows if no active record is found.
func (r *PauseLogRepository) Unpause(ctx context.Context, keyPrefix, by string) error {
	now := time.Now().UTC()
	result, err := r.db.Exec(ctx, `
		UPDATE pause_log
		SET unpaused_by  = $1,
		    unpaused_at  = $2
		WHERE key_prefix = $3
		  AND unpaused_at IS NULL
	`, by, now, keyPrefix)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ListActive returns all pause records that have not yet been unpaused for the
// given tenant, ordered by paused_at descending.
func (r *PauseLogRepository) ListActive(ctx context.Context, tenantID string) ([]*PauseLog, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, key_prefix, tenant_id, paused_by, paused_reason,
		       paused_at, unpaused_by, unpaused_at
		FROM   pause_log
		WHERE  tenant_id = $1
		  AND  unpaused_at IS NULL
		ORDER  BY paused_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPauseLogs(rows)
}

// List returns pause log entries for the tenant, limited to the most recent
// records. Pass 0 for no limit.
func (r *PauseLogRepository) List(ctx context.Context, tenantID string, limit int) ([]*PauseLog, error) {
	q := `
		SELECT id, key_prefix, tenant_id, paused_by, paused_reason,
		       paused_at, unpaused_by, unpaused_at
		FROM   pause_log
		WHERE  tenant_id = $1
		ORDER  BY paused_at DESC
	`
	args := []interface{}{tenantID}
	if limit > 0 {
		q += " LIMIT $2"
		args = append(args, limit)
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPauseLogs(rows)
}

// scanPauseLogs scans pgx rows into PauseLog slice.
func scanPauseLogs(rows pgx.Rows) ([]*PauseLog, error) {
	var out []*PauseLog
	for rows.Next() {
		var p PauseLog
		var pausedBy, pausedReason *string
		if err := rows.Scan(
			&p.ID, &p.KeyPrefix, &p.TenantID,
			&pausedBy, &pausedReason,
			&p.PausedAt, &p.UnpausedBy, &p.UnpausedAt,
		); err != nil {
			return nil, err
		}
		if pausedBy != nil {
			p.PausedBy = *pausedBy
		}
		if pausedReason != nil {
			p.PausedReason = *pausedReason
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}
