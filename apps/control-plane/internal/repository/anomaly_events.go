package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AnomalyEvent represents a row in the anomaly_events table.
type AnomalyEvent struct {
	ID           string
	TenantID     string
	DetectedDate string         // YYYY-MM-DD
	Dimension    string         // absolute_spike | dod | yoy | new_model | key_surge
	ScopeType    string         // '' for tenant-level, 'model' or 'key' for scoped
	ScopeID      string         // '' for tenant-level
	Baseline     float64
	Actual       float64
	Severity     string         // info | warning | high | critical
	DetailJSON   map[string]any
	AckedAt      *time.Time
	CreatedAt    time.Time
}

// AnomalyEventRepository handles anomaly_events database operations.
type AnomalyEventRepository struct {
	db *pgxpool.Pool
}

// NewAnomalyEventRepository creates a new AnomalyEventRepository.
func NewAnomalyEventRepository(db *pgxpool.Pool) *AnomalyEventRepository {
	return &AnomalyEventRepository{db: db}
}

// UpsertIfNew inserts a new anomaly event if no duplicate exists.
// Returns (isNew bool, err error). Uses ON CONFLICT DO NOTHING on the unique
// constraint (tenant_id, detected_date, dimension, scope_type, scope_id).
func (r *AnomalyEventRepository) UpsertIfNew(ctx context.Context, e *AnomalyEvent) (bool, error) {
	detailBytes, err := json.Marshal(e.DetailJSON)
	if err != nil {
		return false, fmt.Errorf("marshal detail_json: %w", err)
	}
	// scope_type and scope_id use empty string (not NULL) to satisfy UNIQUE constraint
	scopeType := e.ScopeType
	scopeID := e.ScopeID
	tag, err := r.db.Exec(ctx, `
		INSERT INTO anomaly_events
			(id, tenant_id, detected_date, dimension, scope_type, scope_id,
			 baseline, actual, severity, detail_json, created_at)
		VALUES ($1, $2, $3::date, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)
		ON CONFLICT (tenant_id, detected_date, dimension, scope_type, scope_id) DO NOTHING
	`, e.ID, e.TenantID, e.DetectedDate, e.Dimension, scopeType, scopeID,
		e.Baseline, e.Actual, e.Severity, string(detailBytes), time.Now().UTC())
	if err != nil {
		return false, fmt.Errorf("upsert anomaly_event: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ListByTenant returns anomaly events for a tenant filtered by dimension (empty = all)
// and limited to the last sinceDays days, newest first.
func (r *AnomalyEventRepository) ListByTenant(ctx context.Context, tenantID, dimension string, sinceDays int) ([]*AnomalyEvent, error) {
	q := `
		SELECT id, tenant_id, detected_date, dimension, scope_type, scope_id,
		       baseline, actual, severity, detail_json, acked_at, created_at
		FROM anomaly_events
		WHERE tenant_id = $1
		  AND detected_date >= CURRENT_DATE - $2::int * INTERVAL '1 day'
	`
	args := []any{tenantID, sinceDays}
	if dimension != "" {
		q += " AND dimension = $3"
		args = append(args, dimension)
	}
	q += " ORDER BY detected_date DESC, created_at DESC"

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list anomaly_events: %w", err)
	}
	defer rows.Close()

	var result []*AnomalyEvent
	for rows.Next() {
		var ev AnomalyEvent
		var detailRaw []byte
		var detectedDate time.Time
		if err := rows.Scan(
			&ev.ID, &ev.TenantID, &detectedDate, &ev.Dimension,
			&ev.ScopeType, &ev.ScopeID, &ev.Baseline, &ev.Actual,
			&ev.Severity, &detailRaw, &ev.AckedAt, &ev.CreatedAt,
		); err != nil {
			return nil, err
		}
		ev.DetectedDate = detectedDate.Format("2006-01-02")
		if len(detailRaw) > 0 {
			_ = json.Unmarshal(detailRaw, &ev.DetailJSON)
		}
		result = append(result, &ev)
	}
	return result, rows.Err()
}

// Ack sets acked_at = now for the given anomaly event id.
func (r *AnomalyEventRepository) Ack(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE anomaly_events SET acked_at = $1 WHERE id = $2`,
		time.Now().UTC(), id,
	)
	return err
}
