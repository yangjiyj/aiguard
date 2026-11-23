package outbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	StatusPending    = "pending"
	StatusProcessing = "processing"
	StatusProcessed  = "processed"
	StatusFailed     = "failed"
	StatusDead       = "dead"

	DefaultClaimLimit     = 100
	DefaultMaxAttempts    = 8
	DefaultRetryBaseDelay = 5 * time.Second
)

type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

type Store struct {
	db DB
}

type Event struct {
	ID            string
	Type          string
	TenantID      string
	TraceID       string
	RequestID     string
	SchemaVersion string
	Payload       json.RawMessage
	Status        string
	Attempts      int
	AvailableAt   time.Time
	LockedAt      time.Time
	LockedBy      string
	LastError     string
	ProcessedAt   time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Stats struct {
	Pending            int64
	Processing         int64
	Failed             int64
	Dead               int64
	OldestPendingAgeMS int64
}

func NewStore(db DB) *Store {
	return &Store{db: db}
}

func (s *Store) Enqueue(ctx context.Context, event eventbus.Event) error {
	if s == nil || s.db == nil {
		return errors.New("outbox db is required")
	}
	if err := event.Validate(); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO outbox_events (
			id, tenant_id, event_type, schema_version, request_id, trace_id,
			payload_json, status, available_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7::jsonb, 'pending', $8, $8, $8)
		ON CONFLICT (id) DO NOTHING
	`, event.ID, event.TenantID, event.Type, event.SchemaVersion, event.RequestID, event.TraceID, payloadOrObject(event.Payload), event.OccurredAt)
	if err != nil {
		return fmt.Errorf("enqueue outbox event: %w", err)
	}
	return nil
}

func (s *Store) Claim(ctx context.Context, consumer string, limit int) ([]Event, error) {
	return s.ClaimAt(ctx, consumer, limit, time.Now().UTC())
}

func (s *Store) ClaimAt(ctx context.Context, consumer string, limit int, now time.Time) ([]Event, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("outbox db is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	consumer = strings.TrimSpace(consumer)
	if consumer == "" {
		return nil, errors.New("outbox consumer is required")
	}
	if limit <= 0 || limit > 1000 {
		limit = DefaultClaimLimit
	}

	rows, err := s.db.Query(ctx, `
		WITH next_events AS (
			SELECT id
			FROM outbox_events
			WHERE (status IN ('pending', 'failed') AND available_at <= $3)
			   OR (status = 'processing' AND locked_at <= $3 - INTERVAL '5 minutes')
			ORDER BY available_at ASC, created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		UPDATE outbox_events oe
		SET status = 'processing',
		    attempts = attempts + 1,
		    locked_at = $3,
		    locked_by = $1,
		    updated_at = $3
		FROM next_events
		WHERE oe.id = next_events.id
		RETURNING oe.id, oe.event_type, oe.tenant_id, COALESCE(oe.trace_id, ''),
		          COALESCE(oe.request_id, ''), oe.schema_version, oe.payload_json,
		          oe.status, oe.attempts, oe.available_at,
		          oe.locked_at, COALESCE(oe.locked_by, ''), COALESCE(oe.last_error, ''),
		          oe.processed_at, oe.created_at, oe.updated_at
	`, consumer, limit, now)
	if err != nil {
		return nil, fmt.Errorf("claim outbox events: %w", err)
	}
	defer rows.Close()

	events := make([]Event, 0, limit)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func NextAvailableAt(now time.Time, retryBaseDelay time.Duration, attempts int) time.Time {
	if now.IsZero() {
		now = time.Now()
	}
	if retryBaseDelay <= 0 {
		retryBaseDelay = DefaultRetryBaseDelay
	}
	if attempts < 1 {
		attempts = 1
	}
	delay := retryBaseDelay
	for i := 1; i < attempts && delay < time.Minute; i++ {
		delay *= 2
	}
	if delay > time.Minute {
		delay = time.Minute
	}
	return now.UTC().Add(delay)
}

func (s *Store) MarkProcessed(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return errors.New("outbox db is required")
	}
	if strings.TrimSpace(id) == "" {
		return errors.New("outbox event id is required")
	}
	_, err := s.db.Exec(ctx, `
		UPDATE outbox_events
		SET status = 'processed', processed_at = NOW(), locked_at = NULL, locked_by = NULL, updated_at = NOW()
		WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("mark outbox event processed: %w", err)
	}
	return nil
}

func (s *Store) MarkFailed(ctx context.Context, id string, cause error, maxAttempts int, nextAvailableAt time.Time) error {
	if s == nil || s.db == nil {
		return errors.New("outbox db is required")
	}
	if strings.TrimSpace(id) == "" {
		return errors.New("outbox event id is required")
	}
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	if nextAvailableAt.IsZero() {
		nextAvailableAt = time.Now().UTC()
	}
	lastError := ""
	if cause != nil {
		lastError = cause.Error()
	}
	_, err := s.db.Exec(ctx, `
		UPDATE outbox_events
		SET status = CASE WHEN attempts >= $3 THEN 'dead' ELSE 'failed' END,
		    available_at = CASE WHEN attempts >= $3 THEN available_at ELSE $4 END,
		    last_error = NULLIF($2, ''),
		    locked_at = NULL,
		    locked_by = NULL,
		    updated_at = NOW()
		WHERE id = $1
	`, id, lastError, maxAttempts, nextAvailableAt.UTC())
	if err != nil {
		return fmt.Errorf("mark outbox event failed: %w", err)
	}
	return nil
}

func (s *Store) LoadStats(ctx context.Context) (Stats, error) {
	if s == nil || s.db == nil {
		return Stats{}, errors.New("outbox db is required")
	}
	rows, err := s.db.Query(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status = 'pending'),
			COUNT(*) FILTER (WHERE status = 'processing'),
			COUNT(*) FILTER (WHERE status = 'failed'),
			COUNT(*) FILTER (WHERE status = 'dead'),
			COALESCE((EXTRACT(EPOCH FROM (NOW() - MIN(created_at))) * 1000)::bigint, 0)
		FROM outbox_events
		WHERE status IN ('pending', 'processing', 'failed', 'dead')
	`)
	if err != nil {
		return Stats{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return Stats{}, rows.Err()
	}
	var stats Stats
	if err := rows.Scan(&stats.Pending, &stats.Processing, &stats.Failed, &stats.Dead, &stats.OldestPendingAgeMS); err != nil {
		return Stats{}, err
	}
	return stats, rows.Err()
}

func scanEvent(rows pgx.Rows) (Event, error) {
	var event Event
	var payload []byte
	var lockedAt, processedAt sql.NullTime
	if err := rows.Scan(
		&event.ID,
		&event.Type,
		&event.TenantID,
		&event.TraceID,
		&event.RequestID,
		&event.SchemaVersion,
		&payload,
		&event.Status,
		&event.Attempts,
		&event.AvailableAt,
		&lockedAt,
		&event.LockedBy,
		&event.LastError,
		&processedAt,
		&event.CreatedAt,
		&event.UpdatedAt,
	); err != nil {
		return Event{}, err
	}
	event.Payload = append(json.RawMessage(nil), payload...)
	if lockedAt.Valid {
		event.LockedAt = lockedAt.Time
	}
	if processedAt.Valid {
		event.ProcessedAt = processedAt.Time
	}
	return event, nil
}

func payloadOrObject(payload json.RawMessage) string {
	if len(payload) == 0 {
		return "{}"
	}
	return string(payload)
}
