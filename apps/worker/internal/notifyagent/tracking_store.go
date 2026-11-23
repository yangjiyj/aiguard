package notifyagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
	"github.com/yangjiyj/aiguard/packages/shared-go/outbox"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TrackingStore struct {
	db             *pgxpool.Pool
	maxAttempts    int
	retryBaseDelay time.Duration
	now            func() time.Time
}

type TrackingConfig struct {
	MaxAttempts    int
	RetryBaseDelay time.Duration
	Now            func() time.Time
}

type trackedNotification struct {
	TenantID    string
	OperationID string
	EventType   string
	Status      string
}

type rowQueryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func NewTrackingStore(db *pgxpool.Pool, configs ...TrackingConfig) *TrackingStore {
	cfg := TrackingConfig{}
	if len(configs) > 0 {
		cfg = configs[0]
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = outbox.DefaultMaxAttempts
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = outbox.DefaultRetryBaseDelay
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &TrackingStore{
		db: db, maxAttempts: cfg.MaxAttempts,
		retryBaseDelay: cfg.RetryBaseDelay, now: cfg.Now,
	}
}

func (s *TrackingStore) Claim(ctx context.Context, consumer string, limit int) ([]outbox.Event, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("tracking outbox db is required")
	}
	claimNow := s.now().UTC()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tracked outbox claim: %w", err)
	}
	defer tx.Rollback(ctx)

	store := outbox.NewStore(tx)
	events, err := store.ClaimAt(ctx, consumer, limit, claimNow)
	if err != nil {
		return nil, err
	}
	identities := make(map[string]trackedNotification)
	identityEvents := make(map[string][]outbox.Event)
	excluded := make(map[string]bool)
	markPoison := func(event outbox.Event, cause error) error {
		next := outbox.NextAvailableAt(claimNow, s.retryBaseDelay, event.Attempts)
		if err := store.MarkFailed(ctx, event.ID, cause, s.maxAttempts, next); err != nil {
			return fmt.Errorf("quarantine poison outbox event %q: %w", event.ID, err)
		}
		excluded[event.ID] = true
		return nil
	}
	for _, event := range events {
		identity, tracked, parseErr := trackedNotificationFromEvent(event)
		if parseErr != nil {
			if err := markPoison(event, fmt.Errorf("invalid destructive notification payload: %w", parseErr)); err != nil {
				return nil, err
			}
			continue
		}
		if tracked {
			key := notificationLockKey(identity)
			identities[key] = identity
			identityEvents[key] = append(identityEvents[key], event)
		}
	}
	keys := make([]string, 0, len(identities))
	for key := range identities {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		identity := identities[key]
		if err := lockNotification(ctx, tx, identity); err != nil {
			return nil, err
		}
		if _, err := refreshNotificationStatus(ctx, tx, identity); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("refresh claimed notification status: %w", err)
			}
			for _, event := range identityEvents[key] {
				if err := markPoison(event, errors.New("destructive notification lifecycle is missing")); err != nil {
					return nil, err
				}
			}
		}
	}
	deliverable := make([]outbox.Event, 0, len(events))
	for _, event := range events {
		if !excluded[event.ID] {
			deliverable = append(deliverable, event)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit tracked outbox claim: %w", err)
	}
	return deliverable, nil
}

func (s *TrackingStore) MarkProcessed(ctx context.Context, id string) error {
	return s.transition(ctx, id, func(store *outbox.Store) error {
		return store.MarkProcessed(ctx, id)
	})
}

func (s *TrackingStore) MarkFailed(ctx context.Context, id string, cause error, maxAttempts int, nextAvailableAt time.Time) error {
	return s.transition(ctx, id, func(store *outbox.Store) error {
		return store.MarkFailed(ctx, id, cause, maxAttempts, nextAvailableAt)
	})
}

func (s *TrackingStore) transition(ctx context.Context, id string, apply func(*outbox.Store) error) error {
	if s == nil || s.db == nil {
		return errors.New("tracking outbox db is required")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tracked outbox transition: %w", err)
	}
	defer tx.Rollback(ctx)

	identity, tracked, err := loadTrackedNotification(ctx, tx, id)
	if err != nil {
		return err
	}
	if tracked {
		if identity.Status != outbox.StatusProcessing {
			return fmt.Errorf("notification outbox %q is %q, want processing", id, identity.Status)
		}
		if err := lockNotification(ctx, tx, identity); err != nil {
			return err
		}
	}
	if err := apply(outbox.NewStore(tx)); err != nil {
		return err
	}
	if tracked {
		if _, err := refreshNotificationStatus(ctx, tx, identity); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tracked outbox transition: %w", err)
	}
	return nil
}

func loadTrackedNotification(ctx context.Context, db rowQueryer, id string) (trackedNotification, bool, error) {
	if strings.TrimSpace(id) == "" {
		return trackedNotification{}, false, errors.New("outbox event id is required")
	}
	var eventType, tenantID, status string
	var payload json.RawMessage
	if err := db.QueryRow(ctx, `
		SELECT event_type, tenant_id, status, payload_json
		FROM outbox_events
		WHERE id=$1
	`, id).Scan(&eventType, &tenantID, &status, &payload); err != nil {
		return trackedNotification{}, false, fmt.Errorf("load outbox event %q: %w", id, err)
	}
	if eventType != eventbus.EventTypeNotifyAgentDestructive {
		return trackedNotification{}, false, nil
	}
	var decoded Payload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return trackedNotification{}, false, fmt.Errorf("decode tracked notification %q: %w", id, err)
	}
	identity := trackedNotification{
		TenantID: tenantID, OperationID: strings.TrimSpace(decoded.OperationID),
		EventType: strings.TrimSpace(decoded.EventType), Status: status,
	}
	if identity.TenantID == "" || identity.OperationID == "" || identity.EventType == "" {
		return trackedNotification{}, false, fmt.Errorf("tracked notification %q identity is incomplete", id)
	}
	return identity, true, nil
}

func trackedNotificationFromEvent(event outbox.Event) (trackedNotification, bool, error) {
	if event.Type != eventbus.EventTypeNotifyAgentDestructive {
		return trackedNotification{}, false, nil
	}
	var payload Payload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return trackedNotification{}, false, fmt.Errorf("decode claimed notification %q: %w", event.ID, err)
	}
	identity := trackedNotification{
		TenantID: event.TenantID, OperationID: strings.TrimSpace(payload.OperationID),
		EventType: strings.TrimSpace(payload.EventType), Status: event.Status,
	}
	if identity.TenantID == "" || identity.OperationID == "" || identity.EventType == "" {
		return trackedNotification{}, false, fmt.Errorf("claimed notification %q identity is incomplete", event.ID)
	}
	return identity, true, nil
}

func notificationLockKey(identity trackedNotification) string {
	return strings.Join([]string{identity.TenantID, identity.OperationID, identity.EventType}, "\x1f")
}

func lockNotification(ctx context.Context, tx pgx.Tx, identity trackedNotification) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, notificationLockKey(identity)); err != nil {
		return fmt.Errorf("lock notification lifecycle: %w", err)
	}
	return nil
}

func refreshNotificationStatus(ctx context.Context, db rowQueryer, identity trackedNotification) (string, error) {
	var status string
	err := db.QueryRow(ctx, `
		WITH aggregate AS (
			SELECT CASE
				WHEN bool_or(status = 'dead') THEN 'dead'
				WHEN bool_or(status IN ('pending', 'processing')) THEN 'pending'
				WHEN bool_or(status = 'failed') THEN 'failed'
				WHEN bool_and(status = 'processed') THEN 'sent'
				ELSE 'failed'
			END AS status
			FROM outbox_events
			WHERE tenant_id=$1
			  AND event_type='notify.agent_destructive'
			  AND payload_json->>'operation_id'=$2
			  AND payload_json->>'event_type'=$3
		)
		UPDATE tool_call_logs AS logs
		SET notification_status = CASE
			WHEN logs.notification_status IN ('sent', 'dead') THEN logs.notification_status
			ELSE aggregate.status
		END
		FROM aggregate
		WHERE logs.tenant_id=$1 AND logs.operation_id=$2 AND logs.event_type=$3
		RETURNING logs.notification_status
	`, identity.TenantID, identity.OperationID, identity.EventType).Scan(&status)
	if err != nil {
		return "", fmt.Errorf("aggregate notification status: %w", err)
	}
	return status, nil
}
