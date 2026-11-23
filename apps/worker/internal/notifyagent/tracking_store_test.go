package notifyagent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setupTrackingStoreTestDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("TOOL_CALL_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TOOL_CALL_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "notify_tracking_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if _, err := db.Exec(ctx, `
		CREATE TABLE tool_call_logs (
			tenant_id varchar(64) NOT NULL,
			operation_id varchar(80) NOT NULL,
			event_type varchar(64) NOT NULL,
			notification_status varchar(16),
			PRIMARY KEY (tenant_id, operation_id, event_type)
		);
		CREATE TABLE outbox_events (
			id varchar(96) PRIMARY KEY,
			tenant_id varchar(64) NOT NULL,
			event_type varchar(128) NOT NULL,
			schema_version varchar(16) NOT NULL DEFAULT 'v1',
			request_id varchar(64),
			trace_id varchar(128),
			payload_json jsonb NOT NULL,
			status varchar(16) NOT NULL,
			attempts integer NOT NULL DEFAULT 0,
			available_at timestamptz NOT NULL DEFAULT now(),
			locked_at timestamptz,
			locked_by varchar(128),
			last_error text,
			processed_at timestamptz,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now()
		);
	`); err != nil {
		t.Fatal(err)
	}
	return db, ctx
}

func seedTrackedNotification(t *testing.T, db *pgxpool.Pool, ctx context.Context, operationID string, states ...string) []string {
	t.Helper()
	if _, err := db.Exec(ctx, `
		INSERT INTO tool_call_logs (tenant_id, operation_id, event_type, notification_status)
		VALUES ('tenant-1', $1, 'tool_attempt_blocked', 'pending')
	`, operationID); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(states))
	for i, status := range states {
		id := fmt.Sprintf("outbox-%s-%d", operationID, i)
		ids = append(ids, id)
		if _, err := db.Exec(ctx, `
			INSERT INTO outbox_events (id, tenant_id, event_type, payload_json, status, attempts, locked_at, locked_by)
			VALUES (
				$1, 'tenant-1', 'notify.agent_destructive',
				jsonb_build_object('operation_id', $2::text, 'event_type', 'tool_attempt_blocked', 'channel_id', $3::text),
				$4::text, CASE WHEN $4::text = 'processing' THEN 1 ELSE 0 END,
				CASE WHEN $4::text = 'processing' THEN now() ELSE NULL END,
				CASE WHEN $4::text = 'processing' THEN 'worker-test' ELSE NULL END
			)
		`, id, operationID, fmt.Sprintf("channel-%d", i), status); err != nil {
			t.Fatal(err)
		}
	}
	return ids
}

func readNotificationStatus(t *testing.T, db *pgxpool.Pool, ctx context.Context, operationID string) string {
	t.Helper()
	var status string
	if err := db.QueryRow(ctx, `
		SELECT notification_status FROM tool_call_logs
		WHERE tenant_id='tenant-1' AND operation_id=$1 AND event_type='tool_attempt_blocked'
	`, operationID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestTrackingStoreAggregatesAllChannelsAcrossRetryAndDeadLetter(t *testing.T) {
	db, ctx := setupTrackingStoreTestDB(t)
	store := NewTrackingStore(db)
	ids := seedTrackedNotification(t, db, ctx, "op-retry", "processing", "processing")
	if err := store.MarkProcessed(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	if got := readNotificationStatus(t, db, ctx, "op-retry"); got != "pending" {
		t.Fatalf("one processed channel with another processing = %q, want pending", got)
	}
	if err := store.MarkFailed(ctx, ids[1], errors.New("temporary failure"), 3, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := readNotificationStatus(t, db, ctx, "op-retry"); got != "failed" {
		t.Fatalf("processed + failed channels = %q, want failed", got)
	}
	claimed, err := store.Claim(ctx, "worker-retry", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].ID != ids[1] {
		t.Fatalf("retry claim = %+v", claimed)
	}
	if got := readNotificationStatus(t, db, ctx, "op-retry"); got != "pending" {
		t.Fatalf("retry processing aggregate = %q, want pending", got)
	}
	if err := store.MarkProcessed(ctx, ids[1]); err != nil {
		t.Fatal(err)
	}
	if got := readNotificationStatus(t, db, ctx, "op-retry"); got != "sent" {
		t.Fatalf("all processed channels = %q, want sent", got)
	}

	deadIDs := seedTrackedNotification(t, db, ctx, "op-dead", "processing", "pending")
	if _, err := db.Exec(ctx, `UPDATE outbox_events SET attempts=3 WHERE id=$1`, deadIDs[0]); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkFailed(ctx, deadIDs[0], errors.New("permanent failure"), 3, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := readNotificationStatus(t, db, ctx, "op-dead"); got != "dead" {
		t.Fatalf("dead + pending channels = %q, want dead", got)
	}
}

func TestTrackingStoreRollsBackProcessedWhenNotificationStatusCannotBeUpdated(t *testing.T) {
	db, ctx := setupTrackingStoreTestDB(t)
	store := NewTrackingStore(db)
	if _, err := db.Exec(ctx, `
		INSERT INTO outbox_events (id, tenant_id, event_type, payload_json, status, attempts, locked_at, locked_by)
		VALUES (
			'outbox-orphan', 'tenant-1', 'notify.agent_destructive',
			'{"operation_id":"op-missing","event_type":"tool_attempt_blocked","channel_id":"channel-1"}',
			'processing', 1, now(), 'worker-test'
		)
	`); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkProcessed(ctx, "outbox-orphan"); err == nil {
		t.Fatal("expected missing lifecycle event to reject processed transition")
	}
	var status string
	if err := db.QueryRow(ctx, `SELECT status FROM outbox_events WHERE id='outbox-orphan'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "processing" {
		t.Fatalf("orphan outbox status = %q, want rollback to processing", status)
	}
}

type outboxClaimState struct {
	Status      string
	Attempts    int
	AvailableAt time.Time
	LockedAt    sql.NullTime
	LockedBy    sql.NullString
}

func readOutboxClaimStates(t *testing.T, db *pgxpool.Pool, ctx context.Context) map[string]outboxClaimState {
	t.Helper()
	rows, err := db.Query(ctx, `
		SELECT id, status, attempts, available_at, locked_at, locked_by
		FROM outbox_events
		ORDER BY id
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	states := make(map[string]outboxClaimState)
	for rows.Next() {
		var id string
		var state outboxClaimState
		if err := rows.Scan(&id, &state.Status, &state.Attempts, &state.AvailableAt, &state.LockedAt, &state.LockedBy); err != nil {
			t.Fatal(err)
		}
		states[id] = state
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return states
}

func TestTrackingStoreClaimQuarantinesPoisonAndReturnsHealthyBatch(t *testing.T) {
	db, ctx := setupTrackingStoreTestDB(t)
	now := time.Now().UTC().Truncate(time.Microsecond).Add(time.Second)
	validIDs := seedTrackedNotification(t, db, ctx, "op-valid", "pending")
	if _, err := db.Exec(ctx, `
		INSERT INTO outbox_events (
			id, tenant_id, event_type, payload_json, status, attempts, available_at, created_at, updated_at
		) VALUES
			('poison-orphan', 'tenant-claim', 'notify.agent_destructive',
			 '{"operation_id":"op-missing","event_type":"tool_attempt_blocked","channel_id":"channel-1"}',
			 'pending', 0, now() - interval '1 minute', now() - interval '1 minute', now()),
			('poison-malformed', 'tenant-claim', 'notify.agent_destructive',
			 '{"operation_id":7,"event_type":"tool_attempt_blocked"}',
			 'pending', 0, now() - interval '1 minute', now() - interval '1 minute', now()),
			('ordinary-event', 'tenant-claim', 'security.audit', '{}',
			 'pending', 0, now() - interval '1 minute', now() - interval '1 minute', now())
	`); err != nil {
		t.Fatal(err)
	}

	store := NewTrackingStore(db, TrackingConfig{
		MaxAttempts: 3, RetryBaseDelay: 5 * time.Second,
		Now: func() time.Time { return now },
	})
	claimed, err := store.Claim(ctx, "worker-poison", 10)
	if err != nil {
		t.Fatal(err)
	}
	claimedIDs := make(map[string]bool)
	for _, event := range claimed {
		claimedIDs[event.ID] = true
	}
	if !claimedIDs["ordinary-event"] || !claimedIDs[validIDs[0]] || len(claimedIDs) != 2 {
		t.Fatalf("healthy claimed events = %+v", claimed)
	}
	for _, id := range []string{"poison-orphan", "poison-malformed"} {
		state := readOutboxClaimStates(t, db, ctx)[id]
		if state.Status != "failed" || state.Attempts != 1 ||
			!state.AvailableAt.Equal(now.Add(5*time.Second)) ||
			state.LockedAt.Valid || state.LockedBy.Valid {
			t.Fatalf("poison %s first claim state=%+v", id, state)
		}
	}
	if err := store.MarkProcessed(ctx, "ordinary-event"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkProcessed(ctx, validIDs[0]); err != nil {
		t.Fatal(err)
	}
	if got := readNotificationStatus(t, db, ctx, "op-valid"); got != "sent" {
		t.Fatalf("valid destructive lifecycle status=%q", got)
	}

	assertNoProcessorEvents := func(stage string) {
		claimed, err := store.Claim(ctx, "worker-poison", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(claimed) != 0 {
			t.Fatalf("%s returned poison to processor: %+v", stage, claimed)
		}
	}
	assertNoProcessorEvents("before first backoff")
	for _, id := range []string{"poison-orphan", "poison-malformed"} {
		if state := readOutboxClaimStates(t, db, ctx)[id]; state.Attempts != 1 {
			t.Fatalf("poison %s retried before backoff: %+v", id, state)
		}
	}

	now = now.Add(5 * time.Second)
	assertNoProcessorEvents("second poison attempt")
	secondStates := readOutboxClaimStates(t, db, ctx)
	for _, id := range []string{"poison-orphan", "poison-malformed"} {
		state := secondStates[id]
		if state.Status != "failed" || state.Attempts != 2 ||
			!state.AvailableAt.Equal(now.Add(10*time.Second)) {
			t.Fatalf("poison %s second state=%+v", id, state)
		}
	}
	assertNoProcessorEvents("before second backoff")
	for _, id := range []string{"poison-orphan", "poison-malformed"} {
		if state := readOutboxClaimStates(t, db, ctx)[id]; state.Attempts != 2 {
			t.Fatalf("poison %s retried before second backoff: %+v", id, state)
		}
	}

	now = now.Add(10 * time.Second)
	assertNoProcessorEvents("terminal poison attempt")
	states := readOutboxClaimStates(t, db, ctx)
	for _, id := range []string{"poison-orphan", "poison-malformed"} {
		state := states[id]
		if state.Status != "dead" || state.Attempts != 3 || state.LockedAt.Valid || state.LockedBy.Valid {
			t.Fatalf("poison %s terminal state=%+v", id, state)
		}
	}
}

func TestTrackingStoreClaimRollsBackWholeBatchOnProjectionSQLFailure(t *testing.T) {
	db, ctx := setupTrackingStoreTestDB(t)
	validIDs := seedTrackedNotification(t, db, ctx, "op-sql-failure", "pending")
	if _, err := db.Exec(ctx, `
		INSERT INTO outbox_events (
			id, tenant_id, event_type, payload_json, status, attempts, available_at, created_at, updated_at
		) VALUES (
			'ordinary-event', 'tenant-claim', 'security.audit', '{}',
			'pending', 0, now() - interval '1 minute', now() - interval '1 minute', now()
		);
		CREATE FUNCTION reject_notification_projection() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected projection failure'; END $$;
		CREATE TRIGGER reject_notification_projection
			BEFORE UPDATE ON tool_call_logs
			FOR EACH ROW EXECUTE FUNCTION reject_notification_projection()
	`); err != nil {
		t.Fatal(err)
	}
	before := readOutboxClaimStates(t, db, ctx)
	store := NewTrackingStore(db)
	if claimed, err := store.Claim(ctx, "worker-sql-failure", 10); err == nil {
		t.Fatalf("Claim succeeded during projection SQL failure: %+v", claimed)
	}
	after := readOutboxClaimStates(t, db, ctx)
	for _, id := range []string{"ordinary-event", validIDs[0]} {
		want, got := before[id], after[id]
		if got.Status != want.Status || got.Attempts != want.Attempts ||
			got.LockedAt.Valid != want.LockedAt.Valid || got.LockedBy.Valid != want.LockedBy.Valid {
			t.Fatalf("outbox %s changed after SQL rollback: before=%+v after=%+v", id, want, got)
		}
	}
}
