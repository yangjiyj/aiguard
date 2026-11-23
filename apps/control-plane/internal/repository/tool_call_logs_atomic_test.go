package repository

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateDestructiveLifecycleRollsBackOutboxFailureAndRetriesIdempotently(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	createDestructiveAtomicFixture(t, db)
	_, err := db.Exec(ctx, `
		CREATE FUNCTION reject_destructive_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected outbox failure'; END $$;
		CREATE TRIGGER reject_destructive_outbox
			BEFORE INSERT ON outbox_events
			FOR EACH ROW EXECUTE FUNCTION reject_destructive_outbox()
	`)
	if err != nil {
		t.Fatal(err)
	}

	entry := atomicDestructiveEntry("op-atomic-outbox")
	repo := NewToolCallLogRepository(db)
	if err := repo.CreateDestructiveLifecycle(ctx, entry); err == nil {
		t.Fatal("expected injected outbox failure")
	}
	assertDestructiveAtomicCounts(t, db, entry.OperationID, 0, 0)

	if _, err := db.Exec(ctx, "DROP TRIGGER reject_destructive_outbox ON outbox_events"); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateDestructiveLifecycle(ctx, entry); err != nil {
		t.Fatal(err)
	}
	retry := *entry
	retry.ID = ""
	retry.RequestID = "req-reconnect"
	if err := repo.CreateDestructiveLifecycle(ctx, &retry); err != nil {
		t.Fatal(err)
	}
	assertDestructiveAtomicCounts(t, db, entry.OperationID, 1, 1)
	if retry.ID != entry.ID || retry.PublicEventID != entry.PublicEventID ||
		retry.NotificationStatus != "pending" {
		t.Fatalf("stable retry mismatch: first=%+v retry=%+v", entry, retry)
	}
}

func TestCreateDestructiveLifecycleRollsBackStatusFailure(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	createDestructiveAtomicFixture(t, db)
	_, err := db.Exec(ctx, `
		CREATE FUNCTION reject_destructive_status() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.notification_status = 'pending' THEN
				RAISE EXCEPTION 'injected status failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER reject_destructive_status
			BEFORE UPDATE ON tool_call_logs
			FOR EACH ROW EXECUTE FUNCTION reject_destructive_status()
	`)
	if err != nil {
		t.Fatal(err)
	}

	entry := atomicDestructiveEntry("op-atomic-status")
	repo := NewToolCallLogRepository(db)
	if err := repo.CreateDestructiveLifecycle(ctx, entry); err == nil {
		t.Fatal("expected injected status failure")
	}
	assertDestructiveAtomicCounts(t, db, entry.OperationID, 0, 0)
}

func createDestructiveAtomicFixture(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	_, err := db.Exec(context.Background(), `
		CREATE TABLE notify_channels (
			id varchar(64) PRIMARY KEY,
			tenant_id varchar(64) NOT NULL,
			config_json jsonb NOT NULL,
			enabled boolean NOT NULL
		);
		CREATE TABLE outbox_events (
			id varchar(96) PRIMARY KEY,
			tenant_id varchar(64) NOT NULL,
			event_type varchar(128) NOT NULL,
			schema_version varchar(16) NOT NULL,
			request_id varchar(128),
			trace_id varchar(128),
			payload_json jsonb NOT NULL,
			status varchar(16) NOT NULL,
			available_at timestamptz NOT NULL,
			created_at timestamptz NOT NULL,
			updated_at timestamptz NOT NULL
		);
		INSERT INTO notify_channels (id, tenant_id, config_json, enabled)
		VALUES ('channel-atomic', 'tenant-atomic', '{}', true)
	`)
	if err != nil {
		t.Fatal(err)
	}
}

func atomicDestructiveEntry(operationID string) *ToolCallLog {
	return &ToolCallLog{
		RequestID: "req-atomic", TenantID: "tenant-atomic",
		ToolName: "shell_command", ToolType: "system", RiskLevel: "high",
		Status: "blocked", EventKind: "invocation_proposed",
		OperationID: operationID, EventType: "tool_attempt_blocked",
		RiskCategory: "destructive_change", RiskSubcategory: "filesystem_delete",
		ReasonSummary: "deterministic_destructive_operation",
		TargetSummary: "filesystem_delete:1-targets", FinalAction: "block",
		NotificationRequired: true, Confidence: 1,
		NotifyChannelIDs: []string{"channel-atomic"},
	}
}

func assertDestructiveAtomicCounts(t *testing.T, db *pgxpool.Pool, operationID string, wantLogs, wantOutbox int) {
	t.Helper()
	var logs, outbox int
	if err := db.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM tool_call_logs WHERE operation_id=$1),
			(SELECT count(*) FROM outbox_events WHERE payload_json->>'operation_id'=$1)
	`, operationID).Scan(&logs, &outbox); err != nil {
		t.Fatal(err)
	}
	if logs != wantLogs || outbox != wantOutbox {
		t.Fatalf("operation=%s lifecycle=%d/%d outbox=%d/%d", operationID, logs, wantLogs, outbox, wantOutbox)
	}
}
