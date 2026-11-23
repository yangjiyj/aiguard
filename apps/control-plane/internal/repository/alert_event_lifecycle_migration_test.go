package repository

import (
	"context"
	"os"
	"strings"
	"testing"
)

const alertLifecycleMigration = "../../../../deploy/migrations/816_security_event_delivery_disposition.sql"
const alertLifecycleDesign = "../../../../docs/superpowers/plans/2026-08-29-alert-delivery-disposition-compatibility.md"

func TestSecurityEventLifecycleMigrationPreservesLegacyAlertedAtContract(t *testing.T) {
	body, err := os.ReadFile(alertLifecycleMigration)
	if err != nil {
		t.Fatalf("read migration 816: %v", err)
	}
	source := string(body)
	for _, required := range []string{
		"processed_at", "delivery", "disposition", "suppression_reason",
		"security_event_delivery_v1", "NOT VALID",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("migration missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"DROP COLUMN alerted_at", "alerted_at IS NULL THEN 'suppressed'",
		"UPDATE security_events", "CREATE INDEX",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("migration contains unsafe compatibility change %q", forbidden)
		}
	}
	design, err := os.ReadFile(alertLifecycleDesign)
	if err != nil {
		t.Fatalf("read lifecycle compatibility design: %v", err)
	}
	for _, required := range []string{"processed_at", "delivery", "disposition", "suppression_reason", "alerted_at", "NULL"} {
		if !strings.Contains(string(design), required) {
			t.Fatalf("design missing %q", required)
		}
	}
}

func TestSecurityEventLifecycleExpandAndConditionalReconcile(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		CREATE TABLE security_events (
			id text PRIMARY KEY,
			alerted_at timestamptz,
			created_at timestamptz NOT NULL DEFAULT now(), agent_instance_id varchar(128));
		INSERT INTO security_events(id,alerted_at) VALUES
			('delivered', now()),
			('legacy-unknown', NULL);
		CREATE TABLE migration_backfill_tasks (
			task_name text NOT NULL,
			task_version integer NOT NULL,
			state text NOT NULL,
			checkpoint jsonb NOT NULL DEFAULT '{}'::jsonb,
			scan_upper_bound jsonb NOT NULL DEFAULT '{}'::jsonb,
			batch_size integer NOT NULL,
			rate_limit_rows_per_second integer NOT NULL,
			lock_timeout_ms integer NOT NULL,
			statement_timeout_ms integer NOT NULL,
			max_retries integer NOT NULL,
			priority integer NOT NULL,
			PRIMARY KEY(task_name,task_version)
		);
		CREATE TABLE migration_backfill_events (
			id bigserial PRIMARY KEY,
			task_name text NOT NULL,
			task_version integer NOT NULL,
			event_type text NOT NULL,
			state text NOT NULL,
			summary text NOT NULL DEFAULT ''
		)
	`); err != nil {
		t.Fatalf("prepare legacy security events: %v", err)
	}
	body, err := os.ReadFile(alertLifecycleMigration)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := f.pool.Exec(ctx, string(body)); err != nil {
			t.Fatalf("apply migration 816 attempt %d: %v", attempt, err)
		}
	}
	var processed bool
	var delivery, disposition, suppressionReason *string
	if err := f.pool.QueryRow(ctx, `
		SELECT processed_at IS NOT NULL,delivery,disposition,suppression_reason
		FROM security_events WHERE id='delivered'
	`).Scan(&processed, &delivery, &disposition, &suppressionReason); err != nil {
		t.Fatal(err)
	}
	if processed || delivery != nil || disposition != nil || suppressionReason != nil {
		t.Fatalf("expand migration rewrote history: processed=%v delivery=%v disposition=%v suppression=%v", processed, delivery, disposition, suppressionReason)
	}
	if err := f.pool.QueryRow(ctx, `
		SELECT processed_at IS NOT NULL,delivery,disposition,suppression_reason
		FROM security_events WHERE id='legacy-unknown'
	`).Scan(&processed, &delivery, &disposition, &suppressionReason); err != nil {
		t.Fatal(err)
	}
	if processed || delivery != nil || disposition != nil || suppressionReason != nil {
		t.Fatalf("legacy NULL row must remain unknown, got processed=%v delivery=%v disposition=%v suppression=%v", processed, delivery, disposition, suppressionReason)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO migration_backfill_tasks(
			task_name,task_version,state,batch_size,rate_limit_rows_per_second,
			lock_timeout_ms,statement_timeout_ms,max_retries,priority
		) VALUES ('security_event_delivery_v1',1,'completed',1000,5000,1000,30000,20,15)
	`); err != nil {
		t.Fatal(err)
	}
	reconcile, err := os.ReadFile("../../../../deploy/migrations/845_security_event_delivery_reconcile.sql")
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := f.pool.Exec(ctx, string(reconcile)); err != nil {
			t.Fatalf("apply migration 845 attempt %d: %v", attempt, err)
		}
	}
	var reconcileCount int
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM migration_backfill_tasks
		WHERE task_name='security_event_delivery_v1' AND task_version=2 AND state='pending'
	`).Scan(&reconcileCount); err != nil || reconcileCount != 1 {
		t.Fatalf("conditional reconcile count=%d err=%v", reconcileCount, err)
	}
}

func TestMarkAlertedWritesSplitLifecycleDimensions(t *testing.T) {
	sql := strings.ToLower(markSecurityEventsAlertedSQL)
	for _, required := range []string{
		"alerted_at = now()", "processed_at = coalesce(processed_at, now())",
		"delivery = coalesce(delivery, 'delivered')", "where id = any($1)",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("MarkAlerted SQL missing %q", required)
		}
	}
}
