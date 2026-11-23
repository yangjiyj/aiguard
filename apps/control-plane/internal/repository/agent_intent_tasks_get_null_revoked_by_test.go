package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Regression for GetIntentTask scanning a NULL revoked_by column: the DB
// column is nullable (only set once a task is revoked), but AgentIntentTask.
// RevokedBy is a plain string, so scanning straight into &task.RevokedBy
// fails every call for a non-revoked (the common) task with a pgx "cannot
// scan NULL into *string" error. GetIntentTask must instead scan into a
// nullable local and only assign it when present.
func TestGetIntentTaskAcceptsNullRevokedByIntegration(t *testing.T) {
	dsn := os.Getenv("AGENTGUARD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENTGUARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("intent_task_null_revoked_by_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	migration, err := os.ReadFile("../../../../deploy/migrations/873_agent_intent_tasks.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	const tenantID = "tenant-null-revoked-by"
	const taskID = "00000000-0000-4000-8000-0000000000a1"
	const principalID = "00000000-0000-4000-8000-0000000000a2"
	_, err = db.Exec(ctx, `INSERT INTO agent_intent_tasks (
		id, tenant_id, endpoint_id, product, principal_id, state,
		purpose, purpose_sha256, source_scope, source_scope_sha256, scope_sha256,
		approved_by, expires_at
	) VALUES (
		$1, $2, 'endpoint-fixture', 'openclaw', $3, 'approved',
		'read approved fixture inputs', repeat('a',64),
		'{"allowed_kinds":["web"]}'::jsonb, repeat('b',64), repeat('c',64),
		'fixture-admin', clock_timestamp() + interval '1 hour'
	)`, taskID, tenantID, principalID)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewAgentAuthorizationRepository(db)
	task, err := repo.GetIntentTask(ctx, tenantID, taskID)
	if err != nil {
		t.Fatalf("GetIntentTask on a non-revoked task (NULL revoked_by) must not error: %v", err)
	}
	if task == nil {
		t.Fatal("expected task, got nil")
	}
	if task.RevokedBy != "" {
		t.Fatalf("RevokedBy = %q, want empty for a non-revoked task", task.RevokedBy)
	}
	if task.RevokedAt != nil {
		t.Fatalf("RevokedAt = %v, want nil for a non-revoked task", task.RevokedAt)
	}
	if task.State != "approved" {
		t.Fatalf("State = %q, want approved", task.State)
	}

	// Once revoked, revoked_by must round-trip through GetIntentTask too.
	_, err = db.Exec(ctx, `UPDATE agent_intent_tasks SET state='revoked', revoked_by='fixture-admin', revoked_at=clock_timestamp() WHERE id=$1`, taskID)
	if err != nil {
		t.Fatal(err)
	}
	revokedTask, err := repo.GetIntentTask(ctx, tenantID, taskID)
	if err != nil {
		t.Fatalf("GetIntentTask on a revoked task must not error: %v", err)
	}
	if revokedTask.RevokedBy != "fixture-admin" {
		t.Fatalf("RevokedBy = %q, want fixture-admin after revocation", revokedTask.RevokedBy)
	}
	if revokedTask.RevokedAt == nil {
		t.Fatal("RevokedAt must be set after revocation")
	}
}
