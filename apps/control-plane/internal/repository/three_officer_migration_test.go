package repository

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const threeOfficerMigration = "../../../../deploy/migrations/890_three_officer_roles.sql"

// migration890Body returns the migration without its own BEGIN/COMMIT so the
// test can run it inside a rolled-back transaction on a shared database.
func migration890Body(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(threeOfficerMigration)
	if err != nil {
		t.Fatalf("read migration 890: %v", err)
	}
	s := string(raw)
	s = strings.Replace(s, "\nBEGIN;\n", "\n", 1)
	s = strings.Replace(s, "\nCOMMIT;\n", "\n", 1)
	return s
}

func migration890Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func migration890Tx(t *testing.T, pool *pgxpool.Pool) pgx.Tx {
	t.Helper()
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx
}

func TestMigration890MapsLegacyAdminAndIsIdempotent(t *testing.T) {
	pool := migration890Pool(t)
	tx := migration890Tx(t, pool)
	ctx := context.Background()
	if _, err := tx.Exec(ctx, `
		INSERT INTO users(id, tenant_id, username, role, status, password_hash)
		VALUES ('w4_legacy_admin', 'tenant_default', 'w4_legacy_admin', 'admin', 'active', 'x'),
		       ('w4_dev', 'tenant_default', 'w4_dev', 'developer', 'active', 'x')`); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	body := migration890Body(t)
	for i := 0; i < 2; i++ { // second run proves idempotency
		if _, err := tx.Exec(ctx, body); err != nil {
			t.Fatalf("run %d of migration 890: %v", i+1, err)
		}
	}
	var role string
	if err := tx.QueryRow(ctx, `SELECT role FROM users WHERE id='w4_legacy_admin'`).Scan(&role); err != nil || role != "platform_admin" {
		t.Fatalf("legacy admin role = %q (%v), want platform_admin", role, err)
	}
	if err := tx.QueryRow(ctx, `SELECT role FROM users WHERE id='w4_dev'`).Scan(&role); err != nil || role != "developer" {
		t.Fatalf("developer role changed to %q (%v)", role, err)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_operations
		WHERE action_type='role.migrated' AND target_id='w4_legacy_admin'
		  AND action_detail->>'old_role'='admin' AND action_detail->>'new_role'='platform_admin'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("migration audit rows = %d (%v), want exactly 1", n, err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM system_roles WHERE name IN ('security_officer','auditor') AND is_builtin`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("officer system roles = %d (%v), want 2", n, err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='admin'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("remaining admin users = %d (%v)", n, err)
	}
}

func TestMigration890RestoresUserAdminWhenNoSystemAdminCanLogIn(t *testing.T) {
	pool := migration890Pool(t)
	tx := migration890Tx(t, pool)
	ctx := context.Background()
	// Upgrade scenario: user_admin was demoted/disabled and no other system admin has a password.
	if _, err := tx.Exec(ctx, `
		UPDATE users SET role='developer', status='disabled', password_hash='bootstrap-hash' WHERE id='user_admin';
		UPDATE users SET status='disabled' WHERE role IN ('platform_admin','admin') AND id <> 'user_admin';
		DELETE FROM audit_operations WHERE id='mig890_restore_user_admin'`); err != nil {
		t.Fatalf("arrange: %v", err)
	}
	if _, err := tx.Exec(ctx, migration890Body(t)); err != nil {
		t.Fatalf("migration 890: %v", err)
	}
	var role, status string
	if err := tx.QueryRow(ctx, `SELECT role, status FROM users WHERE id='user_admin'`).Scan(&role, &status); err != nil {
		t.Fatalf("read user_admin: %v", err)
	}
	if role != "platform_admin" || status != "active" {
		t.Fatalf("user_admin = %s/%s, want platform_admin/active", role, status)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE id='mig890_restore_user_admin'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("restore audit rows = %d (%v)", n, err)
	}
}

func TestMigration890LeavesWorkingSystemAdminAlone(t *testing.T) {
	pool := migration890Pool(t)
	tx := migration890Tx(t, pool)
	ctx := context.Background()
	if _, err := tx.Exec(ctx, `
		UPDATE users SET role='developer', status='disabled' WHERE id='user_admin';
		INSERT INTO users(id, tenant_id, username, role, status, password_hash)
		VALUES ('w4_sysadmin', 'tenant_default', 'w4_sysadmin', 'platform_admin', 'active', 'x')`); err != nil {
		t.Fatalf("arrange: %v", err)
	}
	if _, err := tx.Exec(ctx, migration890Body(t)); err != nil {
		t.Fatalf("migration 890: %v", err)
	}
	var role string
	if err := tx.QueryRow(ctx, `SELECT role FROM users WHERE id='user_admin'`).Scan(&role); err != nil || role != "developer" {
		t.Fatalf("user_admin must not be touched when another system admin can log in; role=%q (%v)", role, err)
	}
}

func TestListLoginHistoryForAuditScopesAndPages(t *testing.T) {
	pool := migration890Pool(t)
	ctx := context.Background()
	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id IN ('w4lh_u1','w4lh_u2')`)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id='w4lh_t2'`)
	}
	cleanup()
	t.Cleanup(cleanup)
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants(id, name, edition, status) VALUES ('w4lh_t2', 'w4lh_t2', 'enterprise', 'active');
		INSERT INTO users(id, tenant_id, username, role, status) VALUES
			('w4lh_u1', 'tenant_default', 'w4lh_u1', 'developer', 'active'),
			('w4lh_u2', 'w4lh_t2', 'w4lh_u2', 'developer', 'active');
		INSERT INTO user_login_history(user_id, logged_at, ip, user_agent, success, failure_reason) VALUES
			('w4lh_u1', '2030-01-01T00:00:00Z', '10.0.0.1', 'ua1', TRUE, NULL),
			('w4lh_u1', '2030-01-02T00:00:00Z', '10.0.0.1', 'ua1', FALSE, 'bad_password'),
			('w4lh_u2', '2030-01-03T00:00:00Z', '10.0.0.2', 'ua2', TRUE, NULL)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	repo := NewUserLoginHistoryRepository(pool)
	since := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	// Tenant-scoped: only tenant_default rows, newest first, username joined.
	got, total, err := repo.ListForAudit(ctx, LoginHistoryAuditFilter{TenantID: "tenant_default", Since: &since})
	if err != nil {
		t.Fatalf("ListForAudit: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("tenant scope: total=%d len=%d, want 2/2", total, len(got))
	}
	if got[0].UserID != "w4lh_u1" || got[0].Success || got[0].FailureReason != "bad_password" || got[0].Username != "w4lh_u1" {
		t.Fatalf("newest row = %+v", got[0])
	}
	// All tenants (system-tenant caller) + paging.
	got, total, err = repo.ListForAudit(ctx, LoginHistoryAuditFilter{Since: &since, Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("ListForAudit all: %v", err)
	}
	if total != 3 || len(got) != 1 || got[0].UserID != "w4lh_u1" || got[0].TenantID != "tenant_default" {
		t.Fatalf("all tenants page 2: total=%d rows=%+v", total, got)
	}
	// Until is exclusive; user filter.
	until := time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)
	got, total, err = repo.ListForAudit(ctx, LoginHistoryAuditFilter{UserID: "w4lh_u1", Since: &since, Until: &until})
	if err != nil || total != 1 || len(got) != 1 || !got[0].Success {
		t.Fatalf("until/user filter: total=%d rows=%+v err=%v", total, got, err)
	}
}
