package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupAgentAuthorizationRetentionPGTest connects to a real, migrated Postgres
// instance (schema current through migration 864). It is skipped unless
// AGENT_AUTHORIZATION_TEST_DATABASE_URL is set, and it refuses databases whose
// name does not look like a disposable test database, so it can never prune a
// shared or production database by accident.
func setupAgentAuthorizationRetentionPGTest(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("AGENT_AUTHORIZATION_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("AGENT_AUTHORIZATION_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var name string
	if err := db.QueryRow(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(name, "test") && !strings.HasPrefix(name, "w3") {
		t.Fatalf("refusing non-test database %q", name)
	}

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	tenantID := "t13ret-" + hex.EncodeToString(suffix)
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, is_test) VALUES ($1, $1, true)`, tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("cleanup tenant %s: %v", tenantID, err)
		}
	})
	return db, tenantID
}

func seedAgentAuthorizationRetentionGrant(t *testing.T, db *pgxpool.Pool, tenantID string) (principalID, grantID string) {
	t.Helper()
	ctx := context.Background()
	hash := make([]byte, 32)
	if _, err := rand.Read(hash); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `
INSERT INTO agent_authorization_principals
	(id, tenant_id, name, credential_hash, credential_prefix, expires_at, created_by)
VALUES (gen_random_uuid(), $1, 'retention-test', $2, 'aap_test', NOW() + interval '1 day', 'retention-test')
RETURNING id::text`, tenantID, hex.EncodeToString(hash)).Scan(&principalID); err != nil {
		t.Fatalf("seed principal: %v", err)
	}
	if err := db.QueryRow(ctx, `
INSERT INTO agent_authorization_grants
	(id, tenant_id, principal_id, action, resource_type, resource_id, expires_at, quota_max, quota_window_seconds)
VALUES (gen_random_uuid(), $1, $2::uuid, 'tool.invoke', 'tool', 'retention-test', NOW() + interval '1 day', 10, 60)
RETURNING id::text`, tenantID, principalID).Scan(&grantID); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return principalID, grantID
}

func TestAgentAuthorizationRetentionPGPrunesOnlyStaleRows(t *testing.T) {
	db, tenantID := setupAgentAuthorizationRetentionPGTest(t)
	ctx := context.Background()
	principalID, grantID := seedAgentAuthorizationRetentionGrant(t, db, tenantID)

	maxWindow := time.Duration(AgentAuthorizationMaxQuotaWindowSeconds) * time.Second
	staleWindow := time.Now().Add(-maxWindow - time.Hour)
	freshWindow := time.Now().Add(-time.Minute)
	for _, windowStart := range []time.Time{staleWindow, freshWindow} {
		if _, err := db.Exec(ctx, `
INSERT INTO agent_authorization_usage (tenant_id, principal_id, grant_id, window_start, used)
VALUES ($1, $2::uuid, $3::uuid, $4, 1)`, tenantID, principalID, grantID, windowStart); err != nil {
			t.Fatalf("seed usage %s: %v", windowStart, err)
		}
	}
	for key, expiresAt := range map[string]time.Time{
		"stale-request": time.Now().Add(-time.Hour),
		"fresh-request": time.Now().Add(time.Hour),
	} {
		if _, err := db.Exec(ctx, `
INSERT INTO agent_authorization_requests (tenant_id, principal_id, idempotency_key, request_hash, state, expires_at)
VALUES ($1, $2::uuid, $3, $4, 'pending', $5)`, tenantID, principalID, key, strings.Repeat("a", 64), expiresAt); err != nil {
			t.Fatalf("seed request %s: %v", key, err)
		}
	}

	result, err := NewAgentAuthorizationRepository(db).PruneExpiredData(ctx)
	if err != nil {
		t.Fatalf("PruneExpiredData on real PostgreSQL: %v", err)
	}
	if result.Backlog {
		t.Fatalf("unexpected backlog after a small prune: %+v", result)
	}

	var usageLeft, requestsLeft []string
	rows, err := db.Query(ctx, `SELECT window_start::text FROM agent_authorization_usage WHERE tenant_id = $1 ORDER BY window_start`, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		usageLeft = append(usageLeft, v)
	}
	rows.Close()
	rows, err = db.Query(ctx, `SELECT idempotency_key FROM agent_authorization_requests WHERE tenant_id = $1 ORDER BY idempotency_key`, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		requestsLeft = append(requestsLeft, v)
	}
	rows.Close()

	if len(usageLeft) != 1 || len(requestsLeft) != 1 || requestsLeft[0] != "fresh-request" {
		t.Fatalf("expected only fresh rows to survive, usage=%v requests=%v", usageLeft, requestsLeft)
	}
	// Other tenants' rows may exist in a shared scratch DB, so count only ours.
	if result.DeletedUsage < 1 || result.DeletedRequests < 1 {
		t.Fatalf("expected at least one stale usage and request deleted, got %+v", result)
	}
}
