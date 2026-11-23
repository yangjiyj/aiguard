package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupSecretFlowTestDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tenantID := fmt.Sprintf("tenant_sf_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active', TRUE)`, tenantID, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM secret_flow_first_seen WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID
}

// 集成测试(需 CONTENT_LOGS_TEST_DATABASE_URL + 迁移 098):幂等首见登记。
func TestSecretFlowMarkSeenIdempotent(t *testing.T) {
	db, tenantID := setupSecretFlowTestDB(t)
	repo := NewSecretFlowFirstSeenRepository(db)
	ctx := context.Background()

	pairs := []SecretFlowPair{
		{SecretFP: "sha_a", TargetHost: "api.example.com"},
		{SecretFP: "sha_b", TargetHost: "api.example.com"},
	}
	n, err := repo.MarkSeen(ctx, tenantID, pairs)
	if err != nil {
		t.Fatalf("MarkSeen: %v", err)
	}
	if n != 2 {
		t.Fatalf("first MarkSeen must report 2 new pairs, got %d", n)
	}

	// 重复登记 → 0 新对(全部已见)。
	n, err = repo.MarkSeen(ctx, tenantID, pairs)
	if err != nil {
		t.Fatalf("repeat MarkSeen: %v", err)
	}
	if n != 0 {
		t.Fatalf("repeat MarkSeen must report 0 new pairs, got %d", n)
	}

	// 旧指纹流向新目的地 → 记 1 新对。
	n, err = repo.MarkSeen(ctx, tenantID, []SecretFlowPair{{SecretFP: "sha_a", TargetHost: "evil.example.org"}})
	if err != nil {
		t.Fatalf("new host MarkSeen: %v", err)
	}
	if n != 1 {
		t.Fatalf("new destination must count as new pair, got %d", n)
	}

	// 空集合 → no-op。
	n, err = repo.MarkSeen(ctx, tenantID, nil)
	if err != nil || n != 0 {
		t.Fatalf("empty pairs should be a no-op, got n=%d err=%v", n, err)
	}
}
