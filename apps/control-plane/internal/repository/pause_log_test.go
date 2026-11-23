package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// setupPauseLogTestDB opens a test database connection and seeds a tenant.
// The tenant (and all pause_log rows) are cleaned up via t.Cleanup.
func setupPauseLogTestDB(t *testing.T) (*pgxpool.Pool, string) {
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
	tenantID := fmt.Sprintf("tenant_pl_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM pause_log WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID
}

func TestPauseLogPauseUnpause(t *testing.T) {
	pool, tenantID := setupPauseLogTestDB(t)
	repo := NewPauseLogRepository(pool)
	ctx := context.Background()

	id := fmt.Sprintf("pl_%d", time.Now().UnixNano())
	keyPrefix := "test-key-" + id

	// --- Pause
	pl, err := repo.Pause(ctx, id, tenantID, keyPrefix, "admin", "exceeded budget")
	if err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if pl.ID != id {
		t.Errorf("ID mismatch: %s", pl.ID)
	}
	if pl.UnpausedAt != nil {
		t.Errorf("UnpausedAt should be nil after pause")
	}

	// --- ListActive should include this record
	active, err := repo.ListActive(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	if len(active) != 1 || active[0].ID != id {
		t.Errorf("expected 1 active entry with id %s, got %d entries", id, len(active))
	}

	// --- Unpause
	if err := repo.Unpause(ctx, keyPrefix, "admin2"); err != nil {
		t.Fatalf("Unpause: %v", err)
	}

	// --- ListActive should now be empty
	active2, err := repo.ListActive(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListActive after unpause: %v", err)
	}
	if len(active2) != 0 {
		t.Errorf("expected 0 active entries after unpause, got %d", len(active2))
	}

	// --- List should still include the record
	all, err := repo.List(ctx, tenantID, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 total entry, got %d", len(all))
	}
	if all[0].UnpausedAt == nil {
		t.Errorf("UnpausedAt should be set after unpause")
	}
}

func TestPauseLogUnpauseNoActiveRecord(t *testing.T) {
	pool, tenantID := setupPauseLogTestDB(t)
	repo := NewPauseLogRepository(pool)
	ctx := context.Background()

	_ = tenantID // needed for cleanup
	err := repo.Unpause(ctx, "sk-nonexistent", "admin")
	if err != pgx.ErrNoRows {
		t.Errorf("expected pgx.ErrNoRows, got %v", err)
	}
}
