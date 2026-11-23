package repository

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupAppSettingsTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	db, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestAppSettings_SetAndGetMany(t *testing.T) {
	db := setupAppSettingsTestDB(t)
	ctx := context.Background()
	repo := NewAppSettingsRepository(db)

	// Set a key
	if err := repo.Set(ctx, "test_key_phase_b", "hello"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// GetMany should return it
	m, err := repo.GetMany(ctx, []string{"test_key_phase_b", "nonexistent_key_xyz"})
	if err != nil {
		t.Fatalf("GetMany: %v", err)
	}
	if m["test_key_phase_b"] != "hello" {
		t.Errorf("expected 'hello', got %q", m["test_key_phase_b"])
	}
	if _, ok := m["nonexistent_key_xyz"]; ok {
		t.Error("nonexistent key should not appear in result")
	}

	// Overwrite and verify update
	if err := repo.Set(ctx, "test_key_phase_b", "world"); err != nil {
		t.Fatalf("Set overwrite: %v", err)
	}
	m2, err := repo.GetMany(ctx, []string{"test_key_phase_b"})
	if err != nil {
		t.Fatalf("GetMany after overwrite: %v", err)
	}
	if m2["test_key_phase_b"] != "world" {
		t.Errorf("expected 'world' after overwrite, got %q", m2["test_key_phase_b"])
	}

	// Cleanup
	db.Exec(ctx, `DELETE FROM app_settings WHERE key = 'test_key_phase_b'`)
}
