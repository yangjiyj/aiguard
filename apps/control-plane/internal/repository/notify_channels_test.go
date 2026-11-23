package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupNotifyChannelsTestDB opens a test DB and seeds a tenant.
func setupNotifyChannelsTestDB(t *testing.T) (*pgxpool.Pool, string) {
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
	tenantID := fmt.Sprintf("tenant_nc_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM notify_channels WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID
}

func TestNotifyChannelsCRUD(t *testing.T) {
	pool, tenantID := setupNotifyChannelsTestDB(t)
	repo := NewNotifyChannelsRepository(pool)
	ctx := context.Background()

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	ch := &NotifyChannel{
		ID:         "nc_" + sfx,
		TenantID:   tenantID,
		Type:       "webhook",
		Name:       "My Webhook",
		ConfigJSON: map[string]any{"url": "https://hooks.example.com/test"},
		Enabled:    true,
	}

	// Create
	if err := repo.Create(ctx, ch); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Get
	got, err := repo.Get(ctx, ch.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "My Webhook" {
		t.Errorf("Name: %s", got.Name)
	}
	if !got.Enabled {
		t.Errorf("Enabled should be true")
	}
	if got.ConfigJSON["url"] != "https://hooks.example.com/test" {
		t.Errorf("ConfigJSON url: %v", got.ConfigJSON["url"])
	}

	// ListByTenant
	all, err := repo.ListByTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 channel, got %d", len(all))
	}

	// ListEnabled
	enabled, err := repo.ListEnabled(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListEnabled: %v", err)
	}
	if len(enabled) != 1 {
		t.Errorf("expected 1 enabled channel, got %d", len(enabled))
	}

	// Update: disable
	if err := repo.Update(ctx, tenantID, ch.ID, "Updated Webhook", map[string]any{"url": "https://new.example.com"}, false); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got2, err := repo.Get(ctx, ch.ID)
	if err != nil {
		t.Fatalf("Get after Update: %v", err)
	}
	if got2.Enabled {
		t.Errorf("Enabled should be false after update")
	}
	if got2.Name != "Updated Webhook" {
		t.Errorf("Name after update: %s", got2.Name)
	}

	// ListEnabled should now be empty
	enabled2, err := repo.ListEnabled(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListEnabled after disable: %v", err)
	}
	if len(enabled2) != 0 {
		t.Errorf("expected 0 enabled after disable, got %d", len(enabled2))
	}

	// Delete
	if err := repo.Delete(ctx, tenantID, ch.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = repo.Get(ctx, ch.ID)
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}
