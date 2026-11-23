package alert

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// setupInboxTestDB opens a test database and seeds a tenant.
func setupInboxTestDB(t *testing.T) (*pgxpool.Pool, string) {
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
	tenantID := fmt.Sprintf("tenant_is_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM alert_inbox WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID
}

func TestInboxServicePushAndUnread(t *testing.T) {
	pool, tenantID := setupInboxTestDB(t)
	repo := repository.NewAlertInboxRepository(pool)
	svc := NewInboxService(repo)
	ctx := context.Background()

	err := svc.Push(ctx, tenantID, "warning", "cost_spike", "Cost Spike Detected",
		map[string]any{"cost_usd": 55.5}, "/usage")
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	items, err := svc.Unread(ctx, tenantID)
	if err != nil {
		t.Fatalf("Unread: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 unread, got %d", len(items))
	}
	if items[0].Severity != "warning" {
		t.Errorf("Severity: %s", items[0].Severity)
	}

	// MarkRead（越权修复后带租户过滤）
	if err := svc.MarkRead(ctx, tenantID, items[0].ID); err != nil {
		t.Fatalf("MarkRead: %v", err)
	}

	unread2, err := svc.Unread(ctx, tenantID)
	if err != nil {
		t.Fatalf("Unread after mark: %v", err)
	}
	if len(unread2) != 0 {
		t.Errorf("expected 0 unread after mark, got %d", len(unread2))
	}
}
