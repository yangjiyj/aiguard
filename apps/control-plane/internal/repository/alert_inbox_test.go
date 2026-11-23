package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupAlertInboxTestDB opens a test database connection and seeds a tenant.
func setupAlertInboxTestDB(t *testing.T) (*pgxpool.Pool, string) {
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
	tenantID := fmt.Sprintf("tenant_ai_%d", time.Now().UnixNano())
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

func TestAlertInboxInsertAndList(t *testing.T) {
	pool, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(pool)
	ctx := context.Background()

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	item := &AlertInboxItem{
		ID:        "alert_" + sfx,
		TenantID:  tenantID,
		Severity:  "warning",
		Type:      "budget_exceeded",
		Title:     "Budget Exceeded",
		BodyJSON:  map[string]any{"usage": 105.5, "limit": 100.0},
		TargetURL: "/budgets",
	}

	if err := repo.Insert(ctx, item); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// List should return 1 item
	items, err := repo.List(ctx, tenantID, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].Title != "Budget Exceeded" {
		t.Errorf("Title: %s", items[0].Title)
	}
	if items[0].BodyJSON == nil {
		t.Errorf("BodyJSON should not be nil")
	}

	// CountUnread should be 1
	count, err := repo.CountUnread(ctx, tenantID)
	if err != nil {
		t.Fatalf("CountUnread: %v", err)
	}
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}
}

func TestAlertInboxListsNullTargetURLAsEmptyString(t *testing.T) {
	pool, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(pool)
	ctx := context.Background()
	id := fmt.Sprintf("alert_null_target_%d", time.Now().UnixNano())

	if _, err := pool.Exec(ctx, `
		INSERT INTO alert_inbox
			(id, tenant_id, severity, type, title, body_json, target_url)
		VALUES
			($1, $2, 'warning', 'security_event', '无跳转地址', '{}', NULL)
	`, id, tenantID); err != nil {
		t.Fatalf("insert NULL target alert: %v", err)
	}

	tests := []struct {
		name string
		list func() ([]*AlertInboxItem, error)
	}{
		{name: "unread", list: func() ([]*AlertInboxItem, error) {
			return repo.ListUnread(ctx, tenantID, 10)
		}},
		{name: "all", list: func() ([]*AlertInboxItem, error) {
			return repo.List(ctx, tenantID, 10)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items, err := tt.list()
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(items) != 1 {
				t.Fatalf("expected 1 item, got %d", len(items))
			}
			if items[0].TargetURL != "" {
				t.Fatalf("expected empty target_url, got %q", items[0].TargetURL)
			}
		})
	}
}

func TestAlertInboxMarkRead(t *testing.T) {
	pool, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(pool)
	ctx := context.Background()

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	item := &AlertInboxItem{
		ID:       "alert_" + sfx,
		TenantID: tenantID,
		Severity: "high",
		Type:     "quota_near_limit",
		Title:    "Quota Near Limit",
		BodyJSON: map[string]any{"percent": 90},
	}
	if err := repo.Insert(ctx, item); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// Unread should have 1 item
	unread, err := repo.ListUnread(ctx, tenantID, 10)
	if err != nil {
		t.Fatalf("ListUnread: %v", err)
	}
	if len(unread) != 1 {
		t.Fatalf("expected 1 unread, got %d", len(unread))
	}

	// Mark read（越权修复后带租户过滤）
	if err := repo.MarkRead(ctx, tenantID, item.ID); err != nil {
		t.Fatalf("MarkRead: %v", err)
	}

	// Unread should be empty now
	unread2, err := repo.ListUnread(ctx, tenantID, 10)
	if err != nil {
		t.Fatalf("ListUnread after mark: %v", err)
	}
	if len(unread2) != 0 {
		t.Errorf("expected 0 unread after MarkRead, got %d", len(unread2))
	}

	// CountUnread should be 0
	count, err := repo.CountUnread(ctx, tenantID)
	if err != nil {
		t.Fatalf("CountUnread: %v", err)
	}
	if count != 0 {
		t.Errorf("expected count 0 after mark read, got %d", count)
	}

	// List (all) should still have 1 item
	all, err := repo.List(ctx, tenantID, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 total, got %d", len(all))
	}
	if all[0].ReadAt == nil {
		t.Errorf("ReadAt should be set after MarkRead")
	}
}

// 越权修复:拿别的租户身份标记本租户的告警必须是 no-op。
func TestAlertInboxMarkReadScopedToTenant(t *testing.T) {
	pool, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(pool)
	ctx := context.Background()

	item := &AlertInboxItem{
		ID:       fmt.Sprintf("alert_scope_%d", time.Now().UnixNano()),
		TenantID: tenantID,
		Severity: "high",
		Type:     "security_event",
		Title:    "跨租户越权检查",
		BodyJSON: map[string]any{},
	}
	if err := repo.Insert(ctx, item); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// 用其他租户 id 标记 → 不生效。
	if err := repo.MarkRead(ctx, "tenant_someone_else", item.ID); err != nil {
		t.Fatalf("cross-tenant MarkRead should not error (no-op): %v", err)
	}
	count, err := repo.CountUnread(ctx, tenantID)
	if err != nil {
		t.Fatalf("CountUnread: %v", err)
	}
	if count != 1 {
		t.Fatalf("cross-tenant MarkRead must be a no-op, unread=%d", count)
	}

	// 本租户标记 → 生效。
	if err := repo.MarkRead(ctx, tenantID, item.ID); err != nil {
		t.Fatalf("MarkRead: %v", err)
	}
	count, err = repo.CountUnread(ctx, tenantID)
	if err != nil {
		t.Fatalf("CountUnread after mark: %v", err)
	}
	if count != 0 {
		t.Fatalf("same-tenant MarkRead must take effect, unread=%d", count)
	}
}
func TestAlertInboxUpsertKeepsHigherSeverityDetails(t *testing.T) {
	pool, tenantID := setupAlertInboxTestDB(t)
	repo := NewAlertInboxRepository(pool)
	ctx := context.Background()
	groupKey := "secret|fixture-representative"

	created, err := repo.UpsertByGroup(ctx, &AlertInboxItem{
		ID:       "alert_critical",
		TenantID: tenantID,
		Severity: "critical",
		Type:     "security_event",
		Title:    "real secret leak",
		BodyJSON: map[string]any{"event_id": "evt_critical"},
	}, groupKey)
	if err != nil || !created {
		t.Fatalf("critical alert create failed: created=%v err=%v", created, err)
	}

	created, err = repo.UpsertByGroup(ctx, &AlertInboxItem{
		ID:       "alert_observation",
		TenantID: tenantID,
		Severity: "high",
		Type:     "security_event",
		Title:    "low-risk observation",
		BodyJSON: map[string]any{"event_id": "evt_observation"},
	}, groupKey)
	if err != nil || created {
		t.Fatalf("lower-severity fold failed: created=%v err=%v", created, err)
	}

	items, err := repo.ListUnread(ctx, tenantID, 10)
	if err != nil {
		t.Fatalf("ListUnread: %v", err)
	}
	if len(items) != 1 || items[0].Severity != "critical" || items[0].Title != "real secret leak" {
		t.Fatalf("lower-severity event replaced inbox representative: %+v", items)
	}
	if got, _ := items[0].BodyJSON["event_id"].(string); got != "evt_critical" {
		t.Fatalf("lower-severity body replaced inbox representative: %+v", items[0].BodyJSON)
	}
}
