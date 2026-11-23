package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alert"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/notify"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// setupAlertHandlerDB creates test DB pool + tenant + user fixture.
func setupAlertHandlerDB(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "tah_" + sfx
	userID := "uah_" + sfx
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		 VALUES ($1,$2,$3,$4,'x','platform_admin','active')`,
		userID, tenantID, userID, userID+"@test.com",
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM alert_inbox WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM notify_channels WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		pool.Close()
	})
	return pool, tenantID, userID
}

func buildAlertDeps(pool *pgxpool.Pool) *Dependencies {
	alertRepo := repository.NewAlertInboxRepository(pool)
	alertSvc := alert.NewInboxService(alertRepo)
	ncRepo := repository.NewNotifyChannelsRepository(pool)
	dispatcher := notify.NewDispatcher(ncRepo)
	return &Dependencies{
		AlertInboxRepo:     alertRepo,
		AlertService:       alertSvc,
		NotifyChannelsRepo: ncRepo,
		NotifyDispatcher:   dispatcher,
		SystemRepo:         &budgetTestSystemRepo{},
	}
}

func withAlertUserCtx(r *http.Request, tenantID, userID string) *http.Request {
	u := &repository.User{
		ID:       userID,
		TenantID: tenantID,
		Role:     "platform_admin",
		Status:   "active",
	}
	return r.WithContext(context.WithValue(r.Context(), auth.UserKey, u))
}

// TestListAlertInbox verifies inbox listing returns correct structure.
func TestListAlertInbox(t *testing.T) {
	pool, tenantID, userID := setupAlertHandlerDB(t)
	deps := buildAlertDeps(pool)
	ctx := context.Background()

	// Push a test alert directly via service
	if err := deps.AlertService.Push(ctx, tenantID, "warning", "budget_exceeded",
		"Budget Exceeded", map[string]any{"usage": 110.0}, "/budgets"); err != nil {
		t.Fatalf("Push: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/alerts/inbox?unread=true&limit=10", nil)
	req = withAlertUserCtx(req, tenantID, userID)
	rr := httptest.NewRecorder()
	ListAlertInbox(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	items := resp["items"].([]interface{})
	if len(items) != 1 {
		t.Errorf("expected 1 item, got %d", len(items))
	}
	if resp["unread_count"].(float64) != 1 {
		t.Errorf("unread_count: %v", resp["unread_count"])
	}
	item := items[0].(map[string]interface{})
	if item["severity"] != "warning" {
		t.Fatalf("severity json field: %#v", item)
	}
	if item["type"] != "budget_exceeded" {
		t.Fatalf("type json field: %#v", item)
	}
	if item["title"] != "Budget Exceeded" {
		t.Fatalf("title json field: %#v", item)
	}
	if _, ok := item["Title"]; ok {
		t.Fatalf("handler leaked Go field names instead of API json names: %#v", item)
	}
	if item["created_at"] == "" || item["created_at"] == nil {
		t.Fatalf("created_at should be present: %#v", item)
	}
}

// TestMarkAlertRead verifies the mark-read endpoint.
func TestMarkAlertRead(t *testing.T) {
	pool, tenantID, userID := setupAlertHandlerDB(t)
	deps := buildAlertDeps(pool)
	ctx := context.Background()

	// Push alert and get its ID
	if err := deps.AlertService.Push(ctx, tenantID, "high", "quota_near_limit",
		"Quota Near Limit", map[string]any{"pct": 90}, "/quota"); err != nil {
		t.Fatalf("Push: %v", err)
	}
	unread, _ := deps.AlertInboxRepo.ListUnread(ctx, tenantID, 10)
	if len(unread) != 1 {
		t.Fatalf("expected 1 unread, got %d", len(unread))
	}
	alertID := unread[0].ID

	// Mark read via handler
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/alerts/"+alertID+"/read", nil)
	req = withAlertUserCtx(req, tenantID, userID)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", alertID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	MarkAlertRead(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify unread is now 0
	count, _ := deps.AlertInboxRepo.CountUnread(ctx, tenantID)
	if count != 0 {
		t.Errorf("expected 0 unread after mark read, got %d", count)
	}
}

// TestCreateAndDeleteNotifyChannel verifies channel create/delete lifecycle.
func TestCreateAndDeleteNotifyChannel(t *testing.T) {
	pool, tenantID, userID := setupAlertHandlerDB(t)
	deps := buildAlertDeps(pool)
	ctx := context.Background()

	// Create channel
	body := map[string]any{
		"type":        "webhook",
		"name":        "Test Webhook",
		"config_json": map[string]any{"url": "https://hooks.example.com/test"},
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/notify-channels", bytes.NewReader(bodyBytes))
	req = withAlertUserCtx(req, tenantID, userID)
	rr := httptest.NewRecorder()
	CreateNotifyChannel(deps)(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var created repository.NotifyChannel
	if err := json.NewDecoder(rr.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected non-empty ID")
	}

	// List channels
	listReq := httptest.NewRequest(http.MethodGet, "/admin/v1/notify-channels", nil)
	listReq = withAlertUserCtx(listReq, tenantID, userID)
	listRR := httptest.NewRecorder()
	ListNotifyChannels(deps)(listRR, listReq)

	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRR.Code, listRR.Body.String())
	}
	var listResp map[string]interface{}
	if err := json.NewDecoder(listRR.Body).Decode(&listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	channels := listResp["channels"].([]interface{})
	if len(channels) != 1 {
		t.Errorf("expected 1 channel, got %d", len(channels))
	}

	// Delete channel
	delReq := httptest.NewRequest(http.MethodDelete, "/admin/v1/notify-channels/"+created.ID, nil)
	delReq = withAlertUserCtx(delReq, tenantID, userID)
	rctxDel := chi.NewRouteContext()
	rctxDel.URLParams.Add("id", created.ID)
	delReq = delReq.WithContext(context.WithValue(delReq.Context(), chi.RouteCtxKey, rctxDel))

	delRR := httptest.NewRecorder()
	DeleteNotifyChannel(deps)(delRR, delReq)

	if delRR.Code != http.StatusOK {
		t.Fatalf("expected 200 delete, got %d: %s", delRR.Code, delRR.Body.String())
	}

	// Verify gone
	chs, err := deps.NotifyChannelsRepo.ListByTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(chs) != 0 {
		t.Errorf("expected 0 channels after delete, got %d", len(chs))
	}
}
