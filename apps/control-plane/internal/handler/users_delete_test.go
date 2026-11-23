package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func cleanupDeleteUserTestTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string) {
	_, _ = pool.Exec(ctx, `DELETE FROM billing_customer_group_memberships WHERE tenant_id = $1`)
	_, _ = pool.Exec(ctx, `DELETE FROM billing_limit_counters WHERE tenant_id = $1`)
	_, _ = pool.Exec(ctx, `DELETE FROM billing_customer_limits WHERE tenant_id = $1`)
	_, _ = pool.Exec(ctx, `DELETE FROM billing_request_leases WHERE tenant_id = $1`)
	_, _ = pool.Exec(ctx, `DELETE FROM billing_wallets WHERE tenant_id = $1`)
	_, _ = pool.Exec(ctx, `DELETE FROM audit_operations WHERE target_id = $1`, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM internal_keys WHERE tenant_id = $1`, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM request_logs WHERE tenant_id = $1`, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM project_users WHERE project_id IN (SELECT id FROM projects WHERE tenant_id = $1)`, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM project_users WHERE user_id IN (SELECT id FROM users WHERE tenant_id = $1)`, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM team_members WHERE user_id IN (SELECT id FROM users WHERE tenant_id = $1)`, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM permission_grants WHERE user_id IN (SELECT id FROM users WHERE tenant_id = $1)`, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE tenant_id = $1`, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
	_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
}

func setupDeleteUserTestDB(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}

	tenantID := "tenant_delete_user_test"
	userID := "user_delete_target"

	cleanupDeleteUserTestTenant(ctx, pool, tenantID)

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, name, edition, status, is_test)
		VALUES ($1, $1, 'enterprise', 'active', TRUE)
	`, tenantID); err != nil {
		pool.Close()
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		VALUES ($1, $2, 'delete_me', 'delete_me@example.com', 'x', 'developer', 'active')
	`, userID, tenantID); err != nil {
		pool.Close()
		t.Fatalf("insert user: %v", err)
	}

	t.Cleanup(func() {
		cleanupDeleteUserTestTenant(context.Background(), pool, tenantID)
		pool.Close()
	})

	return pool, tenantID, userID
}

func TestDeleteUserRemovesUnreferencedUser(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool)}

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/users/"+userID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "platform_admin_user",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	DeleteUser(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE tenant_id = $1 AND id = $2`, tenantID, userID).Scan(&count); err != nil {
		t.Fatalf("count user: %v", err)
	}
	if count != 0 {
		t.Fatalf("deleted user row count = %d, want 0", count)
	}
}

func TestDeleteUserDetachesRequestLogs(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool)}
	projectID := "project_delete_user_request_log"
	logID := "request_log_delete_user_ref"
	requestID := "req_delete_user_ref"

	if _, err := pool.Exec(context.Background(), `
		INSERT INTO projects (id, tenant_id, name, code, environment, status)
		VALUES ($1, $2, 'request log project', 'delete-user-log', 'production', 'active')
	`, projectID, tenantID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status)
		VALUES ($1, $2, $3, $4, $5, 'chat', 'success')
	`, logID, requestID, tenantID, projectID, userID); err != nil {
		t.Fatalf("insert request log: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/users/"+userID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "platform_admin_user",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	DeleteUser(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	var userCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE tenant_id = $1 AND id = $2`, tenantID, userID).Scan(&userCount); err != nil {
		t.Fatalf("count user: %v", err)
	}
	if userCount != 0 {
		t.Fatalf("deleted user row count = %d, want 0", userCount)
	}

	var logCount int
	var logUserID *string
	if err := pool.QueryRow(context.Background(), `SELECT count(*), max(user_id) FROM request_logs WHERE id = $1`, logID).Scan(&logCount, &logUserID); err != nil {
		t.Fatalf("read request log: %v", err)
	}
	if logCount != 1 {
		t.Fatalf("request log row count = %d, want 1", logCount)
	}
	if logUserID != nil {
		t.Fatalf("request log user_id = %q, want NULL", *logUserID)
	}
}

func TestDeleteUserDetachesAuditOperations(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool)}
	auditID := "audit_op_delete_user_ref"

	if _, err := pool.Exec(context.Background(), `
		INSERT INTO audit_operations (id, user_id, action_type, action_detail, target_type, target_id, ip_address)
		VALUES ($1, $2, 'user.test_action', '{}', 'tenant', $3, '127.0.0.1')
	`, auditID, userID, tenantID); err != nil {
		t.Fatalf("insert audit operation: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/users/"+userID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "platform_admin_user",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	DeleteUser(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	var userCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE tenant_id = $1 AND id = $2`, tenantID, userID).Scan(&userCount); err != nil {
		t.Fatalf("count user: %v", err)
	}
	if userCount != 0 {
		t.Fatalf("deleted user row count = %d, want 0", userCount)
	}

	var auditCount int
	var auditUserID *string
	if err := pool.QueryRow(context.Background(), `SELECT count(*), max(user_id) FROM audit_operations WHERE id = $1`, auditID).Scan(&auditCount, &auditUserID); err != nil {
		t.Fatalf("read audit operation: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("audit operation row count = %d, want 1", auditCount)
	}
	if auditUserID != nil {
		t.Fatalf("audit operation user_id = %q, want NULL", *auditUserID)
	}
}

func TestDeleteUserRetiresWalletOwnerAndHidesItFromUserLists(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool)}
	walletID := "wallet_delete_user_history"

	if _, err := pool.Exec(context.Background(), `
		INSERT INTO billing_wallets (id, tenant_id, user_id, currency, balance_micros)
		VALUES ($1, $2, $3, 'CNY', 1250000)
	`, walletID, tenantID, userID); err != nil {
		t.Fatalf("insert billing wallet: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM billing_wallets WHERE id = $1`, walletID)
	})

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/users/"+userID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "platform_admin_user",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	DeleteUser(deps).ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	var username, status string
	var email, passwordHash *string
	if err := pool.QueryRow(context.Background(), `
		SELECT username, status, email, password_hash FROM users WHERE id = $1
	`, userID).Scan(&username, &status, &email, &passwordHash); err != nil {
		t.Fatalf("read retired user: %v", err)
	}
	if status != "deleted" || !strings.HasPrefix(username, "__deleted__") || email != nil || passwordHash != nil {
		t.Fatalf("retired user = username:%q status:%q email:%v password:%v", username, status, email, passwordHash)
	}

	var walletCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM billing_wallets WHERE id=$1 AND user_id=$2`, walletID, userID).Scan(&walletCount); err != nil {
		t.Fatalf("read retained wallet: %v", err)
	}
	if walletCount != 1 {
		t.Fatalf("retained wallet count = %d, want 1", walletCount)
	}

	listed, err := deps.UserRepo.ListAllWithStats(context.Background())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	for _, item := range listed {
		if item.ID == userID {
			t.Fatalf("retired user must not appear in user management list")
		}
	}
}

func TestDeleteUserIgnoresHiddenTestTenantProjectOwnership(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool)}
	projectID := "project_delete_user_hidden_test_ref"

	if _, err := pool.Exec(context.Background(), `
		INSERT INTO projects (id, tenant_id, name, code, environment, owner_user_id, status)
		VALUES ($1, $2, 'hidden test project', 'hidden-test-ref', 'production', $3, 'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatalf("insert hidden test project: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/users/"+userID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "platform_admin_user",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	DeleteUser(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	var userCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE tenant_id = $1 AND id = $2`, tenantID, userID).Scan(&userCount); err != nil {
		t.Fatalf("count user: %v", err)
	}
	if userCount != 0 {
		t.Fatalf("deleted user row count = %d, want 0", userCount)
	}

	var projectOwnerID *string
	if err := pool.QueryRow(context.Background(), `SELECT owner_user_id FROM projects WHERE id = $1`, projectID).Scan(&projectOwnerID); err != nil {
		t.Fatalf("read hidden test project owner: %v", err)
	}
	if projectOwnerID != nil {
		t.Fatalf("hidden test project owner_user_id = %q, want NULL", *projectOwnerID)
	}
}

func TestDeleteUserWithBlockingReferencesReturnsActionableConflict(t *testing.T) {
	pool, tenantID, userID := setupDeleteUserTestDB(t)
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool)}
	projectID := "project_delete_user_ref"
	keyID := "key_delete_user_ref"

	if _, err := pool.Exec(context.Background(), `UPDATE tenants SET is_test = FALSE WHERE id = $1`, tenantID); err != nil {
		t.Fatalf("mark tenant visible: %v", err)
	}

	if _, err := pool.Exec(context.Background(), `
		INSERT INTO projects (id, tenant_id, name, code, environment, owner_user_id, status)
		VALUES ($1, $2, 'referenced project', 'delete-user-ref', 'production', $3, 'active')
	`, projectID, tenantID, userID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, status)
		VALUES ($1, $2, $3, $4, 'hash-delete-user-ref', 'sk-ref', 'active')
	`, keyID, tenantID, projectID, userID); err != nil {
		t.Fatalf("insert internal key: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM internal_keys WHERE id = $1`, keyID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, projectID)
	})

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/users/"+userID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "platform_admin_user",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	DeleteUser(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusConflict, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"referenced project", "应用管理", "先移交负责人", "内部密钥", "密钥管理"} {
		if !strings.Contains(body, want) {
			t.Fatalf("conflict body missing %q: %s", want, body)
		}
	}

	var resp struct {
		Error struct {
			Details struct {
				Blockers []struct {
					Kind  string `json:"kind"`
					Label string `json:"label"`
					Route string `json:"route"`
					Items []struct {
						ID    string `json:"id"`
						Name  string `json:"name"`
						Route string `json:"route"`
					} `json:"items"`
				} `json:"blockers"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal conflict response: %v", err)
	}
	if len(resp.Error.Details.Blockers) != 2 {
		t.Fatalf("blockers len = %d, want 2; body=%s", len(resp.Error.Details.Blockers), body)
	}
	projectBlocker := resp.Error.Details.Blockers[0]
	if projectBlocker.Kind != "project_owner" || projectBlocker.Route != "/apps?project_id=project_delete_user_ref" {
		t.Fatalf("project blocker = %#v", projectBlocker)
	}
	if len(projectBlocker.Items) != 1 || projectBlocker.Items[0].Name != "referenced project" || projectBlocker.Items[0].Route != "/apps?project_id=project_delete_user_ref" {
		t.Fatalf("project blocker items = %#v", projectBlocker.Items)
	}
	keyBlocker := resp.Error.Details.Blockers[1]
	if keyBlocker.Kind != "internal_key" || len(keyBlocker.Items) != 1 || !strings.Contains(keyBlocker.Items[0].Route, "/keys?project_id=project_delete_user_ref") {
		t.Fatalf("key blocker = %#v", keyBlocker)
	}

	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE tenant_id = $1 AND id = $2`, tenantID, userID).Scan(&count); err != nil {
		t.Fatalf("count user: %v", err)
	}
	if count != 1 {
		t.Fatalf("referenced user row count = %d, want 1", count)
	}
}
