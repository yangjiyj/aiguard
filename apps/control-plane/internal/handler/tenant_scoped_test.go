package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// setupTenantScopedDB 连接测试库，用于需要真实 TenantRepo 的用例。
func setupTenantScopedDB(t *testing.T) *pgxpool.Pool {
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
	t.Cleanup(func() { pool.Close() })
	return pool
}

// buildTenantScopedDeps 构建仅含跨租户接口所需字段的 Dependencies。
// pool 为 nil 时跳过需要真库的字段（用于纯门禁测试）。
func buildTenantScopedDeps(pool *pgxpool.Pool) *Dependencies {
	deps := &Dependencies{
		SystemRepo: &orgTestSystemRepo{},
	}
	if pool != nil {
		deps.TenantRepo = repository.NewTenantRepository(pool)
		deps.TeamRepo = repository.NewTeamRepository(pool)
		deps.UserRepo = repository.NewUserRepository(pool)
		deps.ProjectRepo = repository.NewProjectRepository(pool)
		deps.KeyRepo = repository.NewInternalKeyRepository(pool)
	}
	return deps
}

// withTenantScopedUserCtx 注入指定 role 的用户到 ctx。
func withTenantScopedUserCtx(r *http.Request, tenantID, userID, role string) *http.Request {
	u := &repository.User{
		ID:       userID,
		TenantID: tenantID,
		Role:     role,
		Status:   "active",
	}
	return r.WithContext(context.WithValue(r.Context(), auth.UserKey, u))
}

// chiCtxWithTenantID 注入 chi URLParam "id"（tenantID）。
// 注意：org_handler_test.go 里已有 chiCtxWithID，此处为避免命名冲突单独写。
func chiCtxWithTenantID(r *http.Request, tenantID string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", tenantID)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// TestTenantScopedForbidden_NonPlatformAdmin 验证非 platform_admin 调用跨租户接口返回 403。
// 门禁在查库前就返回，不需要真库，deps.TenantRepo 为 nil 也不会 panic。
func TestTenantScopedForbidden_NonPlatformAdmin(t *testing.T) {
	// 不传 pool，TenantRepo 为 nil；代码在 role 检查处就返回，不会到 GetByID
	deps := buildTenantScopedDeps(nil)

	handlers := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"ListTenantUsers", ListTenantUsers(deps)},
		{"ListTenantTeams", ListTenantTeams(deps)},
		{"ListTenantProjects", ListTenantProjects(deps)},
		{"ListTenantKeys", ListTenantKeys(deps)},
	}

	for _, tc := range handlers {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/v1/tenants/some-id/"+tc.name, nil)
			// role=developer，不是 platform_admin
			req = withTenantScopedUserCtx(req, "tenant_123", "user_123", "developer")
			req = chiCtxWithTenantID(req, "some-id")

			rr := httptest.NewRecorder()
			tc.handler(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Errorf("%s: want 403, got %d (body: %s)", tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestTenantScopedNotFound_UnknownTenant 验证 platform_admin 查询不存在的单位返回 404。
// 需要真库（TenantRepo.GetByID 在库里查），用一个肯定不存在的 ID。
func TestTenantScopedNotFound_UnknownTenant(t *testing.T) {
	pool := setupTenantScopedDB(t)
	deps := buildTenantScopedDeps(pool)

	const nonExistentID = "tenant_does_not_exist_xyzabc"

	handlers := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"ListTenantUsers", ListTenantUsers(deps)},
		{"ListTenantTeams", ListTenantTeams(deps)},
		{"ListTenantProjects", ListTenantProjects(deps)},
		{"ListTenantKeys", ListTenantKeys(deps)},
	}

	for _, tc := range handlers {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/v1/tenants/"+nonExistentID+"/"+tc.name, nil)
			req = withTenantScopedUserCtx(req, "tenant_platform", "user_platform", "platform_admin")
			req = chiCtxWithTenantID(req, nonExistentID)

			rr := httptest.NewRecorder()
			tc.handler(rr, req)

			if rr.Code != http.StatusNotFound {
				t.Errorf("%s: want 404, got %d (body: %s)", tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestCreateTenantIsDisabledForPlatformAdmin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/tenants", strings.NewReader(`{"name":"blocked unit","edition":"enterprise"}`))
	req = withTenantScopedUserCtx(req, "tenant_platform", "user_platform", "platform_admin")
	rr := httptest.NewRecorder()

	CreateTenant(nil).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code":"unit_creation_disabled"`) {
		t.Fatalf("body=%s want unit_creation_disabled", rr.Body.String())
	}
}

func TestDeleteTenantProjectSoftDeletesProjectAndRevokesKeys(t *testing.T) {
	pool := setupTenantScopedDB(t)
	deps := buildTenantScopedDeps(pool)
	ctx := context.Background()
	suffix := uuid.NewString()[:8]
	tenantID := "tenant_delete_project_" + suffix
	projectID := "project_delete_" + suffix
	keyID := "key_delete_" + suffix

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id,name,edition,status,is_test)
		VALUES ($1,$1,'enterprise','active',TRUE)
	`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,code,status)
		VALUES ($1,$2,$1,$1,'active')
	`, projectID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO internal_keys (id,tenant_id,project_id,name,key_prefix,key_hash,status)
		VALUES ($1,$2,$3,$1,'vkey-test','hash-test','active')
	`, keyID, tenantID, projectID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM internal_keys WHERE id=$1`, keyID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM projects WHERE id=$1`, projectID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/tenants/"+tenantID+"/projects/"+projectID, nil)
	req = withTenantScopedUserCtx(req, "tenant_platform", "user_platform", "platform_admin")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", tenantID)
	rctx.URLParams.Add("projectId", projectID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	DeleteTenantProject(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}
	var projectStatus, keyStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM projects WHERE id=$1`, projectID).Scan(&projectStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM internal_keys WHERE id=$1`, keyID).Scan(&keyStatus); err != nil {
		t.Fatal(err)
	}
	if projectStatus != "deleted" || keyStatus != "revoked" {
		t.Fatalf("project status=%q key status=%q, want deleted/revoked", projectStatus, keyStatus)
	}
}

func TestDeleteTenantKeepsAuditRowsAndHidesTenant(t *testing.T) {
	pool := setupTenantScopedDB(t)
	deps := buildTenantScopedDeps(pool)
	ctx := context.Background()
	suffix := uuid.NewString()[:8]
	tenantID := "tenant_soft_delete_" + suffix
	projectID := "project_soft_delete_" + suffix

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id,name,edition,status,is_test)
		VALUES ($1,$1,'enterprise','active',FALSE)
	`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO projects (id,tenant_id,name,code,status)
		VALUES ($1,$2,$1,$1,'deleted')
	`, projectID, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM projects WHERE id=$1`, projectID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/tenants/"+tenantID, nil)
	req = withTenantScopedUserCtx(req, "tenant_platform", "user_platform", "platform_admin")
	req = chiCtxWithTenantID(req, tenantID)
	rr := httptest.NewRecorder()

	DeleteTenant(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}
	var tenantStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1`, tenantID).Scan(&tenantStatus); err != nil {
		t.Fatalf("tenant audit row was removed: %v", err)
	}
	if tenantStatus != "deleted" {
		t.Fatalf("tenant status=%q want deleted", tenantStatus)
	}
	var projectCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM projects WHERE id=$1`, projectID).Scan(&projectCount); err != nil {
		t.Fatal(err)
	}
	if projectCount != 1 {
		t.Fatalf("project audit row count=%d want 1", projectCount)
	}
	if tenant, err := deps.TenantRepo.GetByID(ctx, tenantID); err == nil || tenant != nil {
		t.Fatalf("deleted tenant remains addressable: tenant=%v err=%v", tenant, err)
	}
	visibleTenants, err := deps.TenantRepo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range visibleTenants {
		if tenant.ID == tenantID {
			t.Fatalf("deleted tenant %q remains in the visible unit list", tenantID)
		}
	}
	policyTenantIDs, err := deps.TenantRepo.ListSecurityPolicyTenantIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range policyTenantIDs {
		if id == tenantID {
			t.Fatalf("deleted tenant %q remains in policy initialization targets", tenantID)
		}
	}
}

func TestListTenantTeamsAuthorizationMatrix(t *testing.T) {
	pool := setupTenantScopedDB(t)
	deps := buildTenantScopedDeps(pool)
	ctx := context.Background()
	tenantID := "tenant_teams_" + uuid.NewString()[:8]
	teamID := "team_teams_" + uuid.NewString()[:8]
	if err := deps.TenantRepo.Create(ctx, &repository.Tenant{
		ID: tenantID, Name: "Target Business Unit", Edition: "enterprise", Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := deps.TeamRepo.Create(ctx, &repository.Team{
		ID: teamID, TenantID: tenantID, Name: "Target Engineering",
	}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, name, edition, status, config_json)
		VALUES ($1, 'Reserved System', 'enterprise', 'active', '{}')
		ON CONFLICT (id) DO NOTHING
	`, repository.SystemTenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM teams WHERE id = $1`, teamID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	tests := []struct {
		name       string
		actor      *repository.User
		targetID   string
		wantStatus int
		wantCode   string
	}{
		{name: "unauthenticated", targetID: tenantID, wantStatus: http.StatusUnauthorized, wantCode: "unauthorized"},
		{name: "ordinary user", actor: &repository.User{ID: "viewer", TenantID: tenantID, Role: "viewer"}, targetID: tenantID, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "tenant admin own tenant", actor: &repository.User{ID: "tenant-admin", TenantID: tenantID, Role: "tenant_admin"}, targetID: tenantID, wantStatus: http.StatusOK},
		{name: "tenant admin cross tenant", actor: &repository.User{ID: "tenant-admin", TenantID: "tenant_other", Role: "tenant_admin"}, targetID: tenantID, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "platform admin target tenant", actor: &repository.User{ID: "platform-admin", TenantID: "tenant_platform", Role: "platform_admin"}, targetID: tenantID, wantStatus: http.StatusOK},
		{name: "platform admin missing tenant", actor: &repository.User{ID: "platform-admin", TenantID: "tenant_platform", Role: "platform_admin"}, targetID: "tenant_missing_safe", wantStatus: http.StatusNotFound, wantCode: "not_found"},
		{name: "platform admin system tenant", actor: &repository.User{ID: "platform-admin", TenantID: "tenant_platform", Role: "platform_admin"}, targetID: repository.SystemTenantID, wantStatus: http.StatusNotFound, wantCode: "not_found"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := chiCtxWithTenantID(httptest.NewRequest(http.MethodGet, "/admin/v1/tenants/"+tc.targetID+"/teams", nil), tc.targetID)
			if tc.actor != nil {
				req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, tc.actor))
			}
			rr := httptest.NewRecorder()
			ListTenantTeams(deps).ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantCode != "" && decodeErrorCode(t, rr.Body.String()) != tc.wantCode {
				t.Fatalf("body=%s want code=%s", rr.Body.String(), tc.wantCode)
			}
			if tc.wantStatus == http.StatusOK && (!strings.Contains(rr.Body.String(), teamID) || !strings.Contains(rr.Body.String(), "Target Engineering")) {
				t.Fatalf("target teams missing: %s", rr.Body.String())
			}
			if tc.wantStatus != http.StatusOK && (strings.Contains(rr.Body.String(), tenantID) || strings.Contains(rr.Body.String(), "Target Business Unit")) {
				t.Fatalf("target tenant leaked: %s", rr.Body.String())
			}
		})
	}
}

func TestListTenantTeamsWithEnforcedRBAC(t *testing.T) {
	t.Setenv("UAG_RBAC_ENFORCE", "true")
	if !permission.RBACEnforceEnabled() {
		t.Fatal("RBAC enforce mode is not enabled")
	}
	pool := setupTenantScopedDB(t)
	deps := buildTenantScopedDeps(pool)
	ctx := context.Background()
	suffix := uuid.NewString()[:8]
	tenantID := "tenant_rbac_teams_" + suffix
	otherTenantID := "tenant_rbac_other_" + suffix
	teamID := "team_rbac_teams_" + suffix
	userID := "tenant_admin_" + suffix
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id,name,edition,status,is_test) VALUES
			($1,$1,'enterprise','active',TRUE),
			($2,$2,'enterprise','active',TRUE)
	`, tenantID, otherTenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO teams (id,tenant_id,name,path) VALUES ($1,$2,'RBAC Engineering',$3)
	`, teamID, tenantID, "/"+teamID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id,tenant_id,username,role,status)
		VALUES ($1,$2,$1,'tenant_admin','active')
	`, userID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO permission_grants (id,tenant_id,user_id,scope_type,scope_id,role,granted_by)
		VALUES ($3,$2,$1,'tenant',$2,'tenant_admin',$1)
	`, userID, tenantID, "grant_"+userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id,name,edition,status,is_test)
		VALUES ($1,$1,'enterprise','active',TRUE)
		ON CONFLICT (id) DO NOTHING
	`, repository.SystemTenantID); err != nil {
		t.Fatal(err)
	}
	if err := permission.SeedBuiltinRoles(ctx, pool); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM permission_grants WHERE user_id=$1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM teams WHERE id=$1`, teamID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantID, otherTenantID)
	})

	checker := permission.NewChecker(pool, permission.NewGrantsCache())
	router := chi.NewRouter()
	router.Use(permission.Middleware(checker, nil, !permission.RBACEnforceEnabled()))
	router.Get("/admin/v1/tenants/{id}/teams", ListTenantTeams(deps))
	actor := &repository.User{ID: userID, TenantID: tenantID, Role: "tenant_admin", Status: "active"}
	tests := []struct {
		name       string
		targetID   string
		wantStatus int
		wantCode   string
	}{
		{name: "own tenant", targetID: tenantID, wantStatus: http.StatusOK},
		{name: "cross tenant", targetID: otherTenantID, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "system tenant", targetID: repository.SystemTenantID, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/v1/tenants/"+tc.targetID+"/teams", nil)
			req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, actor))
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantCode != "" && decodeErrorCode(t, rr.Body.String()) != tc.wantCode {
				t.Fatalf("body=%s want code=%s", rr.Body.String(), tc.wantCode)
			}
			if tc.wantStatus == http.StatusOK && !strings.Contains(rr.Body.String(), teamID) {
				t.Fatalf("own tenant team missing: %s", rr.Body.String())
			}
		})
	}
}
