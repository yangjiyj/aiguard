package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// M4：GetUserDetail 返回的 teams 应带部门中文名（team_name），避免详情页只显示 UUID。
func TestGetUserDetailTeamsIncludeTeamName(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}

	const (
		tenantID = "tenant_udetail_teamname_test"
		teamID   = "team_udetail_teamname_test"
		userID   = "user_udetail_teamname_test"
		teamName = "研发一部"
	)

	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM team_members WHERE user_id = $1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM teams WHERE id = $1`, teamID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	}
	cleanup()

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, name, edition, status, is_test)
		VALUES ($1, $1, 'enterprise', 'active', TRUE)
	`, tenantID); err != nil {
		pool.Close()
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		VALUES ($1, $2, 'udetail', 'udetail@example.com', 'x', 'developer', 'active')
	`, userID, tenantID); err != nil {
		pool.Close()
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO teams (id, tenant_id, name, path)
		VALUES ($1, $2, $3, $4)
	`, teamID, tenantID, teamName, "/"+teamID); err != nil {
		pool.Close()
		t.Fatalf("insert team: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE users
		SET department_id=$1, department_assignment_mode='manual', department_assignment_source='admin'
		WHERE tenant_id=$2 AND id=$3
	`, teamID, tenantID, userID); err != nil {
		pool.Close()
		t.Fatalf("assign user department: %v", err)
	}

	t.Cleanup(func() {
		cleanup()
		pool.Close()
	})

	deps := &Dependencies{
		UserRepo:            repository.NewUserRepository(pool),
		PermissionGrantRepo: repository.NewPermissionGrantRepository(pool),
		TeamMemberRepo:      repository.NewTeamMemberRepository(pool),
		ProjectUserRepo:     repository.NewProjectUserRepository(pool),
		LoginHistoryRepo:    repository.NewUserLoginHistoryRepository(pool),
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/users/"+userID+"/detail", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "platform_admin_user",
		TenantID: tenantID,
		Role:     "platform_admin",
		Status:   "active",
	}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	GetUserDetail(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Teams []struct {
			TeamID   string `json:"team_id"`
			TeamName string `json:"team_name"`
			Name     string `json:"name"`
			Role     string `json:"role"`
		} `json:"teams"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析详情响应失败: %v; body=%s", err, w.Body.String())
	}

	if len(resp.Teams) != 1 {
		t.Fatalf("teams 数量 = %d, want 1; body=%s", len(resp.Teams), w.Body.String())
	}
	tm := resp.Teams[0]
	if tm.TeamID != teamID {
		t.Fatalf("team_id = %q, want %q", tm.TeamID, teamID)
	}
	if tm.TeamName != teamName {
		t.Fatalf("team_name = %q, want %q", tm.TeamName, teamName)
	}
	if tm.Name != teamName {
		t.Fatalf("name = %q, want %q", tm.Name, teamName)
	}
	if tm.Role != "member" {
		t.Fatalf("role = %q, want member", tm.Role)
	}
}
