package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func setupUsageScopeDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

func seedUsageScopeTenantUser(t *testing.T, pool *pgxpool.Pool, role string) (string, string) {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	tenantID := "tenant_usage_scope_" + suffix
	userID := "user_usage_scope_" + suffix
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name, edition, status) VALUES ($1, $2, 'enterprise', 'active')`, tenantID, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $3, $4, 'active')`, userID, tenantID, userID, role); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM project_users WHERE user_id = $1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM team_members WHERE user_id = $1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM teams WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})
	return tenantID, userID
}

func usageScopeRequest(tenantID, userID, role string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/usage/summary", nil)
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       userID,
		TenantID: tenantID,
		Role:     role,
		Status:   "active",
	}))
}

func insertUsageScopeTeamProject(t *testing.T, pool *pgxpool.Pool, tenantID, userID, teamID, projectID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO teams (id, tenant_id, name, path) VALUES ($1, $2, $3, $4)`, teamID, tenantID, teamID, "/"+teamID); err != nil {
		t.Fatalf("insert team: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE users
		SET department_id=$1, department_assignment_mode='manual', department_assignment_source='admin'
		WHERE tenant_id=$2 AND id=$3
	`, teamID, tenantID, userID); err != nil {
		t.Fatalf("assign user department: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, owner_user_id, status, team_id) VALUES ($1, $2, $3, $4, 'active', $5)`, projectID, tenantID, projectID, userID, teamID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
}

func seedUsageScopeProjectBinding(t *testing.T, pool *pgxpool.Pool, tenantID, userID string) string {
	t.Helper()
	ctx := context.Background()
	projectID := "proj_usage_scope_" + fmt.Sprint(time.Now().UnixNano())
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, owner_user_id, status) VALUES ($1, $2, $3, $4, 'active')`, projectID, tenantID, projectID, userID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_users (project_id, user_id, role) VALUES ($1, $2, 'developer')`, projectID, userID); err != nil {
		t.Fatalf("insert project user: %v", err)
	}
	return projectID
}

func TestResolveUsageScopeDeveloperPrefersTeamProjects(t *testing.T) {
	pool := setupUsageScopeDB(t)
	tenantID, userID := seedUsageScopeTenantUser(t, pool, "developer")
	suffix := fmt.Sprint(time.Now().UnixNano())
	teamID := "team_usage_scope_" + suffix
	projectID := "proj_usage_scope_" + suffix
	insertUsageScopeTeamProject(t, pool, tenantID, userID, teamID, projectID)
	deps := &Dependencies{
		TeamMemberRepo:  repository.NewTeamMemberRepository(pool),
		ProjectUserRepo: repository.NewProjectUserRepository(pool),
	}

	scope, ok := resolveUsageScope(usageScopeRequest(tenantID, userID, "developer"), deps)
	if !ok || scope.FullTenant || len(scope.ProjectIDs) != 1 || scope.ProjectIDs[0] != projectID {
		t.Fatalf("unexpected scope: ok=%v scope=%+v", ok, scope)
	}
	if len(scope.TeamIDs) != 1 || scope.TeamIDs[0] != teamID {
		t.Fatalf("unexpected teams in scope: %+v", scope)
	}
}

func TestResolveUsageScopeTenantOwnerUsesFullTenant(t *testing.T) {
	scope, ok := resolveUsageScope(usageScopeRequest("tenant_owner_scope", "u_owner", "tenant_owner"), &Dependencies{})
	if !ok || !scope.FullTenant {
		t.Fatalf("tenant owner should use full tenant scope: ok=%v scope=%+v", ok, scope)
	}
}

func TestResolveUsageScopeDeveloperFallsBackToProjectBinding(t *testing.T) {
	pool := setupUsageScopeDB(t)
	tenantID, userID := seedUsageScopeTenantUser(t, pool, "developer")
	projectID := seedUsageScopeProjectBinding(t, pool, tenantID, userID)
	deps := &Dependencies{ProjectUserRepo: repository.NewProjectUserRepository(pool)}

	scope, ok := resolveUsageScope(usageScopeRequest(tenantID, userID, "developer"), deps)
	if !ok || len(scope.ProjectIDs) != 1 || scope.ProjectIDs[0] != projectID {
		t.Fatalf("expected project binding fallback, got ok=%v scope=%+v", ok, scope)
	}
}
