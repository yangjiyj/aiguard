package repository

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupUserRepositoryTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func cleanupUserListStatsTest(ctx context.Context, pool *pgxpool.Pool) {
	_, _ = pool.Exec(ctx, `DELETE FROM project_users WHERE project_id IN ('project_user_list_visible_owner', 'project_user_list_hidden_owner')`)
	_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE id IN ('project_user_list_visible_owner', 'project_user_list_hidden_owner')`)
	_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id IN ('user_list_visible_owner', 'user_list_hidden_fixture')`)
	_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id IN ('tenant_user_list_visible', 'tenant_user_list_hidden')`)
}

func TestListAllWithStatsHidesTestTenantUsersAndCountsOwnedProjects(t *testing.T) {
	pool := setupUserRepositoryTestDB(t)
	ctx := context.Background()
	cleanupUserListStatsTest(ctx, pool)
	t.Cleanup(func() { cleanupUserListStatsTest(context.Background(), pool) })

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, name, edition, status, is_test)
		VALUES
			('tenant_user_list_visible', '真实单位', 'enterprise', 'active', FALSE),
			('tenant_user_list_hidden', '隐藏测试单位', 'enterprise', 'active', TRUE)
	`); err != nil {
		t.Fatalf("insert tenants: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		VALUES
			('user_list_visible_owner', 'tenant_user_list_visible', 'visible_owner', 'visible@example.local', 'x', 'developer', 'active'),
			('user_list_hidden_fixture', 'tenant_user_list_hidden', 'hidden_fixture', 'hidden@example.local', 'x', 'developer', 'active')
	`); err != nil {
		t.Fatalf("insert users: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO projects (id, tenant_id, name, code, environment, owner_user_id, status)
		VALUES
			('project_user_list_visible_owner', 'tenant_user_list_visible', 'visible owned project', 'visible-owned', 'production', 'user_list_visible_owner', 'active'),
			('project_user_list_hidden_owner', 'tenant_user_list_hidden', 'hidden owned project', 'hidden-owned', 'production', 'user_list_hidden_fixture', 'active')
	`); err != nil {
		t.Fatalf("insert projects: %v", err)
	}

	users, err := NewUserRepository(pool).ListAllWithStats(ctx)
	if err != nil {
		t.Fatalf("list users with stats: %v", err)
	}

	var visible *UserWithStats
	for _, user := range users {
		switch user.ID {
		case "user_list_hidden_fixture":
			t.Fatalf("hidden test tenant user should not be listed: %#v", user)
		case "user_list_visible_owner":
			visible = user
		}
	}
	if visible == nil {
		t.Fatal("visible user not returned")
	}
	if visible.ProjectsCount != 1 {
		t.Fatalf("visible owner projects_count = %d, want 1", visible.ProjectsCount)
	}
}

func TestHasEmergencyAdminRequiresActivePasswordAdmin(t *testing.T) {
	pool := setupUserRepositoryTestDB(t)
	ctx := context.Background()
	tenantID := "tenant_emergency_admin"
	cleanup := func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE tenant_id=$1", tenantID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenantID)
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id,name,edition,status)
		VALUES ($1,$2,'enterprise','active')`, tenantID, tenantID); err != nil {
		t.Fatal(err)
	}
	seedUser := func(id, role, status string, passwordHash *string) {
		if _, err := pool.Exec(ctx, `INSERT INTO users
			(id,tenant_id,username,email,password_hash,role,status)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			id, tenantID, id, id+"@example.local", passwordHash, role, status); err != nil {
			t.Fatal(err)
		}
	}
	hash := "bcrypt"
	empty := ""
	seedUser("developer-with-password", "developer", "active", &hash)
	seedUser("disabled-admin", "platform_admin", "disabled", &hash)
	seedUser("sso-only-admin", "tenant_owner", "active", &empty)
	seedUser("null-password-admin", "tenant_admin", "active", nil)

	repo := NewUserRepository(pool)
	ok, err := repo.HasEmergencyAdmin(ctx, tenantID)
	if err != nil || ok {
		t.Fatalf("expected unavailable, got ok=%v err=%v", ok, err)
	}

	seedUser("local-admin", "tenant_owner", "active", &hash)
	ok, err = repo.HasEmergencyAdmin(ctx, tenantID)
	if err != nil || !ok {
		t.Fatalf("expected available, got ok=%v err=%v", ok, err)
	}
}
