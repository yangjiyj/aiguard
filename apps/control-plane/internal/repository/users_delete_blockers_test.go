package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Only the tables ListDeleteBlockers reads, with the columns it filters on.
func newDeleteBlockersFixture(t *testing.T) *UserRepository {
	t.Helper()
	dsn := os.Getenv("RULES_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("RULES_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin database: %v", err)
	}
	schema := fmt.Sprintf("delete_blockers_%d", time.Now().UnixNano())
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		admin.Close()
		t.Fatalf("parse database config: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		admin.Close()
		t.Fatalf("connect isolated database: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+ident+" CASCADE")
		admin.Close()
	})
	for _, stmt := range []string{
		`CREATE TABLE tenants (id VARCHAR(64) PRIMARY KEY, is_test BOOLEAN NOT NULL DEFAULT FALSE)`,
		`CREATE TABLE projects (
			id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL, name VARCHAR(255) NOT NULL,
			owner_user_id VARCHAR(64), status VARCHAR(32) NOT NULL DEFAULT 'active',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
		`CREATE TABLE internal_keys (
			id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL, user_id VARCHAR(64),
			project_id VARCHAR(64), key_prefix VARCHAR(64), status VARCHAR(32) NOT NULL DEFAULT 'active',
			deleted_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
		`INSERT INTO tenants(id, is_test) VALUES ('t_real', FALSE), ('t_test', TRUE)`,
		`INSERT INTO projects(id, tenant_id, name, status) VALUES
			('p_live', 't_real', '在用应用', 'active'),
			('p_gone', 't_real', '已删应用', 'deleted')`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create fixture schema: %v", err)
		}
	}
	return NewUserRepository(pool)
}

func blockerByKind(blockers []UserDeleteBlocker, kind string) *UserDeleteBlocker {
	for i := range blockers {
		if blockers[i].Kind == kind {
			return &blockers[i]
		}
	}
	return nil
}

func TestListDeleteBlockersOnlyReportsResourcesThatStillExist(t *testing.T) {
	repo := newDeleteBlockersFixture(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := repo.db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	key := func(id, user, project, status string, deleted bool) {
		t.Helper()
		var deletedAt any
		if deleted {
			deletedAt = time.Now()
		}
		var projectID any
		if project != "" {
			projectID = project
		}
		exec(`INSERT INTO internal_keys(id, tenant_id, user_id, project_id, key_prefix, status, deleted_at)
			VALUES ($1, 't_real', $2, $3, $4, $5, $6)`, id, user, projectID, "jjd_"+id, status, deletedAt)
	}

	// u_live: a working key and a live app: both must still block, with a route to them
	key("k_live", "u_live", "p_live", "active", false)
	exec(`INSERT INTO projects(id, tenant_id, name, owner_user_id) VALUES ('p_owned', 't_real', '负责的应用', 'u_live')`)
	// u_deleted_key: the customer deleted the key in key management (soft delete: deleted_at set)
	key("k_deleted", "u_deleted_key", "p_live", "revoked", true)
	// u_revoked_key: the key was disabled; "删除或禁用" is exactly what the dialog asks for
	key("k_revoked", "u_revoked_key", "p_live", "revoked", false)
	// u_gone_app: the key's app was deleted afterwards
	key("k_in_gone_app", "u_gone_app", "p_gone", "active", false)
	// u_gone_owner: owns an app that was already deleted
	exec(`INSERT INTO projects(id, tenant_id, name, owner_user_id, status) VALUES ('p_gone_owned', 't_real', '已删应用2', 'u_gone_owner', 'deleted')`)
	// u_no_project: a key without an app must not break the lookup
	key("k_no_project", "u_no_project", "", "active", false)
	// u_test_tenant: hidden test tenants never block
	exec(`INSERT INTO internal_keys(id, tenant_id, user_id, project_id, key_prefix) VALUES ('k_test', 't_test', 'u_test_tenant', NULL, 'jjd_test')`)

	live, err := repo.ListDeleteBlockers(ctx, "u_live")
	if err != nil {
		t.Fatalf("u_live: %v", err)
	}
	keyBlocker, ownerBlocker := blockerByKind(live, "internal_key"), blockerByKind(live, "project_owner")
	if keyBlocker == nil || keyBlocker.Count != 1 || len(keyBlocker.Items) != 1 || keyBlocker.Items[0].ID != "k_live" {
		t.Fatalf("a working key must still block: %#v", live)
	}
	if want := "/keys?project_id=p_live&key_id=k_live"; keyBlocker.Items[0].Route != want {
		t.Fatalf("key route=%q want %q", keyBlocker.Items[0].Route, want)
	}
	if ownerBlocker == nil || ownerBlocker.Count != 1 || ownerBlocker.Items[0].ID != "p_owned" {
		t.Fatalf("a live app owner must still block: %#v", live)
	}

	for user, why := range map[string]string{
		"u_deleted_key": "key already deleted in key management",
		"u_revoked_key": "key already disabled",
		"u_gone_app":    "key belongs to an already deleted app",
		"u_gone_owner":  "owner of an already deleted app",
		"u_test_tenant": "hidden test tenant",
	} {
		blockers, err := repo.ListDeleteBlockers(ctx, user)
		if err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		if len(blockers) != 0 {
			t.Fatalf("%s (%s) must not be blocked by a resource that is already gone: %#v", user, why, blockers)
		}
	}

	noProject, err := repo.ListDeleteBlockers(ctx, "u_no_project")
	if err != nil {
		t.Fatalf("a key without an app must not make the blocker lookup fail: %v", err)
	}
	if b := blockerByKind(noProject, "internal_key"); b == nil || b.Count != 1 {
		t.Fatalf("key without an app should still block: %#v", noProject)
	}
}
