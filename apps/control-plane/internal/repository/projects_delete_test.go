package repository

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func projectDeleteTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	db := statusTestDB(t)
	if _, err := db.Exec(context.Background(), `
		CREATE TABLE projects(id varchar(64) PRIMARY KEY, tenant_id varchar(64) NOT NULL REFERENCES tenants(id), name varchar(255) NOT NULL, code varchar(64), environment varchar(32), owner_user_id varchar(64), team_id varchar(64), status varchar(32) NOT NULL DEFAULT 'active', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), model_whitelist jsonb NOT NULL DEFAULT '[]', quota_limits jsonb NOT NULL DEFAULT '{}');
		CREATE TABLE internal_keys(id varchar(64) PRIMARY KEY, tenant_id varchar(64) NOT NULL REFERENCES tenants(id), project_id varchar(64) NOT NULL REFERENCES projects(id), status varchar(32) NOT NULL DEFAULT 'active', last_used_at timestamptz, agent_instance_id varchar(128));
		ALTER TABLE request_logs ADD COLUMN project_id varchar(64) REFERENCES projects(id);
	`); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestProjectRepositoryDeleteRevokesKeysAndPreservesHistoricalRequests(t *testing.T) {
	db := projectDeleteTestDB(t)
	ctx := context.Background()
	const tenantID = "tenant-project-delete"
	const projectID = "project-delete"
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id) VALUES($1)`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects(id, tenant_id, name) VALUES($1, $2, 'delete me')`, projectID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO internal_keys(id, tenant_id, project_id) VALUES('key-project-delete', $1, $2)`, tenantID, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO request_logs(id, request_id, tenant_id, project_id) VALUES('request-project-delete', 'request-delete', $1, $2)`, tenantID, projectID); err != nil {
		t.Fatal(err)
	}

	repo := NewProjectRepository(db)
	if err := repo.Delete(ctx, tenantID, projectID); err != nil {
		t.Fatalf("delete project with key and historical requests: %v", err)
	}

	var projectStatus, keyStatus, requestProjectID string
	if err := db.QueryRow(ctx, `SELECT status FROM projects WHERE id = $1`, projectID).Scan(&projectStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT status FROM internal_keys WHERE id = 'key-project-delete'`).Scan(&keyStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT project_id FROM request_logs WHERE id = 'request-project-delete'`).Scan(&requestProjectID); err != nil {
		t.Fatal(err)
	}
	if projectStatus != "deleted" || keyStatus != "revoked" || requestProjectID != projectID {
		t.Fatalf("project=%q key=%q historical project=%q", projectStatus, keyStatus, requestProjectID)
	}

	project, err := repo.GetByID(ctx, tenantID, projectID)
	if err != nil || project != nil {
		t.Fatalf("deleted project should not be retrievable: project=%#v err=%v", project, err)
	}
	projects, err := repo.List(ctx, tenantID)
	if err != nil || len(projects) != 0 {
		t.Fatalf("deleted project should not be listed: projects=%#v err=%v", projects, err)
	}
}

func TestProjectRepositoryDeleteIsTenantScoped(t *testing.T) {
	db := projectDeleteTestDB(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id) VALUES('tenant-project-owner'), ('tenant-project-other')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects(id, tenant_id, name) VALUES('project-owned', 'tenant-project-owner', 'owned')`); err != nil {
		t.Fatal(err)
	}

	err := NewProjectRepository(db).Delete(ctx, "tenant-project-other", "project-owned")
	if err == nil || err.Error() != "project not found" {
		t.Fatalf("cross-tenant delete error = %v", err)
	}

	var status string
	if err := db.QueryRow(ctx, `SELECT status FROM projects WHERE id = 'project-owned'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("cross-tenant delete changed project status to %q", status)
	}
}
