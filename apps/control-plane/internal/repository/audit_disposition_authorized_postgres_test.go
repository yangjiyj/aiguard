package repository

import (
	"context"
	"errors"
	"testing"
)

func TestUpsertAuthorizedDispositionChecksSubjectProjectAndLinkedTargetOnPostgres(t *testing.T) {
	db := verifiedModelsTestDB(t)
	ctx := context.Background()
	_, err := db.Exec(ctx, `
		ALTER TABLE request_logs
			ADD COLUMN project_id TEXT,
			ADD COLUMN user_id TEXT,
			ADD COLUMN client_id TEXT,
			ADD COLUMN session_id TEXT;
		CREATE TABLE users (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, username TEXT,
			email TEXT, phone TEXT, password_hash TEXT, must_change_password BOOLEAN DEFAULT FALSE,
			role TEXT, status TEXT, external_subject TEXT, department_id TEXT,
			department_assignment_mode TEXT DEFAULT 'manual',
			department_assignment_source TEXT DEFAULT 'manual',
			department_assignment_rule_id TEXT, department_resolved_at TIMESTAMPTZ,
			department_version BIGINT DEFAULT 1, updated_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE TABLE internal_keys (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT,
			key_hash TEXT, status TEXT DEFAULT 'active', agent_instance_id varchar(128));
		CREATE TABLE audit_dispositions (
			id TEXT PRIMARY KEY DEFAULT md5(random()::text),
			tenant_id TEXT NOT NULL, subject_type TEXT NOT NULL, subject_id TEXT NOT NULL,
			status TEXT NOT NULL, note TEXT, operator_id TEXT, operator_name TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (tenant_id, subject_type, subject_id)
		);
		INSERT INTO tenants(id,name) VALUES ('tenant-a','A'),('tenant-b','B');
		INSERT INTO users(id,tenant_id,username,role,status)
			VALUES ('user-a','tenant-a','A','developer','active'),
			       ('user-other','tenant-a','Other','developer','active'),
			       ('user-b','tenant-b','B','developer','active');
		INSERT INTO internal_keys(id,tenant_id,user_id,key_hash)
			VALUES ('key-a','tenant-a','user-a',repeat('a',64)),
			       ('key-other','tenant-a','user-other',repeat('b',64)),
			       ('key-b','tenant-b','user-b',repeat('c',64));
		INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,client_id)
			VALUES ('log-a','request-a','tenant-a','project-a','user-a','key-a'),
			       ('log-denied','request-denied','tenant-a','project-b','user-other','key-other'),
			       ('log-b','request-b','tenant-b','project-b','user-b','key-b');
	`)
	if err != nil {
		t.Fatal(err)
	}

	repo := NewAuditDispositionRepository(db)
	newDisposition := func(subjectID string) *AuditDisposition {
		return &AuditDisposition{
			TenantID: "tenant-a", SubjectType: "request", SubjectID: subjectID,
			Status: "accepted", OperatorID: "admin-a", OperatorName: "Admin A",
		}
	}
	if _, err := repo.UpsertAuthorized(ctx, newDisposition("request-a"), []string{"project-a"}, "revoke_key", "key-a"); err != nil {
		t.Fatalf("linked same-tenant key must be accepted: %v", err)
	}
	if _, err := repo.UpsertAuthorized(ctx, newDisposition("request-a"), []string{"project-a"}, "ban_user", "user-a"); err != nil {
		t.Fatalf("linked same-tenant user must be accepted: %v", err)
	}
	for _, tc := range []struct {
		name, subject, action, target string
	}{
		{name: "unrelated key", subject: "request-a", action: "revoke_key", target: "key-other"},
		{name: "cross tenant user", subject: "request-a", action: "ban_user", target: "user-b"},
		{name: "invisible project", subject: "request-denied", action: "ban_user", target: "user-other"},
		{name: "cross tenant subject", subject: "request-b", action: "ban_user", target: "user-b"},
		{name: "missing subject", subject: "missing", action: "", target: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := repo.UpsertAuthorized(ctx, newDisposition(tc.subject), []string{"project-a"}, tc.action, tc.target)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("error=%v, want ErrNotFound", err)
			}
		})
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_dispositions WHERE subject_id <> 'request-a'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("unauthorized subjects wrote %d disposition rows", count)
	}

	updated, err := NewUserRepository(db).UpdateStatusForTenant(ctx, "tenant-a", "user-b", "disabled")
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Fatal("tenant-a must not update tenant-b user")
	}
	var status string
	if err := db.QueryRow(ctx, `SELECT status FROM users WHERE id='user-b'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("cross-tenant user status changed to %q", status)
	}
}
