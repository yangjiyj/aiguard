package localidentity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupProvisionerDB(t *testing.T) (*pgxpool.Pool, string, string, string) {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID, actorID, departmentID := "tenant_local_"+suffix, "actor_local_"+suffix, "dept_local_"+suffix
	_, err = db.Exec(context.Background(), `
		INSERT INTO tenants (id,name,edition,status,is_test) VALUES ($1,$1,'enterprise','active',TRUE)
	`, tenantID)
	if err == nil {
		_, err = db.Exec(context.Background(), `
			INSERT INTO users (id,tenant_id,username,role,status,department_assignment_mode,department_assignment_source)
			VALUES ($2,$1,$2,'platform_admin','active','emergency','local')
		`, tenantID, actorID)
	}
	if err == nil {
		// teams.id is VARCHAR while the concatenation yields text, so the bound
		// parameter needs an explicit cast; $2 was never referenced by the SQL.
		_, err = db.Exec(context.Background(), `
			INSERT INTO teams (id,tenant_id,name,path) VALUES ($2,$1,'???','/' || $2::varchar)
		`, tenantID, departmentID)
	}
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM audit_operations WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(context.Background(), `DELETE FROM users WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenantID)
		db.Close()
	})
	return db, tenantID, actorID, departmentID
}

func TestPostgresProvisionerCreatesStableIdentityDepartmentAndGrant(t *testing.T) {
	db, tenantID, actorID, departmentID := setupProvisionerDB(t)
	ctx := context.Background()
	issuer := "https://sso.example.test/sso/realms/jjdguard"
	p, err := NewProvisioner(db, issuer)
	if err != nil {
		t.Fatal(err)
	}
	userID := "local_" + tenantID[len(tenantID)-12:]
	if err := p.Provision(ctx, ProvisionInput{
		ID: userID, TenantID: tenantID, Username: "alice", Email: "alice@example.test",
		Phone: "13800000000", PasswordHash: "bcrypt-hash", MustChangePassword: true,
		Role: "viewer", Status: "provisioning", DepartmentID: departmentID,
		AssignmentMode: "manual", AssignmentSource: "local",
		ExternalSubject: "keycloak-subject-1", ActorID: actorID,
	}); err != nil {
		t.Fatal(err)
	}
	var status, selectedDepartment, legacySubject, linkedIssuer, linkedSubject string
	if err := db.QueryRow(ctx, `
		SELECT u.status,u.department_id,COALESCE(u.external_subject,''),l.issuer,l.external_subject
		FROM users u JOIN user_identity_links l ON l.tenant_id=u.tenant_id AND l.user_id=u.id
		WHERE u.tenant_id=$1 AND u.id=$2
	`, tenantID, userID).Scan(&status, &selectedDepartment, &legacySubject, &linkedIssuer, &linkedSubject); err != nil {
		t.Fatal(err)
	}
	if status != "provisioning" || selectedDepartment != departmentID || legacySubject != "" ||
		linkedIssuer != issuer || linkedSubject != "keycloak-subject-1" {
		t.Fatalf("unexpected provisioned state: status=%q department=%q legacy=%q issuer=%q subject=%q",
			status, selectedDepartment, legacySubject, linkedIssuer, linkedSubject)
	}
	var projectedTeam, scopeID, grantRole string
	if err := db.QueryRow(ctx, `
		SELECT tm.team_id,g.scope_id,g.role FROM team_members tm
		JOIN permission_grants g ON g.user_id=tm.user_id WHERE tm.user_id=$1
	`, userID).Scan(&projectedTeam, &scopeID, &grantRole); err != nil {
		t.Fatal(err)
	}
	if projectedTeam != departmentID || scopeID != tenantID || grantRole != "viewer" {
		t.Fatalf("projection/grant mismatch team=%q scope=%q role=%q", projectedTeam, scopeID, grantRole)
	}
	var createAuditCount, createOutboxCount int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_operations
		WHERE tenant_id=$1 AND target_id=$2 AND action_type='user.create'
		  AND action_detail->>'role'='viewer'
		  AND action_detail::text NOT LIKE '%alice@example.test%'
	`, tenantID, userID).Scan(&createAuditCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM identity_cache_invalidation_outbox WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID).Scan(&createOutboxCount); err != nil {
		t.Fatal(err)
	}
	if createAuditCount != 1 || createOutboxCount != 1 {
		t.Fatalf("create audit=%d outbox=%d", createAuditCount, createOutboxCount)
	}
	var runtimeManaged bool
	if err := db.QueryRow(ctx, "SELECT local_runtime_managed FROM user_identity_links WHERE tenant_id=$1 AND user_id=$2 AND source_type='local'", tenantID, userID).Scan(&runtimeManaged); err != nil || !runtimeManaged {
		t.Fatal("official native provisioning did not mark credential ownership")
	}
	if err := p.Activate(ctx, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	if got, err := p.ExternalSubject(ctx, tenantID, userID); err != nil || got != linkedSubject {
		t.Fatalf("subject=%q err=%v", got, err)
	}
	if err := p.UpdatePasswordHash(ctx, tenantID, userID, "new-hash", false); err != nil {
		t.Fatal(err)
	}
	disposableID := "disposable_" + tenantID[len(tenantID)-12:]
	if err := p.Provision(ctx, ProvisionInput{
		ID: disposableID, TenantID: tenantID, Username: "disposable",
		PasswordHash: "bcrypt-hash", Role: "viewer", Status: "provisioning",
		DepartmentID: departmentID, AssignmentMode: "manual", AssignmentSource: "local",
		ExternalSubject: "keycloak-subject-disposable", ActorID: actorID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteProvisioned(ctx, tenantID, disposableID); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM users WHERE id=$1`, disposableID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("remaining user=%d err=%v", remaining, err)
	}
}

func TestPostgresProvisionerRollsBackAndAuditsSanitizedReconciliation(t *testing.T) {
	db, tenantID, actorID, _ := setupProvisionerDB(t)
	p, err := NewProvisioner(db, "https://sso.example.test/sso/realms/jjdguard")
	if err != nil {
		t.Fatal(err)
	}
	userID := "failed_" + tenantID[len(tenantID)-12:]
	err = p.Provision(context.Background(), ProvisionInput{
		ID: userID, TenantID: tenantID, Username: "failed-user", PasswordHash: "bcrypt-hash",
		Role: "viewer", Status: "provisioning", DepartmentID: "missing-department",
		AssignmentMode: "manual", AssignmentSource: "local",
		ExternalSubject: "subject-sensitive", ActorID: actorID,
	})
	if err == nil {
		t.Fatal("expected invalid department to fail")
	}
	var remaining int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE id=$1`, userID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("partial user=%d err=%v", remaining, err)
	}
	if err := p.MarkReconciliationRequired(context.Background(), ReconciliationInput{
		ID: "reconcile_" + tenantID[len(tenantID)-12:], TenantID: tenantID,
		UserID: userID, ActorID: actorID, Reason: "keycloak_delete_failed",
		SubjectFingerprint: strings.Repeat("a", 64),
		Operation:          "provision", Stage: "delete_compensation",
		Provider: "keycloak", Source: "local",
	}); err != nil {
		t.Fatal(err)
	}
	var detail string
	if err := db.QueryRow(context.Background(), `
		SELECT action_detail::text FROM audit_operations WHERE tenant_id=$1 AND target_id=$2
	`, tenantID, userID).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal([]byte(detail), &fields); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"user_id": userID, "reason": "keycloak_delete_failed", "actor_id": actorID,
		"subject_fingerprint": strings.Repeat("a", 64),
		"operation":           "provision", "stage": "delete_compensation",
		"provider": "keycloak", "source": "local",
	}
	if len(fields) != len(want) {
		t.Fatalf("reconciliation fields=%v", fields)
	}
	for key, value := range want {
		if fields[key] != value {
			t.Fatalf("field %s=%q want=%q detail=%s", key, fields[key], value, detail)
		}
	}
	for _, forbidden := range []string{"subject-sensitive", "raw error", "password", "credential", "token"} {
		if strings.Contains(strings.ToLower(detail), forbidden) {
			t.Fatalf("audit leaked %q: %s", forbidden, detail)
		}
	}
}

func TestPostgresProvisionerRecordsLocalReconciliationWithoutWeakeningDisabledUser(t *testing.T) {
	db, tenantID, actorID, _ := setupProvisionerDB(t)
	ctx := context.Background()
	p, err := NewProvisioner(db, "https://sso.example.test/sso/realms/jjdguard")
	if err != nil {
		t.Fatal(err)
	}
	userID := "emergency_disabled_" + tenantID[len(tenantID)-12:]
	if _, err := db.Exec(ctx, `
		INSERT INTO users (
			id,tenant_id,username,role,status,
			department_assignment_mode,department_assignment_source
		) VALUES ($1,$2,$1,'platform_admin','disabled','emergency','local')
	`, userID, tenantID); err != nil {
		t.Fatal(err)
	}

	if err := p.MarkReconciliationRequired(ctx, ReconciliationInput{
		ID: "reconcile_local_" + tenantID[len(tenantID)-12:], TenantID: tenantID,
		UserID: userID, ActorID: actorID, Reason: "database_status_update_failed_identity_absent",
		Operation: "status_transition", Stage: "database_status_update_failed_identity_absent",
		Provider: "local", Source: "local",
	}); err != nil {
		t.Fatal(err)
	}

	var status, detail string
	if err := db.QueryRow(ctx, `SELECT status FROM users WHERE tenant_id=$1 AND id=$2`, tenantID, userID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `
		SELECT action_detail::text FROM audit_operations
		WHERE tenant_id=$1 AND target_id=$2 AND action_type='local_identity.reconciliation_required'
	`, tenantID, userID).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal([]byte(detail), &fields); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"user_id": userID, "reason": "database_status_update_failed_identity_absent", "actor_id": actorID,
		"subject_fingerprint": "", "operation": "status_transition",
		"stage":    "database_status_update_failed_identity_absent",
		"provider": "local", "source": "local",
	}
	if status != "disabled" || len(fields) != len(want) {
		t.Fatalf("status=%q reconciliation fields=%v", status, fields)
	}
	for key, value := range want {
		if fields[key] != value {
			t.Fatalf("field %s=%q want=%q detail=%s", key, fields[key], value, detail)
		}
	}
}

func TestPostgresProvisionerBindsEmergencyIdentityAndTransitionsRoleAtomically(t *testing.T) {
	db, tenantID, actorID, departmentID := setupProvisionerDB(t)
	ctx := context.Background()
	issuer := "https://sso.example.test/sso/realms/jjdguard"
	p, err := NewProvisioner(db, issuer)
	if err != nil {
		t.Fatal(err)
	}
	userID := "emergency_" + tenantID[len(tenantID)-12:]
	if _, err := db.Exec(ctx, `
		INSERT INTO users (
			id,tenant_id,username,password_hash,role,status,
			department_assignment_mode,department_assignment_source
		) VALUES ($1,$2,$1,'old-hash','platform_admin','active','emergency','admin')
	`, userID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO permission_grants (
			id,tenant_id,user_id,scope_type,scope_id,role,granted_by
		) VALUES ('grant-' || $1::varchar,$2,$1,'tenant',$2,'platform_admin',$3)
	`, userID, tenantID, actorID); err != nil {
		t.Fatal(err)
	}

	err = p.BindEmergencyIdentityAndTransition(ctx, EmergencyDemotionInput{
		TenantID: tenantID, UserID: userID, ExternalSubject: "new-local-subject",
		PasswordHash: "new-hash", Role: "viewer", DepartmentID: departmentID, ActorID: actorID,
	})
	if err != nil {
		t.Fatal(err)
	}

	var role, selectedDepartment, mode, source, passwordHash, linkedIssuer, linkedSubject string
	var mustChange bool
	if err := db.QueryRow(ctx, `
		SELECT u.role,u.department_id,u.department_assignment_mode,
		       u.department_assignment_source,u.password_hash,u.must_change_password,
		       l.issuer,l.external_subject
		FROM users u
		JOIN user_identity_links l ON l.tenant_id=u.tenant_id AND l.user_id=u.id
		WHERE u.tenant_id=$1 AND u.id=$2
	`, tenantID, userID).Scan(
		&role, &selectedDepartment, &mode, &source, &passwordHash, &mustChange,
		&linkedIssuer, &linkedSubject,
	); err != nil {
		t.Fatal(err)
	}
	if role != "viewer" || selectedDepartment != departmentID || mode != "manual" || source != "admin" ||
		passwordHash != "new-hash" || !mustChange || linkedIssuer != issuer || linkedSubject != "new-local-subject" {
		t.Fatalf("role=%q dept=%q mode=%q source=%q hash=%q must_change=%v issuer=%q subject=%q",
			role, selectedDepartment, mode, source, passwordHash, mustChange, linkedIssuer, linkedSubject)
	}
	var grantCount int
	var grantRole, grantedBy string
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*),MIN(role),MIN(granted_by)
		FROM permission_grants
		WHERE tenant_id=$1 AND user_id=$2 AND scope_type='tenant' AND scope_id=$1
	`, tenantID, userID).Scan(&grantCount, &grantRole, &grantedBy); err != nil {
		t.Fatal(err)
	}
	if grantCount != 1 || grantRole != "viewer" || grantedBy != actorID {
		t.Fatalf("grant count=%d role=%q actor=%q", grantCount, grantRole, grantedBy)
	}
	var auditCount, outboxCount int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_operations
		WHERE tenant_id=$1 AND target_id=$2 AND action_type='identity.department.changed'
		  AND action_detail->>'old_role'='platform_admin'
		  AND action_detail->>'new_role'='viewer'
		  AND action_detail::text NOT LIKE '%new-local-subject%'
	`, tenantID, userID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM identity_cache_invalidation_outbox WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 || outboxCount != 1 {
		t.Fatalf("audit=%d outbox=%d", auditCount, outboxCount)
	}
}

func TestPostgresProvisionerBindsEmergencyIdentityAsDeptManager(t *testing.T) {
	db, tenantID, actorID, departmentID := setupProvisionerDB(t)
	ctx := context.Background()
	p, err := NewProvisioner(db, "https://sso.example.test/sso/realms/jjdguard")
	if err != nil {
		t.Fatal(err)
	}
	userID := "emergency_dept_manager_" + tenantID[len(tenantID)-12:]
	if _, err := db.Exec(ctx, `
		INSERT INTO users (
			id,tenant_id,username,password_hash,role,status,
			department_assignment_mode,department_assignment_source
		) VALUES ($1,$2,$1,'old-hash','platform_admin','active','emergency','admin')
	`, userID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO permission_grants (
			id,tenant_id,user_id,scope_type,scope_id,role,granted_by
		) VALUES ('grant-' || $1::varchar,$2,$1,'tenant',$2,'platform_admin',$3)
	`, userID, tenantID, actorID); err != nil {
		t.Fatal(err)
	}

	if err := p.BindEmergencyIdentityAndTransition(ctx, EmergencyDemotionInput{
		TenantID: tenantID, UserID: userID, ExternalSubject: "dept-manager-subject",
		PasswordHash: "new-hash", Role: "dept_manager",
		DepartmentID: departmentID, ActorID: actorID,
	}); err != nil {
		t.Fatal(err)
	}
	var role, grantRole string
	if err := db.QueryRow(ctx, `SELECT role FROM users WHERE tenant_id=$1 AND id=$2`, tenantID, userID).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `
		SELECT role FROM permission_grants
		WHERE tenant_id=$1 AND user_id=$2 AND scope_type='tenant' AND scope_id=$1
	`, tenantID, userID).Scan(&grantRole); err != nil {
		t.Fatal(err)
	}
	if role != "dept_manager" || grantRole != role {
		t.Fatalf("role=%q grant=%q", role, grantRole)
	}
}

func TestPostgresProvisionerTransitionsStatusAtomicallyWithAuditAndOutbox(t *testing.T) {
	db, tenantID, actorID, departmentID := setupProvisionerDB(t)
	ctx := context.Background()
	p, err := NewProvisioner(db, "https://sso.example.test/sso/realms/jjdguard")
	if err != nil {
		t.Fatal(err)
	}
	userID := "status_" + tenantID[len(tenantID)-12:]
	if _, err := db.Exec(ctx, `
		INSERT INTO users (
			id,tenant_id,username,role,status,department_id,
			department_assignment_mode,department_assignment_source
		) VALUES ($1,$2,$1,'viewer','active',$3,'manual','local')
	`, userID, tenantID, departmentID); err != nil {
		t.Fatal(err)
	}

	if err := p.TransitionStatus(ctx, StatusTransitionInput{
		TenantID: tenantID, UserID: userID, Status: "disabled", ActorID: actorID,
	}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := db.QueryRow(ctx, `SELECT status FROM users WHERE tenant_id=$1 AND id=$2`, tenantID, userID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	var auditCount, outboxCount int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_operations
		WHERE tenant_id=$1 AND target_id=$2 AND action_type='user.status.update'
		  AND action_detail->>'old_status'='active'
		  AND action_detail->>'new_status'='disabled'
	`, tenantID, userID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM identity_cache_invalidation_outbox WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if status != "disabled" || auditCount != 1 || outboxCount != 1 {
		t.Fatalf("status=%q audit=%d outbox=%d", status, auditCount, outboxCount)
	}

	triggerName := "task4_reject_status_outbox"
	functionName := "task4_reject_status_outbox"
	if _, err := db.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $body$
		BEGIN
			RAISE EXCEPTION 'forced status outbox failure';
		END
		$body$;
		CREATE TRIGGER %s BEFORE INSERT ON identity_cache_invalidation_outbox
		FOR EACH ROW WHEN (NEW.user_id = '%s') EXECUTE FUNCTION %s()
	`, functionName, triggerName, userID, functionName)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), "DROP TRIGGER IF EXISTS "+triggerName+" ON identity_cache_invalidation_outbox")
		_, _ = db.Exec(context.Background(), "DROP FUNCTION IF EXISTS "+functionName+"()")
	})

	if err := p.TransitionStatus(ctx, StatusTransitionInput{
		TenantID: tenantID, UserID: userID, Status: "active", ActorID: actorID,
	}); err == nil {
		t.Fatal("expected forced status outbox failure")
	}
	if err := db.QueryRow(ctx, `SELECT status FROM users WHERE tenant_id=$1 AND id=$2`, tenantID, userID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_operations WHERE tenant_id=$1 AND target_id=$2 AND action_type='user.status.update'`, tenantID, userID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM identity_cache_invalidation_outbox WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if status != "disabled" || auditCount != 1 || outboxCount != 1 {
		t.Fatalf("rollback status=%q audit=%d outbox=%d", status, auditCount, outboxCount)
	}
}

func TestNativeServiceProvisionerRejectsHumanAndAdministrativeRoles(t *testing.T) {
	p := &PostgresProvisioner{nativeServiceOnly: true}
	for _, role := range []string{"platform_admin", "tenant_admin", "viewer", "developer"} {
		if err := p.Provision(context.Background(), ProvisionInput{Role: role, AssignmentMode: "service"}); err != ErrInvalidInput {
			t.Fatalf("role %s must be rejected before DB access: %v", role, err)
		}
	}
	if _, err := NewNativeServiceProvisioner(nil); err != ErrInvalidConfig {
		t.Fatal("nil database accepted")
	}
}

func TestPostgresStatusTransitionRechecksPausedStateAfterRowLock(t *testing.T) {
	db, tenant, actor, dept := setupProvisionerDB(t)
	ctx := context.Background()
	p, err := NewProvisioner(db, "https://sso.example.test/sso/realms/jjdguard")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"active", "disabled"} {
		t.Run(target, func(t *testing.T) {
			user := "paused_status_" + target + tenant[len(tenant)-12:]
			if _, err := db.Exec(ctx, "INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode,department_assignment_source) VALUES($1,$2,$1,'chat_user','active',$3,'manual','local')", user, tenant, dept); err != nil {
				t.Fatal(err)
			}
			tx, err := db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, "UPDATE users SET status='reconciliation_required',local_credential_version=local_credential_version+1 WHERE id=$1", user); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				result <- p.TransitionStatus(ctx, StatusTransitionInput{TenantID: tenant, UserID: user, Status: target, ActorID: actor})
			}()
			select {
			case <-result:
				t.Fatal("status transition crossed a held user row lock")
			case <-time.After(30 * time.Millisecond):
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, ErrReconciliationRequired) {
				t.Fatal("status transition did not reject the actual locked pause state")
			}
			var status string
			var epoch int64
			if err := db.QueryRow(ctx, "SELECT status,local_credential_version FROM users WHERE id=$1", user).Scan(&status, &epoch); err != nil || status != "reconciliation_required" || epoch != 2 {
				t.Fatal("ordinary status transition erased paused identity or changed its epoch")
			}
		})
	}
}
