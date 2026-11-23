package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/jackc/pgx/v5/pgxpool"
)

func seedSystemPlatformActor(t *testing.T, db *pgxpool.Pool, suffix string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := db.Exec(ctx, `
		INSERT INTO tenants (id,name,edition,status,is_test)
		VALUES ($1,$1,'enterprise','active',TRUE)
		ON CONFLICT (id) DO NOTHING
	`, SystemTenantID); err != nil {
		t.Fatal(err)
	}
	actorID := "system-platform-" + suffix
	if _, err := db.Exec(ctx, `
		INSERT INTO users (
			id,tenant_id,username,role,status,
			department_assignment_mode,department_assignment_source
		) VALUES ($1,$2,$1,'platform_admin','active','emergency','local')
	`, actorID, SystemTenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM users WHERE tenant_id=$1 AND id=$2`, SystemTenantID, actorID)
	})
	return actorID
}

func assertCrossTenantActorAudit(t *testing.T, db *pgxpool.Pool, tenantID, userID, actorID string, fieldCount int) {
	t.Helper()
	var auditUserID, detail string
	if err := db.QueryRow(context.Background(), `
		SELECT COALESCE(user_id,''),action_detail::text
		FROM audit_operations
		WHERE tenant_id=$1 AND target_id=$2 AND action_type='identity.department.changed'
		ORDER BY created_at DESC LIMIT 1
	`, tenantID, userID).Scan(&auditUserID, &detail); err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal([]byte(detail), &fields); err != nil {
		t.Fatal(err)
	}
	if auditUserID != "" || fields["actor_id"] != actorID || len(fields) != fieldCount {
		t.Fatalf("audit user_id=%q fields=%v", auditUserID, fields)
	}
	for _, forbidden := range []string{"tenant_id", "actor_tenant_id", "actor_role"} {
		if _, exists := fields[forbidden]; exists || strings.Contains(detail, forbidden) {
			t.Fatalf("audit exposed %q: %s", forbidden, detail)
		}
	}
}

func seedRoleTransitionUser(
	t *testing.T,
	db *pgxpool.Pool,
	tenantID, userID, departmentID, role, mode string,
) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.Exec(ctx, `
		INSERT INTO teams (id,tenant_id,name,path) VALUES ($1,$2,$1,$3)
	`, departmentID, tenantID, "/"+departmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO users (
			id,tenant_id,username,role,status,department_id,
			department_assignment_mode,department_assignment_source
		) VALUES ($1,$2,$1,$4,'active',$3,$5,'admin')
	`, userID, tenantID, departmentID, role, mode); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO permission_grants (
			id,tenant_id,user_id,scope_type,scope_id,role,granted_by
		) VALUES ($4,$2,$1,'tenant',$2,$3,'seed-admin')
	`, userID, tenantID, role, "grant-"+userID); err != nil {
		t.Fatal(err)
	}
}

func tenantGrantRoles(t *testing.T, db *pgxpool.Pool, tenantID, userID string) []string {
	t.Helper()
	rows, err := db.Query(context.Background(), `
		SELECT role FROM permission_grants
		WHERE tenant_id=$1 AND user_id=$2 AND scope_type='tenant' AND scope_id=$1
		ORDER BY role
	`, tenantID, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			t.Fatal(err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return roles
}

func TestTransitionPlatformRoleReplacesTenantGrant(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	userID := "role-user-" + suffix
	departmentID := "role-dept-" + suffix
	seedRoleTransitionUser(t, db, tenantID, userID, departmentID, "viewer", identitybinding.ModeManual)

	service := identitybinding.NewService(NewUserIdentityLinkRepository(db))
	if err := service.TransitionPlatformRole(
		ctx, tenantID, userID, "platform_admin", "", identitybinding.ActorPortalUserSync,
	); err != nil {
		t.Fatal(err)
	}
	var role string
	if err := db.QueryRow(ctx, `SELECT role FROM users WHERE tenant_id=$1 AND id=$2`, tenantID, userID).Scan(&role); err != nil {
		t.Fatal(err)
	}
	roles := tenantGrantRoles(t, db, tenantID, userID)
	if role != "platform_admin" || len(roles) != 1 || roles[0] != role {
		t.Fatalf("user role=%q tenant grants=%v", role, roles)
	}
}

func TestSystemPlatformAdminTransitionsCrossTenantRoleWithRealActorAudit(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	actorID := seedSystemPlatformActor(t, db, suffix)
	userID := "cross-role-user-" + suffix
	departmentID := "cross-role-dept-" + suffix
	seedRoleTransitionUser(t, db, tenantID, userID, departmentID, "viewer", identitybinding.ModeManual)

	service := identitybinding.NewService(NewUserIdentityLinkRepository(db))
	if err := service.TransitionPlatformRole(ctx, tenantID, userID, "platform_admin", "", actorID); err != nil {
		t.Fatal(err)
	}
	assertCrossTenantActorAudit(t, db, tenantID, userID, actorID, 8)
}

func TestSystemPlatformAdminAssignsCrossTenantDepartmentWithRealActorAudit(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	actorID := seedSystemPlatformActor(t, db, suffix)
	userID := "cross-assign-user-" + suffix
	oldDepartmentID := "cross-assign-old-" + suffix
	newDepartmentID := "cross-assign-new-" + suffix
	seedRoleTransitionUser(t, db, tenantID, userID, oldDepartmentID, "viewer", identitybinding.ModeManual)
	if _, err := db.Exec(ctx, `INSERT INTO teams (id,tenant_id,name,path) VALUES ($1,$2,$1,$3)`,
		newDepartmentID, tenantID, "/"+newDepartmentID); err != nil {
		t.Fatal(err)
	}

	service := identitybinding.NewService(NewUserIdentityLinkRepository(db))
	if err := service.AssignManually(ctx, tenantID, userID, newDepartmentID, actorID); err != nil {
		t.Fatal(err)
	}
	assertCrossTenantActorAudit(t, db, tenantID, userID, actorID, 6)
}

func TestNonSystemCrossTenantActorIsRejected(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	userID := "rejected-cross-user-" + suffix
	departmentID := "rejected-cross-dept-" + suffix
	seedRoleTransitionUser(t, db, tenantID, userID, departmentID, "viewer", identitybinding.ModeManual)

	service := identitybinding.NewService(NewUserIdentityLinkRepository(db))
	err := service.TransitionPlatformRole(ctx, tenantID, userID, "platform_admin", "", "user_admin")
	if !errors.Is(err, identitybinding.ErrNotFound) {
		t.Fatalf("cross-tenant actor error=%v want ErrNotFound", err)
	}
	var auditCount int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_operations WHERE tenant_id=$1 AND target_id=$2`,
		tenantID, userID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 0 {
		t.Fatalf("rejected cross-tenant actor wrote %d audits", auditCount)
	}
}

func TestTransitionPlatformRoleRollsBackWhenTenantGrantReplacementFails(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	userID := "rollback-user-" + suffix
	departmentID := "rollback-dept-" + suffix
	seedRoleTransitionUser(t, db, tenantID, userID, departmentID, "viewer", identitybinding.ModeManual)

	deleteTriggerName := "task4_reject_permission_grant_delete"
	insertTriggerName := "task4_reject_permission_grant_insert"
	functionName := "task4_reject_permission_grant_change"
	if _, err := db.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $body$
		BEGIN
			RAISE EXCEPTION 'forced permission grant failure';
		END
		$body$;
		CREATE TRIGGER %s BEFORE DELETE ON permission_grants
		FOR EACH ROW
		WHEN (OLD.user_id = '%s')
		EXECUTE FUNCTION %s();
		CREATE TRIGGER %s BEFORE INSERT ON permission_grants
		FOR EACH ROW
		WHEN (NEW.user_id = '%s')
		EXECUTE FUNCTION %s()
	`, functionName, deleteTriggerName, userID, functionName,
		insertTriggerName, userID, functionName)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), "DROP TRIGGER IF EXISTS "+deleteTriggerName+" ON permission_grants")
		_, _ = db.Exec(context.Background(), "DROP TRIGGER IF EXISTS "+insertTriggerName+" ON permission_grants")
		_, _ = db.Exec(context.Background(), "DROP FUNCTION IF EXISTS "+functionName+"()")
	})

	service := identitybinding.NewService(NewUserIdentityLinkRepository(db))
	if err := service.TransitionPlatformRole(
		ctx, tenantID, userID, "platform_admin", "", identitybinding.ActorPortalUserSync,
	); err == nil {
		t.Fatal("expected permission grant replacement failure")
	}

	var role, gotDepartment, mode string
	if err := db.QueryRow(ctx, `
		SELECT role,department_id,department_assignment_mode
		FROM users WHERE tenant_id=$1 AND id=$2
	`, tenantID, userID).Scan(&role, &gotDepartment, &mode); err != nil {
		t.Fatal(err)
	}
	roles := tenantGrantRoles(t, db, tenantID, userID)
	var auditCount, outboxCount int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_operations WHERE tenant_id=$1 AND target_id=$2`, tenantID, userID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM identity_cache_invalidation_outbox WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if role != "viewer" || gotDepartment != departmentID || mode != identitybinding.ModeManual ||
		len(roles) != 1 || roles[0] != "viewer" || auditCount != 0 || outboxCount != 0 {
		t.Fatalf("role=%q department=%q mode=%q grants=%v audit=%d outbox=%d",
			role, gotDepartment, mode, roles, auditCount, outboxCount)
	}
}
