package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
)

func TestAssignManyManuallyRollsBackWhenSecondUserIsInvalid(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	departmentA := "dept-batch-a-" + suffix
	departmentB := "dept-batch-b-" + suffix
	for _, departmentID := range []string{departmentA, departmentB} {
		if _, err := db.Exec(ctx, `
			INSERT INTO teams (id,tenant_id,name,path)
			VALUES ($1::varchar,$2::varchar,$1::varchar,'/' || $1::text)
		`, departmentID, tenantID); err != nil {
			t.Fatal(err)
		}
	}
	actorID := "batch-actor-" + suffix
	userID := "batch-user-" + suffix
	for _, fixture := range []struct {
		id   string
		role string
	}{
		{id: actorID, role: "tenant_admin"},
		{id: userID, role: "developer"},
	} {
		if _, err := db.Exec(ctx, `
			INSERT INTO users (
				id,tenant_id,username,role,status,department_id,
				department_assignment_mode,department_assignment_source
			) VALUES ($1,$2,$1,$3,'active',$4,'manual','admin')
		`, fixture.id, tenantID, fixture.role, departmentA); err != nil {
			t.Fatal(err)
		}
	}
	var auditBefore, outboxBefore int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_operations WHERE tenant_id=$1
	`, tenantID).Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM identity_cache_invalidation_outbox WHERE tenant_id=$1
	`, tenantID).Scan(&outboxBefore); err != nil {
		t.Fatal(err)
	}

	service := identitybinding.NewService(NewUserIdentityLinkRepository(db))
	err := service.AssignManyManually(
		ctx, tenantID, []string{userID, "missing-user-" + suffix},
		departmentB, "owner", actorID,
	)
	if !errors.Is(err, identitybinding.ErrNotFound) {
		t.Fatalf("batch error=%v, want not found", err)
	}
	var departmentID, assignmentMode, membershipRole string
	if err := db.QueryRow(ctx, `
		SELECT u.department_id,u.department_assignment_mode,tm.role
		FROM users u
		JOIN team_members tm ON tm.user_id=u.id AND tm.team_id=u.department_id
		WHERE u.tenant_id=$1 AND u.id=$2
	`, tenantID, userID).Scan(&departmentID, &assignmentMode, &membershipRole); err != nil {
		t.Fatal(err)
	}
	if departmentID != departmentA || assignmentMode != identitybinding.ModeManual || membershipRole != "member" {
		t.Fatalf("partial batch commit: department=%s mode=%s role=%s", departmentID, assignmentMode, membershipRole)
	}
	var auditAfter, outboxAfter int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_operations WHERE tenant_id=$1
	`, tenantID).Scan(&auditAfter); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM identity_cache_invalidation_outbox WHERE tenant_id=$1
	`, tenantID).Scan(&outboxAfter); err != nil {
		t.Fatal(err)
	}
	if auditAfter != auditBefore || outboxAfter != outboxBefore {
		t.Fatalf("partial batch evidence: audit %d->%d outbox %d->%d", auditBefore, auditAfter, outboxBefore, outboxAfter)
	}
}

func TestAssignManyManuallyRoleOnlyChangeWritesAuditAndOutbox(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	departmentID := "dept-role-only-" + suffix
	if _, err := db.Exec(ctx, `
		INSERT INTO teams (id,tenant_id,name,path)
		VALUES ($1::varchar,$2::varchar,$1::varchar,'/' || $1::text)
	`, departmentID, tenantID); err != nil {
		t.Fatal(err)
	}
	actorID := "role-actor-" + suffix
	userID := "role-user-" + suffix
	for _, fixture := range []struct {
		id   string
		role string
	}{
		{id: actorID, role: "tenant_admin"},
		{id: userID, role: "developer"},
	} {
		if _, err := db.Exec(ctx, `
			INSERT INTO users (
				id,tenant_id,username,role,status,department_id,
				department_assignment_mode,department_assignment_source
			) VALUES ($1,$2,$1,$3,'active',$4,'manual','admin')
		`, fixture.id, tenantID, fixture.role, departmentID); err != nil {
			t.Fatal(err)
		}
	}

	service := identitybinding.NewService(NewUserIdentityLinkRepository(db))
	if err := service.AssignManyManually(
		ctx, tenantID, []string{userID}, departmentID, "owner", actorID,
	); err != nil {
		t.Fatal(err)
	}

	var gotDepartmentID, assignmentMode, assignmentSource, membershipRole string
	if err := db.QueryRow(ctx, `
		SELECT u.department_id,u.department_assignment_mode,
		       u.department_assignment_source,tm.role
		FROM users u
		JOIN team_members tm ON tm.user_id=u.id AND tm.team_id=u.department_id
		WHERE u.tenant_id=$1 AND u.id=$2
	`, tenantID, userID).Scan(
		&gotDepartmentID, &assignmentMode, &assignmentSource, &membershipRole,
	); err != nil {
		t.Fatal(err)
	}
	if gotDepartmentID != departmentID || assignmentMode != identitybinding.ModeManual ||
		assignmentSource != "admin" || membershipRole != "owner" {
		t.Fatalf("role-only state: department=%s mode=%s source=%s role=%s",
			gotDepartmentID, assignmentMode, assignmentSource, membershipRole)
	}

	var auditCount int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM audit_operations
		WHERE tenant_id=$1
		  AND action_type='identity.department.changed'
		  AND target_type='user'
		  AND target_id=$2
		  AND action_detail @> jsonb_build_object(
		    'user_id',$2::text,
		    'old_department_id',$3::text,
		    'new_department_id',$3::text,
		    'old_role','member',
		    'new_role','owner',
		    'source_id','admin',
		    'actor_id',$4::text
		  )
		  AND NOT action_detail ?| ARRAY[
		    'tenant_id','token','email','groups','source'
		  ]
	`, tenantID, userID, departmentID, actorID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("role-only audit count=%d, want 1", auditCount)
	}

	var outboxCount int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM identity_cache_invalidation_outbox
		WHERE tenant_id=$1
		  AND user_id=$2
		  AND old_department_id=$3
		  AND new_department_id=$3
		  AND status='pending'
	`, tenantID, userID, departmentID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 {
		t.Fatalf("role-only outbox count=%d, want 1", outboxCount)
	}
}

func TestAssignManyManuallyReverseOrderCompletesWithoutDeadlock(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	departmentA := "dept-reverse-a-" + suffix
	departmentB := "dept-reverse-b-" + suffix
	for _, departmentID := range []string{departmentA, departmentB} {
		if _, err := db.Exec(ctx, `
			INSERT INTO teams (id,tenant_id,name,path)
			VALUES ($1::varchar,$2::varchar,$1::varchar,'/' || $1::text)
		`, departmentID, tenantID); err != nil {
			t.Fatal(err)
		}
	}

	actorID := "reverse-actor-" + suffix
	userA := "reverse-user-a-" + suffix
	userB := "reverse-user-b-" + suffix
	for _, fixture := range []struct {
		id   string
		role string
	}{
		{id: actorID, role: "tenant_admin"},
		{id: userA, role: "developer"},
		{id: userB, role: "developer"},
	} {
		if _, err := db.Exec(ctx, `
			INSERT INTO users (
				id,tenant_id,username,role,status,department_id,
				department_assignment_mode,department_assignment_source
			) VALUES ($1,$2,$1,$3,'active',$4,'manual','admin')
		`, fixture.id, tenantID, fixture.role, departmentA); err != nil {
			t.Fatal(err)
		}
	}

	service := identitybinding.NewService(NewUserIdentityLinkRepository(db))
	operationCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, order := range [][]string{{userA, userB}, {userB, userA}} {
		order := append([]string(nil), order...)
		go func() {
			<-start
			results <- service.AssignManyManually(
				operationCtx, tenantID, order, departmentB, "member", actorID,
			)
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("reverse-order assignment %d failed: %v", i+1, err)
			}
		case <-operationCtx.Done():
			t.Fatalf("reverse-order assignments timed out: %v", operationCtx.Err())
		}
	}

	for _, userID := range []string{userA, userB} {
		var departmentID, assignmentMode, assignmentSource, membershipRole string
		if err := db.QueryRow(ctx, `
			SELECT u.department_id,u.department_assignment_mode,
			       u.department_assignment_source,tm.role
			FROM users u
			JOIN team_members tm ON tm.user_id=u.id AND tm.team_id=u.department_id
			WHERE u.tenant_id=$1 AND u.id=$2
		`, tenantID, userID).Scan(
			&departmentID, &assignmentMode, &assignmentSource, &membershipRole,
		); err != nil {
			t.Fatal(err)
		}
		if departmentID != departmentB || assignmentMode != identitybinding.ModeManual ||
			assignmentSource != "admin" || membershipRole != "member" {
			t.Fatalf(
				"user %s partial state: department=%s mode=%s source=%s role=%s",
				userID, departmentID, assignmentMode, assignmentSource, membershipRole,
			)
		}

		var auditCount, outboxCount int
		if err := db.QueryRow(ctx, `
			SELECT COUNT(*) FROM audit_operations
			WHERE tenant_id=$1
			  AND action_type='identity.department.changed'
			  AND target_type='user'
			  AND target_id=$2
			  AND action_detail @> jsonb_build_object(
			    'old_department_id',$3::text,
			    'new_department_id',$4::text,
			    'new_role','member',
			    'source_id','admin',
			    'actor_id',$5::text
			  )
		`, tenantID, userID, departmentA, departmentB, actorID).Scan(&auditCount); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(ctx, `
			SELECT COUNT(*) FROM identity_cache_invalidation_outbox
			WHERE tenant_id=$1
			  AND user_id=$2
			  AND old_department_id=$3
			  AND new_department_id=$4
		`, tenantID, userID, departmentA, departmentB).Scan(&outboxCount); err != nil {
			t.Fatal(err)
		}
		if auditCount != 1 || outboxCount != 1 {
			t.Fatalf(
				"user %s duplicated evidence: audit=%d outbox=%d, want 1/1",
				userID, auditCount, outboxCount,
			)
		}
	}
}

// C1 回归：viewer -> tenant_admin 这种非应急的纯角色变化必须走事务化路径，
// 同步 users.role、permission_grants、audit、outbox。
// 本测试在真实 PG（迁移 137 应用后）上验证。
func TestTransitionTenantRoleSyncsGrantsAuditOutbox(t *testing.T) {
	db, tenantID := setupEnterpriseIdentityRepositoryDB(t)
	ctx := context.Background()
	suffix := identityFixtureSuffix(tenantID)
	departmentID := "dept-c1-" + suffix
	actorID := "actor-c1-" + suffix
	userID := "user-c1-" + suffix
	oldGrantID := "grant-old-c1-" + suffix

	if _, err := db.Exec(ctx, `
		INSERT INTO teams (id,tenant_id,name,path)
		VALUES ($1::varchar,$2::varchar,$1::varchar,$3)
	`, departmentID, tenantID, "/"+departmentID); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		id, role string
	}{
		{id: actorID, role: "platform_admin"},
		{id: userID, role: "viewer"},
	} {
		if _, err := db.Exec(ctx, `
			INSERT INTO users (
				id,tenant_id,username,role,status,department_id,
				department_assignment_mode,department_assignment_source
			) VALUES ($1,$2,$1,$3,$4,$5,$6,$7)
		`, fixture.id, tenantID, fixture.role, "active", departmentID, "manual", "admin"); err != nil {
			t.Fatal(err)
		}
	}
	// 旧 grant：与 viewer 角色一致
	if _, err := db.Exec(ctx, `
		INSERT INTO permission_grants (id,tenant_id,user_id,scope_type,scope_id,role,granted_by)
		VALUES ($1,$2,$3,$4,$2,$5,$6)
	`, oldGrantID, tenantID, userID, "tenant", "viewer", actorID); err != nil {
		t.Fatal(err)
	}

	var auditBefore, outboxBefore int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_operations WHERE tenant_id=$1`, tenantID).Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM identity_cache_invalidation_outbox WHERE tenant_id=$1`, tenantID).Scan(&outboxBefore); err != nil {
		t.Fatal(err)
	}

	service := identitybinding.NewService(NewUserIdentityLinkRepository(db))
	// 期望存在 TransitionTenantRole 方法（C1 修复新增）
	type tenantRoleTransitioner interface {
		TransitionTenantRole(ctx context.Context, tenantID, userID, role, actorID string) error
	}
	transitioner, ok := interface{}(service).(tenantRoleTransitioner)
	if !ok {
		t.Fatalf("BindingService 未实现 TransitionTenantRole（C1 未实现）")
	}
	if err := transitioner.TransitionTenantRole(ctx, tenantID, userID, "tenant_admin", actorID); err != nil {
		t.Fatalf("TransitionTenantRole: %v", err)
	}

	// 1) users.role 必须更新
	var newRole string
	if err := db.QueryRow(ctx, `SELECT role FROM users WHERE id=$1`, userID).Scan(&newRole); err != nil {
		t.Fatal(err)
	}
	if newRole != "tenant_admin" {
		t.Fatalf("users.role = %q, want tenant_admin", newRole)
	}

	// 2) permission_grants 必须替换为 tenant_admin 角色（旧 grant 删除，新 grant 插入）
	var grantCount int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM permission_grants
		WHERE tenant_id=$1 AND user_id=$2 AND scope_type='tenant' AND scope_id=$1
	`, tenantID, userID).Scan(&grantCount); err != nil {
		t.Fatal(err)
	}
	if grantCount != 1 {
		t.Fatalf("permission_grants 计数 = %d, want 1（旧 grant 应被替换）", grantCount)
	}
	var newGrantRole string
	var oldGrantStillExists bool
	if err := db.QueryRow(ctx, `
		SELECT role, EXISTS(SELECT 1 FROM permission_grants WHERE id=$1)
		FROM permission_grants
		WHERE tenant_id=$2 AND user_id=$3 AND scope_type='tenant' AND scope_id=$2
	`, oldGrantID, tenantID, userID).Scan(&newGrantRole, &oldGrantStillExists); err != nil {
		t.Fatalf("查新 grant: %v", err)
	}
	if newGrantRole != "tenant_admin" {
		t.Fatalf("permission_grants.role = %q, want tenant_admin", newGrantRole)
	}
	if oldGrantStillExists {
		t.Fatalf("旧 grant %q 仍存在，应被删除", oldGrantID)
	}

	// 3) audit_operations 必须新增一条
	var auditAfter int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_operations WHERE tenant_id=$1`, tenantID).Scan(&auditAfter); err != nil {
		t.Fatal(err)
	}
	if auditAfter != auditBefore+1 {
		t.Fatalf("audit_operations 新增 = %d, want 1", auditAfter-auditBefore)
	}

	// 4) identity_cache_invalidation_outbox 必须新增 pending 行
	var outboxAfter int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM identity_cache_invalidation_outbox
		WHERE tenant_id=$1 AND status='pending'
	`, tenantID).Scan(&outboxAfter); err != nil {
		t.Fatal(err)
	}
	if outboxAfter != outboxBefore+1 {
		t.Fatalf("outbox 新增 pending = %d, want 1", outboxAfter-outboxBefore)
	}
}
