package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupTeamMembersTestDB opens a test database connection, creates a tenant,
// a user, and a team for member tests. All are cleaned up after the test.
func setupTeamMembersTestDB(t *testing.T) (*pgxpool.Pool, string, string, string) {
	t.Helper()

	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}

	suffix := fmt.Sprint(time.Now().UnixNano())
	tenantID := "tenant_tm_" + suffix
	userID := "user_tm_" + suffix
	teamID := "team_tm_" + suffix

	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`,
		tenantID, tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $3, 'developer', 'active')`,
		userID, tenantID, userID,
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	// Insert a team so team_members FK is satisfied.
	if _, err := db.Exec(ctx,
		`INSERT INTO teams (id, tenant_id, name, path) VALUES ($1, $2, '测试组', $3)`,
		teamID, tenantID, "/"+teamID,
	); err != nil {
		t.Fatalf("insert team: %v", err)
	}

	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM team_members WHERE team_id = $1`, teamID)
		_, _ = db.Exec(ctx, `DELETE FROM teams WHERE id = $1`, teamID)
		_, _ = db.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})

	return db, tenantID, userID, teamID
}

func TestTeamMemberAddRemove(t *testing.T) {
	pool, tenantID, userID, teamID := setupTeamMembersTestDB(t)
	repo := NewTeamMemberRepository(pool)
	ctx := context.Background()

	if err := repo.Add(ctx, teamID, userID, "owner"); err != nil {
		t.Fatalf("add: %v", err)
	}

	members, err := repo.ListByTeam(ctx, teamID)
	if err != nil {
		t.Fatalf("list by team err: %v", err)
	}
	if len(members) != 1 || members[0].Role != "owner" {
		t.Fatalf("members: %+v", members)
	}

	var userDepartment, assignmentMode string
	if err := pool.QueryRow(ctx, `
		SELECT department_id, department_assignment_mode
		FROM users WHERE tenant_id=$1 AND id=$2
	`, tenantID, userID).Scan(&userDepartment, &assignmentMode); err != nil {
		t.Fatal(err)
	}
	if userDepartment != teamID || assignmentMode != "manual" {
		t.Fatalf("user authority=%s/%s", userDepartment, assignmentMode)
	}
	teams, err := repo.ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list by user err: %v", err)
	}
	if len(teams) != 1 {
		t.Fatalf("user teams: %+v", teams)
	}

	if err := repo.Remove(ctx, teamID, userID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	members, err = repo.ListByTeam(ctx, teamID)
	if err != nil {
		t.Fatalf("list after remove err: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("after remove: %+v", members)
	}
	teams, err = repo.ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list user projection after remove: %v", err)
	}
	if len(teams) != 1 || teams[0].TeamID == teamID || teams[0].Role != "member" {
		t.Fatalf("unassigned projection after remove: %+v", teams)
	}
	var systemKey string
	if err := pool.QueryRow(ctx, `
		SELECT COALESCE(system_key,'') FROM teams
		WHERE tenant_id=$1 AND id=$2
	`, tenantID, teams[0].TeamID).Scan(&systemKey); err != nil {
		t.Fatal(err)
	}
	if systemKey != "unassigned" {
		t.Fatalf("removed user projected to %q, want unassigned", systemKey)
	}
}

func TestTeamMemberUpsertRole(t *testing.T) {
	pool, _, userID, teamID := setupTeamMembersTestDB(t)
	repo := NewTeamMemberRepository(pool)
	ctx := context.Background()

	_ = repo.Add(ctx, teamID, userID, "member")
	// Upsert should change the role.
	if err := repo.Add(ctx, teamID, userID, "owner"); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	members, _ := repo.ListByTeam(ctx, teamID)
	if len(members) != 1 || members[0].Role != "owner" {
		t.Errorf("upsert role: %+v", members)
	}
}

func TestTeamMemberUpdateRole(t *testing.T) {
	pool, _, userID, teamID := setupTeamMembersTestDB(t)
	repo := NewTeamMemberRepository(pool)
	ctx := context.Background()

	_ = repo.Add(ctx, teamID, userID, "member")

	if err := repo.UpdateRole(ctx, teamID, userID, "admin"); err != nil {
		t.Fatalf("update role: %v", err)
	}
	members, _ := repo.ListByTeam(ctx, teamID)
	if len(members) != 1 || members[0].Role != "admin" {
		t.Errorf("role after update: %+v", members)
	}
}

func TestTeamMemberMultipleUsers(t *testing.T) {
	pool, tenantID, userID, teamID := setupTeamMembersTestDB(t)
	repo := NewTeamMemberRepository(pool)
	ctx := context.Background()

	// Create a second user in the same tenant.
	user2ID := "user_tm2_" + fmt.Sprint(time.Now().UnixNano())
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $3, 'developer', 'active')`,
		user2ID, tenantID, user2ID,
	); err != nil {
		t.Fatalf("insert user2: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, user2ID)
	})

	_ = repo.Add(ctx, teamID, userID, "owner")
	_ = repo.Add(ctx, teamID, user2ID, "member")

	members, _ := repo.ListByTeam(ctx, teamID)
	if len(members) != 2 {
		t.Errorf("want 2 members, got %d: %+v", len(members), members)
	}

	// user2 should appear in their own membership list.
	teams, _ := repo.ListByUser(ctx, user2ID)
	if len(teams) != 1 {
		t.Errorf("want 1 team for user2, got %d", len(teams))
	}
}

func TestTeamMemberListProjectIDsByUserTeamsIncludesDescendants(t *testing.T) {
	pool, tenantID, userID, teamID := setupTeamMembersTestDB(t)
	repo := NewTeamMemberRepository(pool)
	ctx := context.Background()

	suffix := fmt.Sprint(time.Now().UnixNano())
	childID := teamID + "_child_" + suffix
	otherID := teamID + "_other_" + suffix
	projectRoot := "proj_root_" + suffix
	projectChild := "proj_child_" + suffix
	projectOther := "proj_other_" + suffix

	_, err := pool.Exec(ctx, `
		INSERT INTO teams (id, tenant_id, name, parent_team_id, path) VALUES
			($1, $2, '子部门', $3, $4),
			($5, $2, '其它部门', NULL, $6)
	`, childID, tenantID, teamID, "/"+teamID+"/"+childID, otherID, "/"+otherID)
	if err != nil {
		t.Fatalf("insert child teams: %v", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO projects (id, tenant_id, name, owner_user_id, status, team_id) VALUES
			($1, $2, '根部门应用', $3, 'active', $4),
			($5, $2, '子部门应用', $3, 'active', $6),
			($7, $2, '其它部门应用', $3, 'active', $8)
	`, projectRoot, tenantID, userID, teamID, projectChild, childID, projectOther, otherID)
	if err != nil {
		t.Fatalf("insert projects: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE id = ANY($1)`, []string{projectRoot, projectChild, projectOther})
		_, _ = pool.Exec(ctx, `DELETE FROM teams WHERE id = ANY($1)`, []string{childID, otherID})
	})

	if err := repo.Add(ctx, teamID, userID, "member"); err != nil {
		t.Fatalf("add member: %v", err)
	}

	projectIDs, err := repo.ListProjectIDsByUserTeams(ctx, tenantID, userID)
	if err != nil {
		t.Fatalf("list project ids: %v", err)
	}
	got := map[string]bool{}
	for _, id := range projectIDs {
		got[id] = true
	}
	if !got[projectRoot] || !got[projectChild] || got[projectOther] {
		t.Fatalf("unexpected project scope: got=%v root=%s child=%s other=%s", projectIDs, projectRoot, projectChild, projectOther)
	}
}

// TestTeamMembersProjectionRejectsStaleRow 锁定任务11场景5 的底层保证：
// 迁移 137 的触发器强制 team_members 行必须匹配 users.department_id（单一事实源）。
// 任何尝试塞入"用户不在该部门但 team_members 有残留行"的脏数据都被 DB 约束拒绝，
// 从根上杜绝了"旧 team_members 残留扩大权限"。授权读取（ListTeamIDsByUser）即便
// 不做应用层过滤，也无法读到这种残留——因为它们根本无法存在。
//
// 构造：user.department_id = 主部门，尝试往另一个 dept_X 塞 team_members 残留行。
// 期望：DB 抛 P0001（触发器拒绝）。
func TestTeamMembersProjectionRejectsStaleRow(t *testing.T) {
	pool, tenantID, userID, teamID := setupTeamMembersTestDB(t)
	_ = NewTeamMemberRepository(pool) // 仅为复用 setup；本测试断 DB 约束
	ctx := context.Background()

	// 先把用户事实部门设为主部门（setup 默认未设 department_id）
	if _, err := pool.Exec(ctx,
		`UPDATE users SET department_id=$1, department_assignment_mode='manual' WHERE tenant_id=$2 AND id=$3`,
		teamID, tenantID, userID,
	); err != nil {
		t.Fatalf("set user department_id: %v", err)
	}

	// 诱饵部门 dept_X
	suffix := fmt.Sprint(time.Now().UnixNano())
	deptX := "team_decoy_X_" + suffix
	if _, err := pool.Exec(ctx,
		`INSERT INTO teams (id, tenant_id, name, path) VALUES ($1, $2, '诱饵部门', $3)`,
		deptX, tenantID, "/"+deptX,
	); err != nil {
		t.Fatalf("insert decoy team: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM teams WHERE id = $1`, deptX)
	})

	// 尝试塞残留：user 的 department_id 是 teamID，但往 dept_X 塞 team_members 行。
	// 触发器必须拒绝（P0001），保证 team_members 永远是 department_id 的精确投影。
	_, err := pool.Exec(ctx,
		`INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, 'member')`,
		deptX, userID,
	)
	if err == nil {
		t.Fatal("期望触发器拒绝不匹配 department_id 的 team_members 残留行，实际插入成功——单一事实源被破坏")
	}
	// 断言是触发器抛的拒绝（SQLSTATE P0001 raised exception），不是其它无关错误
	if !strings.Contains(err.Error(), "department_id projection") && !strings.Contains(err.Error(), "P0001") {
		t.Fatalf("期望触发器拒绝信息，实际错误: %v", err)
	}
}

// TestListTeamIDsByUserExcludesEmergency 锁定任务11场景6 的 repo 层：
// 应急用户（department_assignment_mode='emergency'）即便有 department_id，
// 授权读取也必须返空——闸门层据此把模型列表收窄为空集。
func TestListTeamIDsByUserExcludesEmergency(t *testing.T) {
	pool, tenantID, userID, teamID := setupTeamMembersTestDB(t)
	repo := NewTeamMemberRepository(pool)
	ctx := context.Background()

	// 把用户设为应急态（带 department_id）
	if _, err := pool.Exec(ctx,
		`UPDATE users SET department_id=$1, department_assignment_mode='emergency' WHERE tenant_id=$2 AND id=$3`,
		teamID, tenantID, userID,
	); err != nil {
		t.Fatalf("set emergency: %v", err)
	}

	ids, err := repo.ListTeamIDsByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list team ids: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("应急用户授权读取必须为空，实际 ids=%v", ids)
	}
}
