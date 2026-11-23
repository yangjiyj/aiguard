package repository

import (
	"context"
	"testing"
)

// 控制台巡检（11-10）：用户列表的“应用数”把已删除（status=deleted）的应用也算进去了，
// 用户详情里应用授权却是空的——同一个用户，列表说 1 个、点进去一个都没有。
// 部门概览里的应用数同理。
func TestUserListProjectsCountIgnoresDeletedProjects(t *testing.T) {
	pool := setupUserRepositoryTestDB(t)
	ctx := context.Background()
	cleanup := func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM project_users WHERE project_id IN ('proj_pc_live', 'proj_pc_gone', 'proj_pc_member_gone')`)
		_, _ = pool.Exec(c, `DELETE FROM projects WHERE id IN ('proj_pc_live', 'proj_pc_gone', 'proj_pc_member_gone', 'proj_pc_team_live', 'proj_pc_team_gone')`)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id IN ('user_pc_owner', 'user_pc_gone_only')`)
		_, _ = pool.Exec(c, `DELETE FROM teams WHERE id = 'team_pc'`)
		_, _ = pool.Exec(c, `DELETE FROM tenants WHERE id = 'tenant_pc'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	for _, stmt := range []string{
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ('tenant_pc', '计数单位', 'enterprise', 'active', FALSE)`,
		`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status) VALUES
			('user_pc_owner', 'tenant_pc', 'pc_owner', 'pc_owner@example.local', 'x', 'developer', 'active'),
			('user_pc_gone_only', 'tenant_pc', 'pc_gone_only', 'pc_gone_only@example.local', 'x', 'developer', 'active')`,
		`INSERT INTO projects (id, tenant_id, name, code, environment, owner_user_id, status) VALUES
			('proj_pc_live', 'tenant_pc', '在用应用', 'live', 'production', 'user_pc_owner', 'active'),
			('proj_pc_gone', 'tenant_pc', '已删应用', 'gone', 'production', 'user_pc_owner', 'deleted'),
			('proj_pc_member_gone', 'tenant_pc', '已删的成员应用', 'member-gone', 'production', NULL, 'deleted')`,
		`INSERT INTO project_users (project_id, user_id, role) VALUES
			('proj_pc_live', 'user_pc_owner', 'developer'),
			('proj_pc_member_gone', 'user_pc_owner', 'developer'),
			('proj_pc_gone', 'user_pc_gone_only', 'developer'),
			('proj_pc_member_gone', 'user_pc_gone_only', 'developer')`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed: %v\n%s", err, stmt)
		}
	}

	users, err := NewUserRepository(pool).ListAllWithStats(ctx)
	if err != nil {
		t.Fatalf("list users with stats: %v", err)
	}
	counts := map[string]int64{}
	for _, u := range users {
		counts[u.ID] = u.ProjectsCount
	}
	if counts["user_pc_owner"] != 1 {
		t.Fatalf("owner 只有 1 个在用应用（另有 2 个已删除），projects_count = %d", counts["user_pc_owner"])
	}
	if counts["user_pc_gone_only"] != 0 {
		t.Fatalf("只关联已删除应用的用户 projects_count 应为 0，实际 %d", counts["user_pc_gone_only"])
	}
}

func TestCountProjectsByTeamsIgnoresDeletedProjects(t *testing.T) {
	pool := setupUserRepositoryTestDB(t)
	ctx := context.Background()
	cleanup := func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM projects WHERE id IN ('proj_pc_team_live', 'proj_pc_team_gone')`)
		_, _ = pool.Exec(c, `DELETE FROM teams WHERE id = 'team_pc'`)
		_, _ = pool.Exec(c, `DELETE FROM tenants WHERE id = 'tenant_pc_team'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	for _, stmt := range []string{
		`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ('tenant_pc_team', '部门计数单位', 'enterprise', 'active', FALSE)`,
		`INSERT INTO teams (id, tenant_id, name, path) VALUES ('team_pc', 'tenant_pc_team', '计数部门', '/team_pc')`,
		`INSERT INTO projects (id, tenant_id, name, code, environment, team_id, status) VALUES
			('proj_pc_team_live', 'tenant_pc_team', '部门在用应用', 'tl', 'production', 'team_pc', 'active'),
			('proj_pc_team_gone', 'tenant_pc_team', '部门已删应用', 'tg', 'production', 'team_pc', 'deleted')`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed: %v\n%s", err, stmt)
		}
	}

	n, err := NewTeamMemberRepository(pool).CountProjectsByTeams(ctx, "tenant_pc_team", []string{"team_pc"})
	if err != nil {
		t.Fatalf("count projects by teams: %v", err)
	}
	if n != 1 {
		t.Fatalf("部门下只有 1 个在用应用，实际数到 %d", n)
	}
}
