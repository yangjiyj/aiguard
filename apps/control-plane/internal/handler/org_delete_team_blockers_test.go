package handler

// 控制台巡检（11-10）：删除部门（DeleteTeam）以前没有任何占用检查——
//   - 有成员：库里 users.department_id 是 RESTRICT 外键，管理员在页面上看到的是数据库原始英文报错；
//   - 有下级部门：悄悄把下级提成一级部门；
//
// 现在先查占用，409 + 中文说明数量；库里的外键兜底也不再外露原始报错。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 只建 DeleteTeam 读写的表和相关外键（与真实迁移一致：users.department_id RESTRICT、parent 与 team_members 随删除）。
func newDeleteTeamFixture(t *testing.T) (*pgxpool.Pool, *Dependencies) {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin database: %v", err)
	}
	schema := fmt.Sprintf("delete_team_%d", time.Now().UnixNano())
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
		`CREATE TABLE teams (
			id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL, name VARCHAR(255) NOT NULL,
			parent_team_id VARCHAR(64) REFERENCES teams(id) ON DELETE SET NULL,
			path TEXT NOT NULL DEFAULT '', is_system BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
		`CREATE TABLE users (
			id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL, username VARCHAR(255) NOT NULL,
			status VARCHAR(32) NOT NULL DEFAULT 'active',
			department_id VARCHAR(64) REFERENCES teams(id) ON DELETE RESTRICT)`,
		`CREATE TABLE team_members (
			team_id VARCHAR(64) NOT NULL REFERENCES teams(id) ON DELETE CASCADE, user_id VARCHAR(64) NOT NULL,
			PRIMARY KEY (team_id, user_id))`,
		// 员工密钥：department_id 是没有 ON DELETE 的外键（968_employee_api_keys.sql），同样会拦住删除。
		`CREATE TABLE employee_api_keys (id VARCHAR(64) PRIMARY KEY, department_id VARCHAR(64) NOT NULL REFERENCES teams(id))`,
		`INSERT INTO teams(id, tenant_id, name, path) VALUES
			('t_empty', 'ten', '空部门', '/t_empty'),
			('t_members', 'ten', '有成员', '/t_members'),
			('t_parent', 'ten', '有下级', '/t_parent'),
			('t_keys', 'ten', '有员工密钥', '/t_keys')`,
		`INSERT INTO teams(id, tenant_id, name, parent_team_id, path) VALUES ('t_child', 'ten', '下级', 't_parent', '/t_parent/t_child')`,
		`INSERT INTO users(id, tenant_id, username, status, department_id) VALUES
			('u1', 'ten', 'alice', 'active', 't_members'),
			('u2', 'ten', 'bob', 'disabled', 't_members'),
			('gone', 'ten', '__deleted__gone', 'deleted', NULL)`,
		// 只出现在成员表里的人也是成员页里看得到的成员；已退役用户不算。
		`INSERT INTO team_members(team_id, user_id) VALUES ('t_members', 'u1'), ('t_members', 'u2'), ('t_empty', 'gone')`,
		`INSERT INTO employee_api_keys(id, department_id) VALUES ('ek1', 't_keys')`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create fixture schema: %v\n%s", err, stmt)
		}
	}
	return pool, &Dependencies{TeamRepo: repository.NewTeamRepository(pool)}
}

func deleteTeamAs(t *testing.T, deps *Dependencies, teamID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/teams/"+teamID, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "admin", TenantID: "ten", Role: "platform_admin", Status: "active"}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", teamID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	DeleteTeam(deps).ServeHTTP(rr, req)
	return rr
}

func teamRowCount(t *testing.T, pool *pgxpool.Pool, id string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM teams WHERE id=$1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func decodeTeamDeleteConflict(t *testing.T, rr *httptest.ResponseRecorder) (code, message string, details map[string]float64) {
	t.Helper()
	var body struct {
		Error struct {
			Code    string             `json:"code"`
			Message string             `json:"message"`
			Details map[string]float64 `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v", rr.Body.String(), err)
	}
	return body.Error.Code, body.Error.Message, body.Error.Details
}

func TestDeleteTeamWithMembersIsRejectedWithCountsInsteadOfRawDatabaseError(t *testing.T) {
	pool, deps := newDeleteTeamFixture(t)

	rr := deleteTeamAs(t, deps, "t_members")

	if rr.Code != http.StatusConflict {
		t.Fatalf("有成员的部门应返回 409，实际 %d %s", rr.Code, rr.Body.String())
	}
	code, message, details := decodeTeamDeleteConflict(t, rr)
	if code != "team_not_empty" || !strings.Contains(message, "2 名成员") || details["members"] != 2 {
		t.Fatalf("code=%q message=%q details=%v", code, message, details)
	}
	if strings.Contains(rr.Body.String(), "SQLSTATE") || strings.Contains(rr.Body.String(), "violates") {
		t.Fatalf("不能把数据库报错带给页面: %s", rr.Body.String())
	}
	if teamRowCount(t, pool, "t_members") != 1 {
		t.Fatal("被拒绝的部门不能被删")
	}
}

func TestDeleteTeamWithChildTeamsIsRejectedAndKeepsHierarchy(t *testing.T) {
	pool, deps := newDeleteTeamFixture(t)

	rr := deleteTeamAs(t, deps, "t_parent")

	if rr.Code != http.StatusConflict {
		t.Fatalf("有下级部门应返回 409，实际 %d %s", rr.Code, rr.Body.String())
	}
	code, message, details := decodeTeamDeleteConflict(t, rr)
	if code != "team_not_empty" || !strings.Contains(message, "1 个下级") || details["child_teams"] != 1 {
		t.Fatalf("code=%q message=%q details=%v", code, message, details)
	}
	var parent string
	if err := pool.QueryRow(context.Background(), `SELECT parent_team_id FROM teams WHERE id='t_child'`).Scan(&parent); err != nil || parent != "t_parent" {
		t.Fatalf("下级部门不能被悄悄提成一级: parent=%q err=%v", parent, err)
	}
}

// 已退役用户（status=deleted）不在任何列表里，不能让一个看起来是空的部门删不掉。
func TestDeleteTeamIgnoresRetiredUsersAndDeletesEmptyTeam(t *testing.T) {
	pool, deps := newDeleteTeamFixture(t)

	rr := deleteTeamAs(t, deps, "t_empty")

	if rr.Code != http.StatusNoContent {
		t.Fatalf("空部门应能删除，实际 %d %s", rr.Code, rr.Body.String())
	}
	if teamRowCount(t, pool, "t_empty") != 0 {
		t.Fatal("空部门没有被删除")
	}
}

// 员工密钥等其他表还引用着部门时，库的外键兜底也要翻译成“被占用”。
func TestDeleteTeamTranslatesForeignKeyFallbackToConflict(t *testing.T) {
	pool, deps := newDeleteTeamFixture(t)

	rr := deleteTeamAs(t, deps, "t_keys")

	if rr.Code != http.StatusConflict {
		t.Fatalf("外键兜底应返回 409，实际 %d %s", rr.Code, rr.Body.String())
	}
	code, message, _ := decodeTeamDeleteConflict(t, rr)
	if code != "team_in_use" || !containsChinese(message) {
		t.Fatalf("code=%q message=%q", code, message)
	}
	if strings.Contains(rr.Body.String(), "SQLSTATE") || strings.Contains(rr.Body.String(), "violates") {
		t.Fatalf("不能把数据库报错带给页面: %s", rr.Body.String())
	}
	if teamRowCount(t, pool, "t_keys") != 1 {
		t.Fatal("被拒绝的部门不能被删")
	}
}
