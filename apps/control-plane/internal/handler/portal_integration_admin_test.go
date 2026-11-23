package handler

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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/org"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// ---------- 缺 tenant 头 → 400（纯逻辑，无需 DB）----------

func TestListPortalProjectsRequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/projects", nil)
	w := httptest.NewRecorder()
	ListPortalProjects(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "tenant") {
		t.Fatalf("want 400 tenant_required, got %d %s", w.Code, w.Body.String())
	}
}

func TestListPortalTeamsRequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/teams", nil)
	w := httptest.NewRecorder()
	ListPortalTeams(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "tenant") {
		t.Fatalf("want 400 tenant_required, got %d %s", w.Code, w.Body.String())
	}
}

func TestCreatePortalProjectRequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/projects", strings.NewReader(`{"name":"x"}`))
	w := httptest.NewRecorder()
	CreatePortalProject(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "tenant") {
		t.Fatalf("want 400 tenant_required, got %d %s", w.Code, w.Body.String())
	}
}

func TestSetPortalModelPolicyRequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/portal-integration/policies/model", strings.NewReader(`{"project_id":"p1"}`))
	w := httptest.NewRecorder()
	SetPortalModelPolicy(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "tenant") {
		t.Fatalf("want 400 tenant_required, got %d %s", w.Code, w.Body.String())
	}
}

func TestCreatePortalTeamRequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/teams", strings.NewReader(`{"name":"x"}`))
	w := httptest.NewRecorder()
	CreatePortalTeam(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "tenant") {
		t.Fatalf("want 400 tenant_required, got %d %s", w.Code, w.Body.String())
	}
}

// name 必填校验（缺 name → 400，租户头已带）
func TestCreatePortalProjectRequiresName(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/projects", strings.NewReader(`{"name":"  "}`))
	req.Header.Set(portalIntegrationTenantHeader, "tenant_default")
	w := httptest.NewRecorder()
	CreatePortalProject(&Dependencies{ProjectRepo: &repository.ProjectRepository{}})(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "name") {
		t.Fatalf("want 400 name required, got %d %s", w.Code, w.Body.String())
	}
}

// ---------- DB 集成流（无测试库则跳过）----------

// setupPortalAdminPool 建两个租户（A/B）+ A 的一个用户，返回连接池与两租户 ID，
// 并注册全量清理（policies/projects/teams/users/tenants）。
func setupPortalAdminPool(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantA := "tpa_a_" + sfx
	tenantB := "tpa_b_" + sfx
	userA := "upa_a_" + sfx
	for _, tid := range []string{tenantA, tenantB} {
		if _, err = pool.Exec(ctx,
			`INSERT INTO tenants (id, name, edition, status) VALUES ($1, $2, $3, $4)`,
			tid, tid, "enterprise", "active"); err != nil {
			t.Fatalf("insert tenant %s: %v", tid, err)
		}
	}
	if _, err = pool.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		userA, tenantA, userA, userA+"@test.com", "x", "platform_admin", "active"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		for _, tid := range []string{tenantA, tenantB} {
			_, _ = pool.Exec(cctx, `DELETE FROM model_policies WHERE tenant_id = $1`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM internal_keys WHERE tenant_id = $1`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM project_users WHERE project_id IN (SELECT id FROM projects WHERE tenant_id = $1)`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM projects WHERE tenant_id = $1`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM team_members WHERE team_id IN (SELECT id FROM teams WHERE tenant_id = $1)`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM teams WHERE tenant_id = $1`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM users WHERE tenant_id = $1`, tid)
			_, _ = pool.Exec(cctx, `DELETE FROM tenants WHERE id = $1`, tid)
		}
		pool.Close()
	})
	return pool, tenantA, tenantB
}

func buildPortalAdminDeps(pool *pgxpool.Pool) *Dependencies {
	teamRepo := repository.NewTeamRepository(pool)
	teamMemberRepo := repository.NewTeamMemberRepository(pool)
	quotaRepo := repository.NewQuotaPolicyRepository(pool)
	return &Dependencies{
		ProjectRepo:     repository.NewProjectRepository(pool),
		TeamRepo:        teamRepo,
		TeamMemberRepo:  teamMemberRepo,
		ModelPolicyRepo: repository.NewModelPolicyRepository(pool),
		OrgService:      org.NewService(teamRepo, teamMemberRepo, quotaRepo),
		SystemRepo:      &orgTestSystemRepo{}, // 复用 org_handler_test.go 的 stub
	}
}

func portalAdminReq(method, path, tenantID, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if tenantID != "" {
		r.Header.Set(portalIntegrationTenantHeader, tenantID)
	}
	return r
}

// TestPortalAdminEndpointsDBFlow 端到端：建 team/project、挂 team、设策略、列表、跨租户 404 掩蔽。
func TestPortalAdminEndpointsDBFlow(t *testing.T) {
	pool, tenantA, tenantB := setupPortalAdminPool(t)
	deps := buildPortalAdminDeps(pool)

	// 1) 建 team（A）→ 201
	w := httptest.NewRecorder()
	CreatePortalTeam(deps)(w, portalAdminReq(http.MethodPost, "/x", tenantA, `{"name":"研发部"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("CreatePortalTeam A: status=%d body=%s", w.Code, w.Body.String())
	}
	var teamResp struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &teamResp)
	if teamResp.ID == "" {
		t.Fatalf("team id empty: %s", w.Body.String())
	}
	teamAID := teamResp.ID

	// 2) 建 project（A）挂 teamA → 201
	w = httptest.NewRecorder()
	CreatePortalProject(deps)(w, portalAdminReq(http.MethodPost, "/x", tenantA,
		fmt.Sprintf(`{"name":"研发项目","code":"rd","team_id":"%s"}`, teamAID)))
	if w.Code != http.StatusCreated {
		t.Fatalf("CreatePortalProject A: status=%d body=%s", w.Code, w.Body.String())
	}
	var projResp struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &projResp)
	if projResp.ID == "" || projResp.TenantID != tenantA {
		t.Fatalf("bad project resp: %s", w.Body.String())
	}
	projAID := projResp.ID

	// 断言 team_id 真落库（owner_user_id 为 NULL 也应成功创建）
	byTeam, err := repository.NewProjectRepository(pool).ListByTeam(context.Background(), tenantA, teamAID)
	if err != nil {
		t.Fatalf("ListByTeam: %v", err)
	}
	found := false
	for _, p := range byTeam {
		if p.ID == projAID {
			found = true
		}
	}
	if !found {
		t.Fatalf("project %s not attached to team %s", projAID, teamAID)
	}

	// 3) GET projects（A）含新建 project；GET projects（B）不含（租户隔离）
	w = httptest.NewRecorder()
	ListPortalProjects(deps)(w, portalAdminReq(http.MethodGet, "/x", tenantA, ""))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), projAID) {
		t.Fatalf("ListPortalProjects A missing project: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	ListPortalProjects(deps)(w, portalAdminReq(http.MethodGet, "/x", tenantB, ""))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), projAID) {
		t.Fatalf("ListPortalProjects B leaked project: %d %s", w.Code, w.Body.String())
	}

	// 4) GET teams（A）含 teamA；（B）不含
	w = httptest.NewRecorder()
	ListPortalTeams(deps)(w, portalAdminReq(http.MethodGet, "/x", tenantA, ""))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), teamAID) {
		t.Fatalf("ListPortalTeams A missing team: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	ListPortalTeams(deps)(w, portalAdminReq(http.MethodGet, "/x", tenantB, ""))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), teamAID) {
		t.Fatalf("ListPortalTeams B leaked team: %d %s", w.Code, w.Body.String())
	}

	// 5) PUT policies/model（A）→ 200，allow_list 回显
	w = httptest.NewRecorder()
	SetPortalModelPolicy(deps)(w, portalAdminReq(http.MethodPut, "/x", tenantA,
		fmt.Sprintf(`{"project_id":"%s","allow_list":["glm-5.2"],"deny_list":[]}`, projAID)))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "glm-5.2") {
		t.Fatalf("SetPortalModelPolicy A: status=%d body=%s", w.Code, w.Body.String())
	}

	// 6) 跨租户 404：用 B 的租户头对 A 的 project 设策略 → 404 掩蔽
	w = httptest.NewRecorder()
	SetPortalModelPolicy(deps)(w, portalAdminReq(http.MethodPut, "/x", tenantB,
		fmt.Sprintf(`{"project_id":"%s","allow_list":["glm-5.2"]}`, projAID)))
	if w.Code != http.StatusNotFound {
		t.Fatalf("SetPortalModelPolicy cross-tenant: want 404, got %d %s", w.Code, w.Body.String())
	}

	// 7) 跨租户 404：B 建 project 却引用 A 的 team → 404 掩蔽
	w = httptest.NewRecorder()
	CreatePortalProject(deps)(w, portalAdminReq(http.MethodPost, "/x", tenantB,
		fmt.Sprintf(`{"name":"越权项目","team_id":"%s"}`, teamAID)))
	if w.Code != http.StatusNotFound {
		t.Fatalf("CreatePortalProject cross-tenant team: want 404, got %d %s", w.Code, w.Body.String())
	}
}
