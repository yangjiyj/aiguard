package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func portalProjectFixture(t *testing.T) (*Dependencies, *pgxpool.Pool, string, string, string) {
	t.Helper()
	pool, tenant, _ := setupUserSyncPool(t)
	deps := buildUserSyncDeps(pool)
	deps.IdentityRuntimeConfig.IssuerURL = "https://portal-project.test"
	deps.UserIdentityLinkLookup = repository.NewUserIdentityLinkRepository(pool)
	deps.UserModelRepo = repository.NewUserModelRepository(pool)
	deps.KeyRepo = repository.NewInternalKeyRepository(pool)
	dept := ensureDepartment(t, pool, tenant, "engineers")
	seedDepartmentMapping(t, pool, tenant, "oidc", "", "groups", "engineers", dept, 10)
	project := tenant + "-engineers-app"
	mustExec(t, pool, `INSERT INTO projects(id,tenant_id,name,team_id,status,code,environment) VALUES($1,$2,'Engineering Chat',$3,'active','fixture','test')`, project, tenant, dept)
	w := httptest.NewRecorder()
	EnsurePortalUser(deps)(w, userSyncReq(http.MethodPost, "/x", tenant, `{"issuer":"https://portal-project.test","source_type":"oidc","external_subject":"engineer-subject","username":"engineer","email":"engineer@test.invalid","groups":["engineers"]}`))
	if w.Code != 200 {
		t.Fatalf("initial SSO resolution: %d %s", w.Code, w.Body.String())
	}
	var result EnsurePortalUserResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Resolution != identitybinding.ModeAutomatic || result.DepartmentID != dept {
		t.Fatalf("initial mapping: %+v", result)
	}
	if err := deps.ProjectUserRepo.BindUserWithRole(context.Background(), project, result.UserID, "developer"); err != nil {
		t.Fatalf("prepare initial project membership: %v", err)
	}
	return deps, pool, tenant, result.UserID, project
}

func boundPortalContext(deps *Dependencies, tenant, userID, subject string) *httptest.ResponseRecorder {
	req := portalAuthorizationRequest(tenant, userID)
	q := req.URL.Query()
	q.Set("external_subject", subject)
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	GetPortalUserAuthorizationContext(deps)(w, req)
	return w
}

func TestPortalAuthorizationProjectPreservesAutomaticExternalGroup(t *testing.T) {
	deps, _, tenant, userID, project := portalProjectFixture(t)
	before, err := deps.UserRepo.GetByID(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		w := boundPortalContext(deps, tenant, userID, "engineer-subject")
		var response struct {
			Data struct {
				UserID       string `json:"user_id"`
				DepartmentID string `json:"department_id"`
				ProjectID    string `json:"project_id"`
				ChatAllowed  bool   `json:"chat_allowed"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || response.Data.UserID != userID || response.Data.DepartmentID != before.DepartmentID || response.Data.ProjectID != project || !response.Data.ChatAllowed {
			t.Fatalf("bound project context: %d %s", w.Code, w.Body.String())
		}
	}
	after, _ := deps.UserRepo.GetByID(context.Background(), userID)
	if after.DepartmentID != before.DepartmentID || after.DepartmentVersion != before.DepartmentVersion || after.DepartmentAssignmentMode != "automatic" {
		t.Fatalf("read mutated automatic mapping: before=%+v after=%+v", before, after)
	}
}

func TestPortalAuthorizationProjectRejectsSubjectUserAndTenantMismatch(t *testing.T) {
	deps, _, tenant, userID, _ := portalProjectFixture(t)
	for _, tc := range []struct{ tenant, user, subject string }{{tenant, userID, "other-subject"}, {"other-tenant", userID, "engineer-subject"}, {tenant, "missing-user", "engineer-subject"}} {
		w := boundPortalContext(deps, tc.tenant, tc.user, tc.subject)
		if w.Code != 404 {
			t.Fatalf("mismatched binding accepted: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestPortalEmployeeKeyManualFirstIssueBindsOnlyCurrentDefaultProject(t *testing.T) {
	deps, pool, tenant, originalUser, project := portalProjectFixture(t)
	ctx := context.Background()
	var dept string
	if err := pool.QueryRow(ctx, "SELECT department_id FROM users WHERE id=$1", originalUser).Scan(&dept); err != nil {
		t.Fatal(err)
	}
	userID := tenant + "-local-user"
	mustExec(t, pool, `INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode) VALUES($1,$2,'local-employee','chat_user','active',$3,'manual')`, userID, tenant, dept)
	links := repository.NewUserIdentityLinkRepository(pool)
	if err := links.BindLoginSources(ctx, tenant, userID, "https://portal-project.test", "local-subject"); err != nil {
		t.Fatal(err)
	}
	w := boundPortalContext(deps, tenant, userID, "local-subject")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"project_id":"`+project+`"`) {
		t.Fatalf("manual context: %d %s", w.Code, w.Body.String())
	}
	memberships, _ := deps.ProjectUserRepo.GetProjectsByUser(ctx, userID)
	if len(memberships) != 0 {
		t.Fatalf("GET wrote membership: %v", memberships)
	}
	key := httptest.NewRecorder()
	CreatePortalKey(deps)(key, userSyncReq(http.MethodPost, "/x", tenant, fmt.Sprintf(`{"project_id":%q,"user_id":%q,"scopes":["chat","models","responses","embeddings"],"name":"manual employee"}`, project, userID)))
	if key.Code != 200 {
		t.Fatalf("manual first employee key: %d %s", key.Code, key.Body.String())
	}
	memberships, _ = deps.ProjectUserRepo.GetProjectsByUser(ctx, userID)
	if len(memberships) != 1 || memberships[0] != project {
		t.Fatalf("employee key did not bind default project: %v", memberships)
	}
}

func TestPortalAuthorizationUnassignedRemainsReadOnlyAndCannotIssueKey(t *testing.T) {
	deps, pool, tenant, userID, _ := portalProjectFixture(t)
	ctx := context.Background()
	unassigned, err := deps.TeamRepo.GetBySystemKey(ctx, tenant, "unassigned")
	if err != nil || unassigned == nil {
		t.Fatalf("unassigned department: %v", err)
	}
	defaultDept := tenant + "-chat-default"
	defaultProject := tenant + "-chat-default-app"
	mustExec(t, pool, `INSERT INTO teams(id,tenant_id,name,path,system_key) VALUES($1,$2,'Chat default',$1,'chat_default')`, defaultDept, tenant)
	mustExec(t, pool, `INSERT INTO projects(id,tenant_id,name,team_id,status,code,environment) VALUES($1,$2,'Default Chat',$3,'active','fixture','test')`, defaultProject, tenant, defaultDept)
	mustExec(t, pool, `UPDATE users SET department_id=$3,department_assignment_mode='unassigned' WHERE tenant_id=$1 AND id=$2`, tenant, userID, unassigned.ID)
	mustExec(t, pool, `DELETE FROM project_users WHERE user_id=$1`, userID)
	before, _ := deps.UserRepo.GetByID(ctx, userID)
	for i := 0; i < 3; i++ {
		w := boundPortalContext(deps, tenant, userID, "engineer-subject")
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"project_id":""`) || !strings.Contains(w.Body.String(), `"chat_allowed":false`) {
			t.Fatalf("fallback read: %d %s", w.Code, w.Body.String())
		}
	}
	after, _ := deps.UserRepo.GetByID(ctx, userID)
	memberships, _ := deps.ProjectUserRepo.GetProjectsByUser(ctx, userID)
	if after.DepartmentID != before.DepartmentID || after.DepartmentVersion != before.DepartmentVersion || len(memberships) != 0 {
		t.Fatalf("read changed fallback user/membership: before=%+v after=%+v memberships=%v", before, after, memberships)
	}
	key := httptest.NewRecorder()
	CreatePortalKey(deps)(key, userSyncReq(http.MethodPost, "/x", tenant, fmt.Sprintf(`{"project_id":%q,"user_id":%q,"scopes":["chat","models"],"name":"fallback employee"}`, defaultProject, userID)))
	if key.Code != 403 {
		t.Fatalf("unassigned key issue: %d %s", key.Code, key.Body.String())
	}
}

func TestPortalEmployeeKeyCannotCreateArbitraryOrStaleMembership(t *testing.T) {
	deps, pool, tenant, userID, project := portalProjectFixture(t)
	ctx := context.Background()
	before, err := deps.UserRepo.GetByID(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	otherDept := ensureDepartment(t, pool, tenant, "other")
	otherProject := tenant + "-other-app"
	mustExec(t, pool, `INSERT INTO projects(id,tenant_id,name,team_id,status,code,environment) VALUES($1,$2,'Other app',$3,'active','fixture','test')`, otherProject, tenant, otherDept)
	mustExec(t, pool, `DELETE FROM project_users WHERE user_id=$1`, userID)
	key := httptest.NewRecorder()
	CreatePortalKey(deps)(key, userSyncReq(http.MethodPost, "/x", tenant, fmt.Sprintf(`{"project_id":%q,"user_id":%q,"scopes":["chat","models"],"name":"unrelated"}`, otherProject, userID)))
	if key.Code != 200 || !strings.Contains(key.Body.String(), `"project_id":"`+project+`"`) {
		t.Fatalf("server did not select authorized application: status=%d", key.Code)
	}
	memberships, _ := deps.ProjectUserRepo.GetProjectsByUser(ctx, userID)
	if len(memberships) != 1 || memberships[0] != project {
		t.Fatalf("arbitrary app added membership: %v", memberships)
	}
	mustExec(t, pool, `UPDATE users SET department_id=$3,department_assignment_mode='manual' WHERE tenant_id=$1 AND id=$2`, tenant, userID, otherDept)
	bound, err := deps.ProjectUserRepo.BindPortalDefaultProject(ctx, tenant, userID, project, before.DepartmentID, before.DepartmentVersion)
	if err != nil || bound {
		t.Fatalf("stale department revision accepted: %v %v", bound, err)
	}
	mustExec(t, pool, `UPDATE users SET status='disabled' WHERE tenant_id=$1 AND id=$2`, tenant, userID)
	key = httptest.NewRecorder()
	CreatePortalKey(deps)(key, userSyncReq(http.MethodPost, "/x", tenant, fmt.Sprintf(`{"project_id":%q,"user_id":%q,"scopes":["chat","models"],"name":"disabled"}`, otherProject, userID)))
	if key.Code != 403 {
		t.Fatalf("disabled user gained app: %d %s", key.Code, key.Body.String())
	}
	w := boundPortalContext(deps, tenant, userID, "engineer-subject")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"project_id":""`) || !strings.Contains(w.Body.String(), `"chat_allowed":false`) {
		t.Fatalf("disabled context included callable app: %d %s", w.Code, w.Body.String())
	}
}

func TestPortalAuthorizationKeepsServerSourceScopedBindingAcrossRuntimeOriginChange(t *testing.T) {
	deps, pool, tenant, userID, project := portalProjectFixture(t)
	sourceID := tenant + "-enterprise-source"
	mustExec(t, pool, `UPDATE user_identity_links SET source_id=$3 WHERE tenant_id=$1 AND user_id=$2`, tenant, userID, sourceID)
	deps.IdentitySourceLookup = portalIdentitySourceLookupStub{source: &repository.IdentitySource{ID: sourceID}}
	deps.IdentityRuntimeConfig.IssuerURL = "https://current-runtime.test"
	w := boundPortalContext(deps, tenant, userID, "engineer-subject")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"project_id":"`+project+`"`) {
		t.Fatalf("existing configured-source binding lost after runtime origin change: %d %s", w.Code, w.Body.String())
	}
}
