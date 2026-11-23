package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

func userModelRequest(method, tenantID, actorID, role, userID, body string) *http.Request {
	r := httptest.NewRequest(method, "/admin/v1/users/"+url.PathEscape(userID)+"/model-access", strings.NewReader(body))
	route := chi.NewRouteContext()
	route.URLParams.Add("id", userID)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, route)
	ctx = context.WithValue(ctx, auth.UserKey, &repository.User{ID: actorID, TenantID: tenantID, Role: role})
	r.RemoteAddr = "198.51.100.26:1234"
	return r.WithContext(ctx)
}

func TestUserModelAccessScopedPersistenceAndPortal(t *testing.T) {
	pool, tenantID, adminID := setupOrgHandlerPool(t)
	ctx := context.Background()
	teamID := ensureDepartment(t, pool, tenantID, "Personal grants")
	mustExec(t, pool, `UPDATE teams SET model_access_mode='allowlist',model_access_configured=true WHERE id=$1`, teamID)
	providerID, models := wtProviderModels(t, pool, tenantID, "personal-model-a", "personal-model-b", "personal-model-c")
	t.Cleanup(func() {
		mustExec(t, pool, "DELETE FROM team_models WHERE team_id=$1", teamID)
		mustExec(t, pool, "DELETE FROM models WHERE provider_id=$1", providerID)
		mustExec(t, pool, "DELETE FROM providers WHERE id=$1", providerID)
	})

	mustExec(t, pool, `INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status) VALUES($1,$2,'fixture','fixture','fixture','active')`, providerID+"_credential", providerID)
	for _, id := range models {
		mustExec(t, pool, `INSERT INTO model_endpoint_capability_overrides(id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id,config_version) VALUES($1,$2,$3,'chat','supported','fixture',$4,1)`, "ov_"+id, tenantID, id, adminID)
	}
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM model_endpoint_capability_overrides WHERE tenant_id=$1`, tenantID)
		mustExec(t, pool, `DELETE FROM provider_credentials WHERE provider_id=$1`, providerID)
	})
	memberID := "member_" + adminID
	mustExec(t, pool, `INSERT INTO users (id,tenant_id,username,role,status,department_id,department_assignment_mode) VALUES ($1,$2,$1,'developer','active',$3,'manual')`, memberID, tenantID, teamID)
	teamModels := repository.NewTeamModelRepository(pool)
	for _, modelID := range models[:2] {
		if err := teamModels.Upsert(ctx, &repository.TeamModel{TeamID: teamID, ModelID: modelID, Allowed: true}); err != nil {
			t.Fatal(err)
		}
	}
	chain := &recordingChainWriter{}
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool), TeamModelRepo: teamModels, UserModelRepo: repository.NewUserModelRepository(pool), AuditAppender: audit_chain.NewAppender(chain, false)}

	w := httptest.NewRecorder()
	GetUserModelAccess(deps)(w, userModelRequest(http.MethodGet, tenantID, adminID, "platform_admin", memberID, ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"mode":"inherit"`) || !strings.Contains(w.Body.String(), "personal-model-b") {
		t.Fatalf("inherit: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	SetUserModelAccess(deps)(w, userModelRequest(http.MethodPut, tenantID, adminID, "platform_admin", memberID, `{"mode":"allowlist","model_names":["personal-model-c"],"version":0}`))
	if w.Code != 400 {
		t.Fatalf("department escalation: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	SetUserModelAccess(deps)(w, userModelRequest(http.MethodPut, tenantID, adminID, "platform_admin", memberID, `{"mode":"allowlist","model_names":["personal-model-a"],"version":0}`))
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	var access struct {
		Data struct {
			EffectiveModels []string `json:"effective_models"`
			Version         int64    `json:"version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &access); err != nil {
		t.Fatal(err)
	}
	if len(access.Data.EffectiveModels) != 1 || access.Data.EffectiveModels[0] != "personal-model-a" || access.Data.Version != 1 {
		t.Fatalf("personal: %+v", access)
	}

	var auditIP string
	if err := pool.QueryRow(ctx, "SELECT ip_address FROM audit_operations WHERE tenant_id=$1 AND action_type='user.model_access.updated' ORDER BY created_at DESC LIMIT 1", tenantID).Scan(&auditIP); err != nil || auditIP != "198.51.100.26" {
		t.Errorf("policy audit IP=%q err=%v", auditIP, err)
	}
	deadline := time.Now().Add(time.Second)
	for chain.count() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if chain.count() != 1 {
		t.Errorf("policy audit missing in chain: %d", chain.count())
	}

	t.Run("ReviewDuplicateExtraGrantAndAudit", func(t *testing.T) {
		req := userModelRequest("POST", tenantID, adminID, "platform_admin", memberID, `{"model":"personal-model-c","reason":"专项授权"}`)
		made := httptest.NewRecorder()
		CreateUserModelExtraGrant(deps)(made, req)
		var reply struct{ Data struct{ ID string } }
		if made.Code != 200 || json.Unmarshal(made.Body.Bytes(), &reply) != nil || reply.Data.ID == "" {
			t.Fatalf("extra creation status=%d body=%s", made.Code, made.Body.String())
		}
		repeated := httptest.NewRecorder()
		CreateUserModelExtraGrant(deps)(repeated, userModelRequest("POST", tenantID, adminID, "platform_admin", memberID, `{"model":"personal-model-c","reason":"专项授权"}`))
		if repeated.Code != 409 {
			t.Fatalf("duplicate extra status=%d", repeated.Code)
		}
		revoke := userModelRequest("POST", tenantID, adminID, "platform_admin", memberID, "")
		route := chi.NewRouteContext()
		route.URLParams.Add("id", memberID)
		route.URLParams.Add("grant_id", reply.Data.ID)
		revoke = revoke.WithContext(context.WithValue(revoke.Context(), chi.RouteCtxKey, route))
		removed := httptest.NewRecorder()
		RevokeUserModelExtraGrant(deps)(removed, revoke)
		if removed.Code != 200 {
			t.Fatalf("extra revoke=%d", removed.Code)
		}
		deadline := time.Now().Add(time.Second)
		for chain.count() < 3 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if chain.count() != 3 {
			t.Fatalf("policy/grant/revoke chain count=%d", chain.count())
		}
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND action_type IN('user.model_extra.granted','user.model_extra.revoked') AND ip_address='198.51.100.26'", tenantID).Scan(&count); err != nil || count != 2 {
			t.Fatalf("grant/revoke IP audits=%d err=%v", count, err)
		}
	})
	w = httptest.NewRecorder()
	GetPortalUserAuthorizationContext(deps)(w, portalAuthorizationRequest(tenantID, memberID))
	var portal struct {
		Data struct {
			Models []string `json:"model_ids"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &portal); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(portal.Data.Models) != 1 || portal.Data.Models[0] != "personal-model-a" {
		t.Fatalf("portal: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	SetUserModelAccess(deps)(w, userModelRequest(http.MethodPut, tenantID, adminID, "platform_admin", memberID, `{"mode":"inherit","model_names":[],"version":0}`))
	if w.Code != 409 {
		t.Fatalf("stale version: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	SetUserModelAccess(deps)(w, userModelRequest(http.MethodPut, tenantID, adminID, "platform_admin", memberID, `{"mode":"allowlist","model_names":[],"version":1}`))
	if w.Code != 200 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	GetPortalUserAuthorizationContext(deps)(w, portalAuthorizationRequest(tenantID, memberID))
	if !strings.Contains(w.Body.String(), `"model_ids":[]`) {
		t.Fatalf("revoke must remove all models: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	GetUserModelAccess(deps)(w, userModelRequest(http.MethodGet, "different-tenant", adminID, "platform_admin", memberID, ""))
	if w.Code != 404 {
		t.Fatalf("cross tenant: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	SetUserModelAccess(deps)(w, userModelRequest(http.MethodPut, tenantID, memberID, "developer", memberID, `{"mode":"inherit","version":2}`))
	if w.Code != 403 {
		t.Fatalf("self escalation: %d %s", w.Code, w.Body.String())
	}
}

func TestTenantAdminModelAccessCannotCrossTenant(t *testing.T) {
	pool, tenant, admin := setupOrgHandlerPool(t)
	mustExec(t, pool, `UPDATE users SET role='tenant_admin' WHERE id=$1`, admin)
	deps := &Dependencies{UserModelRepo: repository.NewUserModelRepository(pool)}
	w := httptest.NewRecorder()
	GetUserModelAccess(deps)(w, userModelRequest("GET", tenant, admin, "tenant_admin", admin, ""))
	if w.Code != 200 {
		t.Fatalf("own tenant status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	GetUserModelAccess(deps)(w, userModelRequest("GET", "other-tenant", admin, "tenant_admin", admin, ""))
	if w.Code != 404 {
		t.Fatalf("cross tenant status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	CreateUserModelExtraGrant(deps)(w, userModelRequest("POST", "other-tenant", admin, "tenant_admin", admin, `{"model":"extra","reason":"业务"}`))
	if w.Code != 404 {
		t.Fatalf("cross tenant grant status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	CreateUserModelExtraGrant(deps)(w, userModelRequest("POST", tenant, admin, "tenant_admin", admin, `{"model":"extra","reason":"业务","role":"platform_admin"}`))
	if w.Code != 400 {
		t.Fatalf("browser privilege override status=%d", w.Code)
	}
}

func TestPortalOwnedKeyProjectIsChosenByServer(t *testing.T) {
	pool, tenant, user := setupOrgHandlerPool(t)
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "portal-key-test-only")
	dept := ensureDepartment(t, pool, tenant, "Default key application")
	mustExec(t, pool, `UPDATE users SET role='developer',department_id=$1,department_assignment_mode='manual' WHERE id=$2`, dept, user)
	first, second := "first_"+user, "second_"+user
	mustExec(t, pool, `INSERT INTO projects(id,tenant_id,name,status,team_id,created_at,code,environment) VALUES($1,$3,'default','active',$4,'2026-10-10','default','production'),($2,$3,'browser choice','active',$4,'2026-10-11','other','production')`, first, second, tenant, dept)
	memberships := repository.NewProjectUserRepository(pool)
	if err := memberships.BindUser(context.Background(), first, user); err != nil {
		t.Fatal(err)
	}
	if err := memberships.BindUser(context.Background(), second, user); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenant)
		mustExec(t, pool, `DELETE FROM project_users WHERE user_id=$1`, user)
		mustExec(t, pool, `DELETE FROM projects WHERE tenant_id=$1`, tenant)
	})
	deps := &Dependencies{UserRepo: repository.NewUserRepository(pool), ProjectRepo: repository.NewProjectRepository(pool), ProjectUserRepo: memberships, UserModelRepo: repository.NewUserModelRepository(pool), KeyRepo: repository.NewInternalKeyRepository(pool)}
	request := portalAdminReq("POST", "/admin/v1/portal-integration/keys", tenant, `{"project_id":"`+second+`","user_id":"`+user+`","name":"个人调用","scopes":["chat","models"]}`)
	w := httptest.NewRecorder()
	CreatePortalKey(deps)(w, request)
	if w.Code != 200 && w.Code != 201 {
		t.Fatalf("create status=%d", w.Code)
	}
	var result struct {
		ProjectID string `json:"project_id"`
		UserID    string `json:"user_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal("invalid response JSON")
	}
	if result.ProjectID != first || result.UserID != user {
		t.Fatal("key application came from browser input")
	}
}

func TestDepartmentModelModesAPISeparatesDefaultAndExplicitDeny(t *testing.T) {
	pool, tenant, admin := setupOrgHandlerPool(t)
	team := ensureDepartment(t, pool, tenant, "Default department API")
	deps := buildWTDeps(pool)
	w := httptest.NewRecorder()
	GetTeamModels(deps)(w, userModelRequest("GET", tenant, admin, "platform_admin", team, ""))
	var before struct {
		Mode       string `json:"model_access_mode"`
		Configured bool   `json:"model_access_configured"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &before) != nil || before.Mode != "all_active" || before.Configured {
		t.Fatalf("default metadata status=%d mode=%s configured=%v", w.Code, before.Mode, before.Configured)
	}
	for _, mode := range []string{"deny_all", "allowlist", "all_active"} {
		w = httptest.NewRecorder()
		PutTeamModels(deps)(w, userModelRequest("PUT", tenant, admin, "platform_admin", team, `{"mode":"`+mode+`","models":[]}`))
		if w.Code != 200 {
			t.Fatalf("save mode=%s status=%d", mode, w.Code)
		}
		actual, configured, err := deps.TeamModelRepo.GetAccessMode(context.Background(), tenant, team)
		if err != nil || actual != mode || !configured {
			t.Fatalf("mode=%s configured=%v err=%v", actual, configured, err)
		}
	}
}
