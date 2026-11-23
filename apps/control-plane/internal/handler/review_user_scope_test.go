package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"net/http/httptest"
	"testing"
)

func TestReviewTenantUserListPaginatesInsideTenantSQL(t *testing.T) {
	db, tenant, admin := setupOrgHandlerPool(t)
	mustExec(t, db, "UPDATE tenants SET is_test=false WHERE id=$1", tenant)
	mustExec(t, db, "UPDATE users SET role='tenant_admin' WHERE id=$1", admin)
	for _, id := range []string{tenant + "_one", tenant + "_two", tenant + "_three"} {
		mustExec(t, db, "INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,$1,'chat_user','active')", id, tenant)
	}
	req := httptest.NewRequest("GET", "/admin/v1/users?limit=2&offset=2", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: admin, TenantID: tenant, Role: "tenant_admin"}))
	w := httptest.NewRecorder()
	ListUsers(&Dependencies{UserRepo: repository.NewUserRepository(db)})(w, req)
	var reply struct {
		Data  []struct{ ID, TenantID string }
		Total int
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(reply.Data) != 2 || reply.Total != 4 {
		t.Fatalf("status=%d rows=%d total=%d", w.Code, len(reply.Data), reply.Total)
	}
}
func TestReviewEmployeePasswordRequiresDirectoryLookup(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	e.deps.UserIdentityLinkLookup = nil
	if w := e.employeeLogin(u.Username, u.Password, "192.0.2.1", nil); w.Code != 503 {
		t.Fatalf("missing identity lookup accepted credentials: %d", w.Code)
	}
}
func TestReviewNonAllowlistDepartmentPreservesServiceProjectPolicy(t *testing.T) {
	db, tenant, admin := setupOrgHandlerPool(t)
	team := ensureDepartment(t, db, tenant, "Scope test")
	deps := buildWTDeps(db)
	project := tenant + "_project"
	mustExec(t, db, "INSERT INTO projects(id,tenant_id,name,team_id,status,code,environment) VALUES($1,$2,$1,$3,'active','fixture','production')", project, tenant, team)
	mustExec(t, db, `INSERT INTO model_policies(id,tenant_id,project_id,scope_type,scope_ref,allow_models_json,deny_models_json) VALUES($1,$2,$3,'project',$3,'["restricted-model"]','[]')`, tenant+"_policy", tenant, project)
	t.Cleanup(func() {
		db.Exec(context.Background(), "DELETE FROM model_policies WHERE tenant_id=$1", tenant)
		db.Exec(context.Background(), "DELETE FROM projects WHERE tenant_id=$1", tenant)
	})
	for _, mode := range []string{"all_active", "deny_all"} {
		payload, _ := json.Marshal(map[string]any{"mode": mode, "models": []any{}})
		w := httptest.NewRecorder()
		PutTeamModels(deps)(w, userModelRequest("PUT", tenant, admin, "platform_admin", team, string(payload)))
		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		policy, err := deps.ModelPolicyRepo.GetByProject(context.Background(), tenant, project)
		if err != nil || policy == nil || len(policy.AllowList) != 1 || policy.AllowList[0] != "restricted-model" {
			t.Errorf("mode=%s overwrote project authorization: %v %v", mode, policy, err)
		}
	}
}
func TestReviewTenantAdminCannotGrantSelf(t *testing.T) {
	db, tenant, admin := setupOrgHandlerPool(t)
	mustExec(t, db, "UPDATE users SET role='tenant_admin' WHERE id=$1", admin)
	team := ensureDepartment(t, db, tenant, "Self grant fixture")
	mustExec(t, db, "UPDATE users SET department_id=$2,department_assignment_mode='manual' WHERE id=$1", admin, team)
	provider, models := wtProviderModels(t, db, tenant, "fixture")
	mustExec(t, db, "UPDATE providers SET base_url='https://fixture.invalid' WHERE id=$1", provider)
	mustExec(t, db, "INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status) VALUES($1,$2,'fixture','fixture','fixture','active')", provider+"_cred", provider)
	mustExec(t, db, "INSERT INTO model_endpoint_capability_overrides(id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id,config_version) VALUES($1,$2,$3,'chat','supported','fixture',$4,1)", provider+"_ov", tenant, models[0], admin)
	t.Cleanup(func() {
		db.Exec(context.Background(), "DELETE FROM model_endpoint_capability_overrides WHERE tenant_id=$1", tenant)
		db.Exec(context.Background(), "DELETE FROM provider_credentials WHERE provider_id=$1", provider)
		db.Exec(context.Background(), "DELETE FROM models WHERE provider_id=$1", provider)
		db.Exec(context.Background(), "DELETE FROM providers WHERE id=$1", provider)
	})
	w := httptest.NewRecorder()
	CreateUserModelExtraGrant(&Dependencies{UserModelRepo: repository.NewUserModelRepository(db)})(w, userModelRequest("POST", tenant, admin, "tenant_admin", admin, "{\"model\":\"fixture\",\"reason\":\"self grant\"}"))
	if w.Code != 403 {
		t.Fatalf("self grant status=%d", w.Code)
	}
}
