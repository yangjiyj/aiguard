package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// buildWTDeps 装配写穿相关 repo（buildOrgDeps 不含 Project/Model/ModelPolicy/TeamModel）。
func buildWTDeps(pool *pgxpool.Pool) *Dependencies {
	return &Dependencies{
		TeamRepo:        repository.NewTeamRepository(pool),
		ProjectRepo:     repository.NewProjectRepository(pool),
		ModelRepo:       repository.NewModelRepository(pool),
		ModelPolicyRepo:      repository.NewModelPolicyRepository(pool),
		GroupMappingRuleRepo: repository.NewGroupMappingRuleRepository(pool),
		TeamModelRepo:        repository.NewTeamModelRepository(pool),
		KeyRepo:              repository.NewInternalKeyRepository(pool),
		SystemRepo:           &orgTestSystemRepo{},
	}
}

// wtProviderModels 插入一个 provider + 若干模型，返回 provID 与各模型行ID。
func wtProviderModels(t *testing.T, pool *pgxpool.Pool, tenantID string, names ...string) (provID string, ids []string) {
	t.Helper()
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	provID = "prov_" + sfx
	mustExec(t, pool, `INSERT INTO providers (id,tenant_id,name,provider_type) VALUES ($1,$2,$3,$4)`, provID, tenantID, provID, "openai")
	for i, n := range names {
		id := fmt.Sprintf("model_%s_%d", sfx, i)
		mustExec(t, pool, `INSERT INTO models (id,provider_id,model_name) VALUES ($1,$2,$3)`, id, provID, n)
		ids = append(ids, id)
	}
	return provID, ids
}

func TestPutTeamModelsWritesThroughToProjectPolicy(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildWTDeps(pool)

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	nameGLM, nameGPT := "glm-5.2-"+sfx, "gpt-5.5-"+sfx
	provID, ids := wtProviderModels(t, pool, tenantID, nameGLM, nameGPT)
	teamID, projID := "twt_"+sfx, "pwt_"+sfx
	mustExec(t, pool, `INSERT INTO teams (id,tenant_id,name,path,monthly_budget_cny,daily_budget_cny) VALUES ($1,$2,$3,$4,0,0)`, teamID, tenantID, "研发部", "/"+teamID)
	mustExec(t, pool, `INSERT INTO projects (id,tenant_id,name,code,team_id) VALUES ($1,$2,$3,$4,$5)`, projID, tenantID, "portal-dev-eng", projID, teamID)
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM model_policies WHERE tenant_id=$1`, tenantID)
		mustExec(t, pool, `DELETE FROM team_models WHERE team_id=$1`, teamID)
		mustExec(t, pool, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
		mustExec(t, pool, `DELETE FROM models WHERE provider_id=$1`, provID)
		mustExec(t, pool, `DELETE FROM providers WHERE id=$1`, provID)
	})

	// 只放行 glm（行ID = ids[0]）
	body := bytes.NewReader([]byte(`{"models":[{"model_id":"` + ids[0] + `","allowed":true}]}`))
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/teams/"+teamID+"/models", body)
	req = withOrgUserCtx(req, tenantID, userID)
	req = chiCtxWithID(req, teamID)
	w := httptest.NewRecorder()
	PutTeamModels(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	// 断言：project 策略 allow_models_json 被写成【模型名】而非行ID
	pol, err := deps.ModelPolicyRepo.GetByProject(context.Background(), tenantID, projID)
	if err != nil || pol == nil {
		t.Fatalf("policy missing: %v", err)
	}
	if len(pol.AllowList) != 1 || pol.AllowList[0] != nameGLM {
		t.Fatalf("want allow=[%s], got %v", nameGLM, pol.AllowList)
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	pp, _ := resp["propagated_project_ids"].([]any)
	if len(pp) != 1 {
		t.Fatalf("want 1 propagated project, got %v", resp)
	}
}

func TestPutTeamModelsRejectsUnknownModel(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildWTDeps(pool)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	teamID := "tunk_" + sfx
	mustExec(t, pool, `INSERT INTO teams (id,tenant_id,name,path,monthly_budget_cny,daily_budget_cny) VALUES ($1,$2,$3,$4,0,0)`, teamID, tenantID, "研发部", "/"+teamID)
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM team_models WHERE team_id=$1`, teamID)
	})

	body := bytes.NewReader([]byte(`{"models":[{"model_id":"model_does_not_exist","allowed":true}]}`))
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/teams/"+teamID+"/models", body)
	req = withOrgUserCtx(req, tenantID, userID)
	req = chiCtxWithID(req, teamID)
	w := httptest.NewRecorder()
	PutTeamModels(deps)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestPutTeamModelsWarnsWhenNoProject(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildWTDeps(pool)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	nameM := "m-" + sfx
	provID, ids := wtProviderModels(t, pool, tenantID, nameM)
	teamID := "tnp_" + sfx
	mustExec(t, pool, `INSERT INTO teams (id,tenant_id,name,path,monthly_budget_cny,daily_budget_cny) VALUES ($1,$2,$3,$4,0,0)`, teamID, tenantID, "空部门", "/"+teamID)
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM team_models WHERE team_id=$1`, teamID)
		mustExec(t, pool, `DELETE FROM models WHERE provider_id=$1`, provID)
		mustExec(t, pool, `DELETE FROM providers WHERE id=$1`, provID)
	})

	body := bytes.NewReader([]byte(`{"models":[{"model_id":"` + ids[0] + `","allowed":true}]}`))
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/teams/"+teamID+"/models", body)
	req = withOrgUserCtx(req, tenantID, userID)
	req = chiCtxWithID(req, teamID)
	w := httptest.NewRecorder()
	PutTeamModels(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["warning"] == nil {
		t.Fatalf("want warning when no project, got %v", resp)
	}
}

func TestPatchProjectTeamSeedsTeamModelsFromPolicy(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildWTDeps(pool)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	name := "glm-5.2-" + sfx
	provID, ids := wtProviderModels(t, pool, tenantID, name)
	teamID, projID := "tseed_"+sfx, "pseed_"+sfx
	// 空 team（无 team_models）+ 未挂 project，project 已有策略 [name]
	mustExec(t, pool, `INSERT INTO teams (id,tenant_id,name,path,monthly_budget_cny,daily_budget_cny) VALUES ($1,$2,$3,$4,0,0)`, teamID, tenantID, "研发部", "/"+teamID)
	mustExec(t, pool, `INSERT INTO projects (id,tenant_id,name,code) VALUES ($1,$2,$3,$4)`, projID, tenantID, "portal-dev-eng", projID)
	if err := deps.ModelPolicyRepo.CreateOrUpdate(context.Background(), &repository.ModelPolicy{
		TenantID: tenantID, ProjectID: projID, ScopeType: "project", AllowList: []string{name},
	}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM model_policies WHERE tenant_id=$1`, tenantID)
		mustExec(t, pool, `DELETE FROM team_models WHERE team_id=$1`, teamID)
		mustExec(t, pool, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
		mustExec(t, pool, `DELETE FROM models WHERE provider_id=$1`, provID)
		mustExec(t, pool, `DELETE FROM providers WHERE id=$1`, provID)
	})

	body := bytes.NewReader([]byte(`{"team_id":"` + teamID + `"}`))
	req := httptest.NewRequest(http.MethodPatch, "/admin/v1/projects/"+projID+"/team", body)
	req = withOrgUserCtx(req, tenantID, userID)
	req = chiCtxWithID(req, projID)
	w := httptest.NewRecorder()
	PatchProjectTeam(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	// 断言：team_models 被反向种成 [行ID=ids[0]]（名→行ID）
	tms, err := deps.TeamModelRepo.ListByTeam(context.Background(), teamID)
	if err != nil {
		t.Fatalf("list team models: %v", err)
	}
	found := false
	for _, tm := range tms {
		if tm.ModelID == ids[0] && tm.Allowed {
			found = true
		}
	}
	if !found {
		t.Fatalf("team_models not seeded with row id %s: %+v", ids[0], tms)
	}
}

func TestGetTeamProjectsReturnsLowercaseKeys(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildWTDeps(pool)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	teamID, projID := "tgp_"+sfx, "pgp_"+sfx
	mustExec(t, pool, `INSERT INTO teams (id,tenant_id,name,path,monthly_budget_cny,daily_budget_cny) VALUES ($1,$2,$3,$4,0,0)`, teamID, tenantID, "研发部", "/"+teamID)
	mustExec(t, pool, `INSERT INTO projects (id,tenant_id,name,code,team_id) VALUES ($1,$2,$3,$4,$5)`, projID, tenantID, "portal-dev-eng", projID, teamID)
	t.Cleanup(func() { mustExec(t, pool, `DELETE FROM projects WHERE tenant_id=$1`, tenantID) })

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/teams/"+teamID+"/projects", nil)
	req = withOrgUserCtx(req, tenantID, userID)
	req = chiCtxWithID(req, teamID)
	w := httptest.NewRecorder()
	GetTeamProjects(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Data) != 1 {
		t.Fatalf("want 1 project, got %v", resp.Data)
	}
	if resp.Data[0]["name"] != "portal-dev-eng" || resp.Data[0]["id"] != projID {
		t.Fatalf("want lowercase name/id, got %v", resp.Data[0])
	}
}

func TestPatchProjectTeamPushesWhitelistToProject(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildWTDeps(pool)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	nameA, nameB := "glm-5.2-"+sfx, "gpt-5.5-"+sfx
	provID, ids := wtProviderModels(t, pool, tenantID, nameA, nameB)
	teamID, projID := "tpush_"+sfx, "ppush_"+sfx
	mustExec(t, pool, `INSERT INTO teams (id,tenant_id,name,path,monthly_budget_cny,daily_budget_cny) VALUES ($1,$2,$3,$4,0,0)`, teamID, tenantID, "研发部", "/"+teamID)
	mustExec(t, pool, `INSERT INTO projects (id,tenant_id,name,code) VALUES ($1,$2,$3,$4)`, projID, tenantID, "portal-dev-eng", projID)
	// team 已有白名单 [A,B]（team_models 存行ID）
	if err := deps.TeamModelRepo.UpsertBatch(context.Background(), teamID, []*repository.TeamModel{
		{TeamID: teamID, ModelID: ids[0], Allowed: true, GrantedBy: userID},
		{TeamID: teamID, ModelID: ids[1], Allowed: true, GrantedBy: userID},
	}); err != nil {
		t.Fatalf("seed team_models: %v", err)
	}
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM model_policies WHERE tenant_id=$1`, tenantID)
		mustExec(t, pool, `DELETE FROM team_models WHERE team_id=$1`, teamID)
		mustExec(t, pool, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
		mustExec(t, pool, `DELETE FROM models WHERE provider_id=$1`, provID)
		mustExec(t, pool, `DELETE FROM providers WHERE id=$1`, provID)
	})

	// 挂 project 到 team（team 已有白名单 → 应把白名单推给该 project 策略）
	body := bytes.NewReader([]byte(`{"team_id":"` + teamID + `"}`))
	req := httptest.NewRequest(http.MethodPatch, "/admin/v1/projects/"+projID+"/team", body)
	req = withOrgUserCtx(req, tenantID, userID)
	req = chiCtxWithID(req, projID)
	w := httptest.NewRecorder()
	PatchProjectTeam(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	pol, err := deps.ModelPolicyRepo.GetByProject(context.Background(), tenantID, projID)
	if err != nil || pol == nil {
		t.Fatalf("policy missing: %v", err)
	}
	got := map[string]bool{}
	for _, m := range pol.AllowList {
		got[m] = true
	}
	if len(pol.AllowList) != 2 || !got[nameA] || !got[nameB] {
		t.Fatalf("want project policy=[%s,%s], got %v", nameA, nameB, pol.AllowList)
	}
}

func TestGetUserKeysReturnsUserKeysMasked(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildWTDeps(pool)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	projID := "pk_" + sfx
	mustExec(t, pool, `INSERT INTO projects (id,tenant_id,name,code) VALUES ($1,$2,$3,$4)`, projID, tenantID, "app", projID)
	key := &repository.InternalKey{
		ID: "key_" + sfx, TenantID: tenantID, ProjectID: projID, UserID: userID,
		Name: "alice@corp.test", KeyPrefix: "na_pref", Status: "active",
	}
	if err := deps.KeyRepo.Create(context.Background(), key, "na_pref_"+sfx+"_rawfullkey"); err != nil {
		t.Fatalf("create key: %v", err)
	}
	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM internal_keys WHERE tenant_id=$1`, tenantID)
		mustExec(t, pool, `DELETE FROM projects WHERE tenant_id=$1`, tenantID)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/users/"+userID+"/keys", nil)
	req = withOrgUserCtx(req, tenantID, userID)
	req = chiCtxWithID(req, userID)
	w := httptest.NewRecorder()
	GetUserKeys(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "na_pref") {
		t.Fatalf("want key_prefix in body, got %s", body)
	}
	// 脱敏铁律：绝不回传 hash / 密文
	if strings.Contains(body, "key_hash") || strings.Contains(body, "ciphertext") || strings.Contains(body, "rawfullkey") {
		t.Fatalf("body leaked secret: %s", body)
	}
}
