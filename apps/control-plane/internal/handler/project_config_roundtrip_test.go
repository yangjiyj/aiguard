package handler

// 控制台巡检（11-10）：应用的配置在 API 里“有进无出”，并且改名/停用会把它清空——
//   - 列表/详情只回 id、名称、状态：应用页的“代码”“环境”永远是“-”，应用抽屉里的模型白名单、额度、
//     所属部门永远是空的，而抽屉里的“保存模型”会把真实配置整个覆盖成空并把应用移出部门；
//   - PATCH /projects/{id}（改名、停用、启用）不带现有的 model_whitelist / quota_limits，
//     仓库层 Update 又是整列写回，于是每次改名或停用再启用都会把模型白名单和额度清空。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type roundTripProjectRepo struct {
	fakeProjectRepo
	updated *repository.Project
}

func (r *roundTripProjectRepo) List(context.Context, string) ([]*repository.Project, error) {
	return []*repository.Project{r.project}, nil
}
func (r *roundTripProjectRepo) Update(_ context.Context, project *repository.Project) error {
	r.updated = project
	return nil
}

func configuredProject() *repository.Project {
	return &repository.Project{
		ID: "proj_cfg", TenantID: "tenant_default", Name: "配置齐全的应用", Code: "cfg", Environment: "production",
		OwnerUserID: "user_admin", TeamID: "team_rd", Status: "active",
		ModelWhitelist: []string{"gpt-4o", "qwen-max"},
		QuotaLimits:    map[string]any{"daily_tokens": float64(1000)},
		CreatedAt:      time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC),
	}
}

func projectRequest(method, body string) *http.Request {
	req := httptest.NewRequest(method, "/admin/v1/projects/proj_cfg", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user_admin", TenantID: "tenant_default", Role: "platform_admin", Status: "active"}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "proj_cfg")
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestUpdateProjectKeepsModelWhitelistAndQuotaLimits(t *testing.T) {
	repo := &roundTripProjectRepo{fakeProjectRepo: fakeProjectRepo{project: configuredProject()}}
	deps := &Dependencies{ProjectRepo: repo}

	for _, body := range []string{`{"name":"改了名字"}`, `{"status":"disabled"}`} {
		repo.updated = nil
		rr := httptest.NewRecorder()
		UpdateProject(deps).ServeHTTP(rr, projectRequest(http.MethodPatch, body))
		if rr.Code != http.StatusOK || repo.updated == nil {
			t.Fatalf("body=%s status=%d %s", body, rr.Code, rr.Body.String())
		}
		if strings.Join(repo.updated.ModelWhitelist, ",") != "gpt-4o,qwen-max" || repo.updated.QuotaLimits["daily_tokens"] != float64(1000) {
			t.Fatalf("body=%s 改名/停用不能清空模型白名单和额度: whitelist=%v quota=%v", body, repo.updated.ModelWhitelist, repo.updated.QuotaLimits)
		}
	}
}

func decodeProjectInfo(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rr.Body.String(), err)
	}
	return out
}

func assertFullProjectConfig(t *testing.T, got map[string]any) {
	t.Helper()
	if got["code"] != "cfg" || got["environment"] != "production" || got["team_id"] != "team_rd" {
		t.Fatalf("代码/环境/所属部门要带回控制台: %v", got)
	}
	whitelist, _ := got["model_whitelist"].([]any)
	quota, _ := got["quota_limits"].(map[string]any)
	if len(whitelist) != 2 || whitelist[0] != "gpt-4o" || quota["daily_tokens"] != float64(1000) {
		t.Fatalf("模型白名单/额度要带回控制台: %v", got)
	}
}

func TestGetProjectReturnsFullConfigForTheDrawer(t *testing.T) {
	deps := &Dependencies{ProjectRepo: &roundTripProjectRepo{fakeProjectRepo: fakeProjectRepo{project: configuredProject()}}}
	rr := httptest.NewRecorder()
	GetProject(deps).ServeHTTP(rr, projectRequest(http.MethodGet, ""))
	assertFullProjectConfig(t, decodeProjectInfo(t, rr))
}

func TestListProjectsReturnsCodeAndEnvironmentForTheCards(t *testing.T) {
	deps := &Dependencies{ProjectRepo: &roundTripProjectRepo{fakeProjectRepo: fakeProjectRepo{project: configuredProject()}}}
	rr := httptest.NewRecorder()
	ListProjects(deps).ServeHTTP(rr, projectRequest(http.MethodGet, ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || len(body.Data) != 1 {
		t.Fatalf("decode %s: %v", rr.Body.String(), err)
	}
	assertFullProjectConfig(t, body.Data[0])
}
