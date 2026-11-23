package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 9.2：?source=new 新建第二个身份源，alias 由服务端派生（jjd-），发布到自己的 broker；
// 默认身份源保持启用，列表同时返回两个身份源及各自的回调地址。
func TestSecondIdentitySourceCoexistsWithDefault(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{publication: identityruntime.Publication{Digest: handlerTestDigest}}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	def := seedActiveIdentitySource(t, deps, tenantID, userID)

	body := `{"display_name":"第二身份源","issuer_url":"https://idp2.example.com","client_id":"c2","client_secret":"s2"}`
	// 客户端试图自带 alias 的字段会被忽略：alias 只由服务端派生。
	req := withOrgUserCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft?source=new", strings.NewReader(body)), tenantID, userID)
	w := httptest.NewRecorder()
	SaveIdentityDraft(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("save new source: %d %s", w.Code, w.Body.String())
	}
	var dto identitySourceDTO
	_ = json.Unmarshal(w.Body.Bytes(), &dto)
	alias := dto.SourceAlias
	if !strings.HasPrefix(alias, "jjd-") || !identityruntime.ValidProviderAlias(alias) {
		t.Fatalf("server must derive a jjd- alias, got %q", alias)
	}
	wantCallback := "https://sso.example.com/sso/realms/jjdguard/broker/" + alias + "/endpoint"
	if dto.CallbackURL != wantCallback {
		t.Fatalf("callback = %q, want %q", dto.CallbackURL, wantCallback)
	}

	// 默认身份源的草稿接口（不带 source）看不到新身份源。
	if d, _ := deps.IdentitySourceRepo.GetDraft(context.Background(), tenantID); d != nil {
		t.Fatalf("default draft must stay empty, got %+v", d)
	}
	src, err := deps.IdentitySourceRepo.GetDraftByAlias(context.Background(), tenantID, alias)
	if err != nil || src == nil {
		t.Fatalf("draft by alias: %+v %v", src, err)
	}
	if err := deps.IdentitySourceRepo.UpdateTestResult(context.Background(), tenantID, src.ID, src.Version, &repository.TestResult{Success: true}); err != nil {
		t.Fatal(err)
	}

	act := withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/activate?source="+alias, nil), tenantID, userID)
	aw := httptest.NewRecorder()
	ActivateIdentitySource(deps)(aw, act)
	if aw.Code != http.StatusOK {
		t.Fatalf("activate second: %d %s", aw.Code, aw.Body.String())
	}
	if runtime.desired.Alias != alias || runtime.desired.Realm != identityruntime.RealmName {
		t.Fatalf("published to %q/%q, want %q", runtime.desired.Realm, runtime.desired.Alias, alias)
	}

	if got, _ := deps.IdentitySourceRepo.GetByID(context.Background(), tenantID, def.ID); got.Status != "active" {
		t.Fatalf("default source must stay active, got %s", got.Status)
	}

	list := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/sources", nil), tenantID, userID)
	lw := httptest.NewRecorder()
	GetIdentitySources(deps)(lw, list)
	var resp struct {
		Data []identitySourceDTO `json:"data"`
	}
	_ = json.Unmarshal(lw.Body.Bytes(), &resp)
	callbacks := map[string]string{}
	for _, s := range resp.Data {
		if s.Status == "active" {
			callbacks[s.SourceAlias] = s.CallbackURL
		}
	}
	if len(callbacks) != 2 || callbacks[alias] != wantCallback ||
		callbacks["enterprise"] != "https://sso.example.com/sso/realms/jjdguard/broker/enterprise/endpoint" {
		t.Fatalf("active sources/callbacks = %v", callbacks)
	}
}

// 9.2：非法 alias 400，未知 alias 404；都不触碰运行态。
func TestIdentitySourceAliasParameterRejected(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	body := `{"display_name":"x","issuer_url":"https://idp.example.com","client_id":"c","client_secret":"s"}`

	for _, bad := range []string{"other", "master", "jjd-UP", "..%2Fenterprise", "jjd-a%2Fb"} {
		req := withOrgUserCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft?source="+bad, bytes.NewReader([]byte(body))), tenantID, userID)
		w := httptest.NewRecorder()
		SaveIdentityDraft(deps)(w, req)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_source") {
			t.Fatalf("save source=%s: %d %s", bad, w.Code, w.Body.String())
		}
		for name, h := range map[string]http.HandlerFunc{
			"activate": ActivateIdentitySource(deps), "reconcile": ReconcileIdentitySource(deps),
			"disable": DisableIdentitySource(deps), "status": GetIdentityStatus(deps),
			"test": TestIdentityConnection(deps),
		} {
			r := withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/x?source="+bad, strings.NewReader(`{"confirm":true}`)), tenantID, userID)
			rw := httptest.NewRecorder()
			h(rw, r)
			if rw.Code != http.StatusBadRequest {
				t.Fatalf("%s source=%s: %d %s", name, bad, rw.Code, rw.Body.String())
			}
		}
	}

	req := withOrgUserCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft?source=jjd-doesnotexist", strings.NewReader(body)), tenantID, userID)
	w := httptest.NewRecorder()
	SaveIdentityDraft(deps)(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown alias must be 404, got %d %s", w.Code, w.Body.String())
	}
	if runtime.publishCalls+runtime.disableCalls+runtime.statusCalls != 0 {
		t.Fatalf("runtime must not be touched: %+v", runtime)
	}
}
