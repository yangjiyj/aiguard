package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func saveDraftBody(t *testing.T, deps *Dependencies, tenantID, userID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := withOrgUserCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft", bytes.NewReader([]byte(body))), tenantID, userID)
	w := httptest.NewRecorder()
	SaveIdentityDraft(deps)(w, req)
	return w
}

const baseDraft = `"display_name":"企业 IdP","issuer_url":"https://idp.example.com","client_id":"c","client_secret":"s","scopes":"openid profile email"`

func TestSaveDraftPersistsProfileOptionsAndKeepsThemWhenOmitted(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildIdentityDeps(pool)

	w := saveDraftBody(t, deps, tenantID, userID, `{`+baseDraft+`,"username_claim":"email","signature_mode":"none","skip_profile_review":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d %s", w.Code, w.Body.String())
	}
	var dto identitySourceDTO
	_ = json.Unmarshal(w.Body.Bytes(), &dto)
	if dto.SignatureMode != "none" || !dto.SkipProfileReview || dto.UsernameClaim != "email" {
		t.Fatalf("dto=%+v", dto)
	}
	// 省略两项（旧客户端/只改别的字段）：保持已存值，不被悄悄改回默认。
	w = saveDraftBody(t, deps, tenantID, userID, `{`+baseDraft+`,"username_claim":"email"}`)
	_ = json.Unmarshal(w.Body.Bytes(), &dto)
	if w.Code != http.StatusOK || dto.SignatureMode != "none" || !dto.SkipProfileReview {
		t.Fatalf("省略时应保持原值: %d %+v", w.Code, dto)
	}
	// 显式关闭。
	w = saveDraftBody(t, deps, tenantID, userID, `{`+baseDraft+`,"signature_mode":"jwks","skip_profile_review":false}`)
	_ = json.Unmarshal(w.Body.Bytes(), &dto)
	if dto.SignatureMode != "jwks" || dto.SkipProfileReview {
		t.Fatalf("dto=%+v", dto)
	}
}

func TestSaveDraftDefaultsAndValidation(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildIdentityDeps(pool)
	w := saveDraftBody(t, deps, tenantID, userID, `{`+baseDraft+`}`)
	var dto identitySourceDTO
	_ = json.Unmarshal(w.Body.Bytes(), &dto)
	if dto.SignatureMode != "jwks" || dto.SkipProfileReview || dto.UsernameClaim != "preferred_username" {
		t.Fatalf("默认值不对: %+v", dto)
	}
	for name, extra := range map[string]string{
		"非法验签方式":   `"signature_mode":"hmac"`,
		"非法用户名取值":  `"username_claim":"a b"`,
		"用户名取值带注入": `"username_claim":"x;drop"`,
	} {
		w := saveDraftBody(t, deps, tenantID, userID, `{`+baseDraft+`,`+extra+`}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: code=%d %s", name, w.Code, w.Body.String())
		}
	}
	// 合法的自定义 claim token 仍允许。
	if w := saveDraftBody(t, deps, tenantID, userID, `{`+baseDraft+`,"username_claim":"login_name"}`); w.Code != http.StatusOK {
		t.Fatalf("code=%d %s", w.Code, w.Body.String())
	}
}

func setOptions(t *testing.T, deps *Dependencies, src *repository.IdentitySource, mode string, skip bool, username string) {
	t.Helper()
	cur, err := deps.IdentitySourceRepo.GetByID(context.Background(), src.TenantID, src.ID)
	if err != nil || cur == nil {
		t.Fatal(err)
	}
	_, err = deps.IdentitySourceRepo.AdoptRuntimeSettings(context.Background(), repository.AdoptRuntimeInput{
		TenantID: src.TenantID, SourceID: src.ID, Version: cur.Version, SignatureMode: mode, SkipProfileReview: skip,
		UsernameClaim: username, ConfigDigest: src.ConfigDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReconcileUsesStoredOptionsNeverDefaults(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	active := seedActiveIdentitySource(t, deps, tenantID, userID)
	setOptions(t, deps, active, "none", true, "email")

	req := withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/reconcile", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	ReconcileIdentitySource(deps)(rr, req)
	if rr.Code != http.StatusOK || runtime.publishCalls != 1 {
		t.Fatalf("code=%d calls=%d %s", rr.Code, runtime.publishCalls, rr.Body.String())
	}
	d := runtime.desired
	if d.SignatureMode != "none" || !d.SkipProfileReview {
		t.Fatalf("修复必须读取库里已存选项: %+v", d)
	}
	var username string
	for _, m := range d.ClaimMappings {
		if m.UserAttribute == "username" {
			username = m.Claim
		}
	}
	if username != "email" {
		t.Fatalf("用户名映射应为 email，实际 %q", username)
	}
}

func TestActivateDefaultOptionsProduceDefaultDesired(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	seedTestedIdentitySource(t, deps, tenantID)
	req := withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/activate", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	ActivateIdentitySource(deps)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d %s", rr.Code, rr.Body.String())
	}
	if runtime.desired.SignatureMode != "jwks" || runtime.desired.SkipProfileReview {
		t.Fatalf("默认选项不对: %+v", runtime.desired)
	}
	// 与不带新字段时的摘要一致（存量不漂移）。
	legacy := runtime.desired
	legacy.SignatureMode = ""
	legacyDigest, _ := identityruntime.ComputeDesiredDigest(legacy)
	if legacyDigest != runtime.desired.Digest {
		t.Fatal("jwks 与空串必须得到相同摘要")
	}
}

func TestActivateRejectsNoneWithHTTPTokenEndpointBeforePublish(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	deps.OIDCTester = &fakeIdentityTester{discovery: &identity.DiscoveryDocument{
		Issuer: "http://10.0.0.5", AuthorizationEndpoint: "http://10.0.0.5/auth",
		TokenEndpoint: "http://10.0.0.5/token", JWKSURI: "http://10.0.0.5/jwks",
	}}
	tested := seedTestedIdentitySource(t, deps, tenantID)
	// 经 DB 直接改为 none（模拟草稿阶段已选）。
	if _, err := pool.Exec(context.Background(), `UPDATE identity_sources SET signature_mode='none' WHERE id=$1`, tested.ID); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "10.0.0.0/8")
	req := withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/activate", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	ActivateIdentitySource(deps)(rr, req)
	if rr.Code == http.StatusOK || runtime.publishCalls != 0 {
		t.Fatalf("none+http 必须在发布前被拒绝: code=%d calls=%d", rr.Code, runtime.publishCalls)
	}
}

func adoptReq(t *testing.T, deps *Dependencies, tenantID, userID, sourceID string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"source_id": sourceID})
	req := withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/adopt-runtime", bytes.NewReader(body)), tenantID, userID)
	rr := httptest.NewRecorder()
	AdoptIdentityRuntime(deps)(rr, req)
	return rr
}

func TestAdoptRuntimeWritesDatabaseOnlyAndReportsDrift(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{
		observed: identityruntime.ObservedSettings{Exists: true, SignatureMode: "none", UsernameClaim: "email", SkipProfileReview: true},
		status:   identityruntime.RuntimeStatus{Exists: true, Enabled: true, Drifted: true, Digest: "sha256:old"},
	}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	active := seedActiveIdentitySource(t, deps, tenantID, userID)

	rr := adoptReq(t, deps, tenantID, userID, active.ID)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d %s", rr.Code, rr.Body.String())
	}
	if runtime.observeCalls != 1 || runtime.publishCalls != 0 || runtime.disableCalls != 0 || runtime.restoreCalls != 0 {
		t.Fatalf("采纳只能读运行态: observe=%d publish=%d disable=%d restore=%d",
			runtime.observeCalls, runtime.publishCalls, runtime.disableCalls, runtime.restoreCalls)
	}
	got, _ := deps.IdentitySourceRepo.GetByID(context.Background(), tenantID, active.ID)
	if got.SignatureMode != "none" || got.UsernameClaim != "email" || !got.SkipProfileReview ||
		got.ConfigDigest == handlerTestDigest || !strings.HasPrefix(got.ConfigDigest, "sha256:") {
		t.Fatalf("库未更新: %+v", got)
	}
	if got.Version != active.Version || got.PublishStatus != "drifted" {
		t.Fatalf("version/publish_status: %+v", got)
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["drift"] != true || !strings.Contains(rr.Body.String(), "按当前配置修复") {
		t.Fatalf("应提示后续修复: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "source-secret") {
		t.Fatal("响应泄露密钥")
	}
}

func TestAdoptRuntimeBecomesActiveWhenRuntimeAlreadyMatches(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{
		observed: identityruntime.ObservedSettings{Exists: true, SignatureMode: "none"},
		status:   identityruntime.RuntimeStatus{Exists: true, Enabled: true},
	}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	active := seedActiveIdentitySource(t, deps, tenantID, userID)
	rr := adoptReq(t, deps, tenantID, userID, active.ID)
	got, _ := deps.IdentitySourceRepo.GetByID(context.Background(), tenantID, active.ID)
	if rr.Code != http.StatusOK || got.PublishStatus != "active" {
		t.Fatalf("code=%d status=%s %s", rr.Code, got.PublishStatus, rr.Body.String())
	}
	// 无法反推用户名取值：原值保留并在 unresolved 提示。
	if got.UsernameClaim != "preferred_username" || !strings.Contains(rr.Body.String(), "username_claim") {
		t.Fatalf("username=%s body=%s", got.UsernameClaim, rr.Body.String())
	}
}

func TestAdoptRuntimeSameAliasRules(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{observed: identityruntime.ObservedSettings{Exists: true, SignatureMode: "none"}}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	// 先放一条同 alias 的已停用旧记录，再放现役记录。
	old := seedTestedIdentitySource(t, deps, tenantID)
	if _, err := pool.Exec(context.Background(), `UPDATE identity_sources SET status='disabled', publish_status='disabled' WHERE id=$1`, old.ID); err != nil {
		t.Fatal(err)
	}
	active := seedActiveIdentitySource(t, deps, tenantID, userID)

	// 采纳现役：成功，旧记录被列出但不被改动。
	rr := adoptReq(t, deps, tenantID, userID, active.ID)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), old.ID) {
		t.Fatalf("code=%d %s", rr.Code, rr.Body.String())
	}
	oldAfter, _ := deps.IdentitySourceRepo.GetByID(context.Background(), tenantID, old.ID)
	if oldAfter.SignatureMode != "jwks" || oldAfter.Status != "disabled" || oldAfter.Version != old.Version {
		t.Fatalf("同 alias 旧记录被改动: %+v", oldAfter)
	}
	// 采纳旧记录：冲突。
	calls := runtime.observeCalls
	rr = adoptReq(t, deps, tenantID, userID, old.ID)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "adopt_target_not_active") {
		t.Fatalf("code=%d %s", rr.Code, rr.Body.String())
	}
	_ = calls
}

func TestAdoptRuntimeAuthorizationAndTenantScope(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{observed: identityruntime.ObservedSettings{Exists: true, SignatureMode: "none"}}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	active := seedActiveIdentitySource(t, deps, tenantID, userID)

	body, _ := json.Marshal(map[string]string{"source_id": active.ID})
	mk := func(role, tenant string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/adopt-runtime", bytes.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
			ID: "u1", TenantID: tenant, Role: role, Status: "active",
		}))
		rr := httptest.NewRecorder()
		AdoptIdentityRuntime(deps)(rr, req)
		return rr
	}
	if rr := mk("developer", tenantID); rr.Code != http.StatusForbidden {
		t.Fatalf("developer code=%d", rr.Code)
	}
	if rr := mk("tenant_owner", "other-tenant"); rr.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant code=%d", rr.Code)
	}
	if runtime.observeCalls != 0 {
		t.Fatal("未授权/跨租户不得读取运行态")
	}
	// 缺 source_id。
	req := withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/adopt-runtime", bytes.NewReader([]byte(`{}`))), tenantID, userID)
	rr := httptest.NewRecorder()
	AdoptIdentityRuntime(deps)(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing source_id code=%d", rr.Code)
	}
}

func TestAdoptRuntimeRuntimeMissingAndUnavailable(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{observed: identityruntime.ObservedSettings{}}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	active := seedActiveIdentitySource(t, deps, tenantID, userID)
	if rr := adoptReq(t, deps, tenantID, userID, active.ID); rr.Code != http.StatusNotFound {
		t.Fatalf("运行态无该身份源应 404: %d %s", rr.Code, rr.Body.String())
	}
	runtime.observeErr = identityruntime.ErrRuntimeUnavailable
	if rr := adoptReq(t, deps, tenantID, userID, active.ID); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("不可用应 503: %d", rr.Code)
	}
}

type hintTester struct{ fakeIdentityTester }

func (h *hintTester) TestConnection(_ context.Context, _ identity.TestConfig) *identity.TestConnectionResult {
	return &identity.TestConnectionResult{Success: true, Hints: []string{"该 IdP 使用对称签名"}}
}

func TestTestConnectionReturnsNonBlockingHints(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildRuntimeIdentityDeps(t, pool, &fakeIdentityRuntime{})
	deps.OIDCTester = &hintTester{}
	if w := saveDraftBody(t, deps, tenantID, userID, `{`+baseDraft+`}`); w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	req := withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/test", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	TestIdentityConnection(deps)(rr, req)
	var resp struct {
		Success bool     `json:"success"`
		Hints   []string `json:"hints"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if rr.Code != http.StatusOK || !resp.Success || len(resp.Hints) != 1 {
		t.Fatalf("code=%d %s", rr.Code, rr.Body.String())
	}
}

func TestActivateReportsManageRealmRequiredClearly(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{publishErr: identityruntime.ErrManageRealmRequired}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	tested := seedTestedIdentitySource(t, deps, tenantID)
	if _, err := pool.Exec(context.Background(), `UPDATE identity_sources SET skip_profile_review=true WHERE id=$1`, tested.ID); err != nil {
		t.Fatal(err)
	}
	req := withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/activate", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	ActivateIdentitySource(deps)(rr, req)
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != http.StatusBadGateway || body.Error.Code != "identity_manage_realm_required" ||
		!strings.Contains(body.Error.Message, "manage-realm") || !strings.Contains(body.Error.Message, "升级文档") {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
	if !runtime.desired.SkipProfileReview {
		t.Fatal("skip 选项应传给运行态")
	}
	// 失败被记录为稳定错误码，而不是笼统的 identity_publish_failed。
	got, _ := deps.IdentitySourceRepo.GetByID(context.Background(), tenantID, tested.ID)
	if got.LastPublishError != "identity_manage_realm_required" {
		t.Fatalf("last_publish_error=%q", got.LastPublishError)
	}
}

func TestAdoptRuntimeConcurrentModificationReturnsConflict(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{observed: identityruntime.ObservedSettings{Exists: true, SignatureMode: "none", UsernameClaim: "email"}}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	active := seedActiveIdentitySource(t, deps, tenantID, userID)
	// 读取源之后、写库之前被他人修改（读 Keycloak 期间）。
	runtime.onObserve = func() {
		if _, err := pool.Exec(context.Background(), `UPDATE identity_sources SET version=version+1 WHERE id=$1`, active.ID); err != nil {
			t.Error(err)
		}
	}
	rr := adoptReq(t, deps, tenantID, userID, active.ID)
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != http.StatusConflict || body.Error.Code != "identity_publish_conflict" ||
		body.Error.Message != "配置已被他人修改，请刷新后重试" {
		t.Fatalf("code=%d %s", rr.Code, rr.Body.String())
	}
	got, _ := deps.IdentitySourceRepo.GetByID(context.Background(), tenantID, active.ID)
	if got.SignatureMode != "jwks" || got.ConfigDigest != active.ConfigDigest {
		t.Fatalf("冲突时不得写库: %+v", got)
	}
}

func TestAdoptRuntimeRejectsEditingStatusBeforeReadingRuntime(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{observed: identityruntime.ObservedSettings{Exists: true, SignatureMode: "none"}}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	tested := seedTestedIdentitySource(t, deps, tenantID)
	for _, status := range []string{"tested", "draft"} {
		if _, err := pool.Exec(context.Background(), `UPDATE identity_sources SET status=$2 WHERE id=$1`, tested.ID, status); err != nil {
			t.Fatal(err)
		}
		rr := adoptReq(t, deps, tenantID, userID, tested.ID)
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		if rr.Code != http.StatusConflict || body.Error.Code != "adopt_target_not_adoptable" ||
			body.Error.Message != "仅启用中或已停用的身份源可采纳（当前处于编辑中，请先发布或放弃草稿）" {
			t.Fatalf("status=%s code=%d %s", status, rr.Code, rr.Body.String())
		}
	}
	if runtime.observeCalls != 0 {
		t.Fatal("状态不允许时必须在读取运行态之前拦截")
	}
}

func TestSaveDraftRejectsNoneWithHTTPIssuer(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildIdentityDeps(pool)
	httpDraft := `"display_name":"企业 IdP","issuer_url":"http://10.0.0.5/oidc","client_id":"c","client_secret":"s","scopes":"openid"`
	w := saveDraftBody(t, deps, tenantID, userID, `{`+httpDraft+`,"signature_mode":"none"}`)
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusBadRequest || body.Error.Code != "signature_none_requires_https" ||
		!strings.Contains(body.Error.Message, "选择「不校验签名」时，token 端点必须是 https") {
		t.Fatalf("code=%d %s", w.Code, w.Body.String())
	}
	// 默认验签方式不受影响（私网 http 仍可保存草稿，沿用既有机制）。
	if w := saveDraftBody(t, deps, tenantID, userID, `{`+httpDraft+`}`); w.Code != http.StatusOK {
		t.Fatalf("jwks 模式 http 草稿应可保存: %d %s", w.Code, w.Body.String())
	}
	// 草稿已是 none 时，省略 signature_mode 的保存同样拦截（用合并后的值判断）。
	w = saveDraftBody(t, deps, tenantID, userID, `{`+strings.Replace(httpDraft, "http://10.0.0.5", "https://10.0.0.5", 1)+`,"signature_mode":"none"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("https + none 应可保存: %d %s", w.Code, w.Body.String())
	}
	w = saveDraftBody(t, deps, tenantID, userID, `{`+httpDraft+`}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("已存 none 且改为 http 的保存应被拦截: %d %s", w.Code, w.Body.String())
	}
}
