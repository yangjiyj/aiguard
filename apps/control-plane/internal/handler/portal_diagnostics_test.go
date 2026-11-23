package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/diagnostics"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 门户代调诊断接口：真实 PG（DIAG_TEST_DATABASE_URL，未设置则跳过）+ 真实共享密钥中间件。

const t10pSecret = "t10p-portal-secret"

// 门户中间件会校验是否夹带原生会话令牌；测试里没有 Redis，用恒返回“无此会话”的假实现。
type t10pNoSessions struct{}

func (t10pNoSessions) Create(context.Context, *repository.Session) error { return nil }
func (t10pNoSessions) Delete(context.Context, string) error              { return nil }
func (t10pNoSessions) DeleteByUser(context.Context, string) error        { return nil }
func (t10pNoSessions) Get(context.Context, string) (*repository.Session, error) {
	return nil, nil
}

type t10pEnv struct {
	*t10hEnv
	portal http.Handler
}

func t10pNew(t *testing.T) *t10pEnv {
	t.Helper()
	e := t10hNew(t)
	deps := &Dependencies{UserRepo: repository.NewUserRepository(e.db), SessionRepo: t10pNoSessions{}}
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(PortalIntegrationAPIMiddleware(t10pSecret, deps))
		r.Post("/admin/v1/portal-integration/diagnostics/sessions", CreatePortalDiagnosticsSession(deps, e.eng))
		r.Get("/admin/v1/portal-integration/diagnostics/sessions", ListPortalDiagnosticsSessions(deps, e.eng))
		r.Get("/admin/v1/portal-integration/diagnostics/sessions/{id}", GetPortalDiagnosticsSession(deps, e.eng))
		r.Post("/admin/v1/portal-integration/diagnostics/sessions/{id}/messages", AddPortalDiagnosticsMessage(deps, e.eng))
	})
	return &t10pEnv{t10hEnv: e, portal: r}
}

// call 以门户身份请求；tenant/secret 为空串表示不带该头。
func (e *t10pEnv) call(secret, tenant, method, path string, body any) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	if tenant != "" {
		req.Header.Set("X-JJDGuard-Tenant-Id", tenant)
	}
	rec := httptest.NewRecorder()
	e.portal.ServeHTTP(rec, req)
	return rec
}

func (e *t10pEnv) as(userKey, method, path string, body map[string]any) *httptest.ResponseRecorder {
	uid := e.users[userKey].ID
	if method == http.MethodGet {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		return e.call(t10pSecret, e.tenant, method, path+sep+"user_id="+uid, nil)
	}
	if body == nil {
		body = map[string]any{}
	}
	body["user_id"] = uid
	return e.call(t10pSecret, e.tenant, method, path, body)
}

const t10pBase = "/admin/v1/portal-integration/diagnostics/sessions"

func (e *t10pEnv) createAs(t *testing.T, userKey string, in diagnostics.Input) string {
	t.Helper()
	rec := e.as(userKey, "POST", t10pBase, map[string]any{"input": in})
	if rec.Code != http.StatusOK {
		t.Fatalf("门户创建会话 %s: %d %s", userKey, rec.Code, rec.Body.String())
	}
	var out struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.SessionID == "" {
		t.Fatalf("响应缺少 session_id：%s", rec.Body.String())
	}
	return out.SessionID
}

func (e *t10pEnv) waitDoneAs(t *testing.T, userKey, id string) {
	t.Helper()
	for i := 0; i < 500; i++ {
		rec := e.as(userKey, "GET", t10pBase+"/"+id, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("读取会话: %d %s", rec.Code, rec.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		if m["status"] != "running" {
			e.eng.Wait()
			return
		}
		select {
		case <-context.Background().Done():
		default:
		}
	}
	t.Fatal("等待诊断完成超时")
}

func TestPortalDiagnosticsSecretRequired(t *testing.T) {
	e := t10pNew(t)
	uid := e.users["developer"].ID
	paths := []struct{ method, path string }{
		{"POST", t10pBase},
		{"GET", t10pBase + "?user_id=" + uid},
		{"GET", t10pBase + "/x?user_id=" + uid},
		{"POST", t10pBase + "/x/messages"},
	}
	for _, c := range paths {
		for name, secret := range map[string]string{"缺失密钥": "", "错误密钥": "wrong-secret"} {
			rec := e.call(secret, e.tenant, c.method, c.path, map[string]any{"user_id": uid})
			if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
				t.Errorf("%s %s %s 应 401/403：%d", name, c.method, c.path, rec.Code)
			}
		}
	}
	// 密钥正确但缺租户头 → 400
	if rec := e.call(t10pSecret, "", "GET", t10pBase+"?user_id="+uid, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("缺租户头应 400：%d", rec.Code)
	}
	// 没有任何会话被创建
	var n int
	if err := e.db.QueryRow(context.Background(), `SELECT count(*) FROM diag_sessions WHERE tenant_id = $1`, e.tenant).Scan(&n); err != nil || n != 0 {
		t.Errorf("密钥校验失败时不应产生会话：n=%d err=%v", n, err)
	}
}

func TestPortalDiagnosticsOnlyOwnSessions(t *testing.T) {
	e := t10pNew(t)
	idDev := e.createAs(t, "developer", diagnostics.Input{Kind: "question", Text: "开发的问题"})
	e.waitDoneAs(t, "developer", idDev)
	// 本人可读，响应形状与管理端一致
	rec := e.as("developer", "GET", t10pBase+"/"+idDev, nil)
	var m map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &m) != nil || m["status"] != "done" || m["report"] == nil {
		t.Fatalf("本人读会话: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"output"`) {
		t.Fatalf("工具输出不得下发：%s", rec.Body.String())
	}
	// 他人（同租户员工）读/追问 → 404
	if rec := e.as("viewer", "GET", t10pBase+"/"+idDev, nil); rec.Code != http.StatusNotFound {
		t.Errorf("读他人会话应 404：%d", rec.Code)
	}
	if rec := e.as("viewer", "POST", t10pBase+"/"+idDev+"/messages", map[string]any{"text": "x"}); rec.Code != http.StatusNotFound {
		t.Errorf("追问他人会话应 404：%d", rec.Code)
	}
	// 本人追问
	if rec := e.as("developer", "POST", t10pBase+"/"+idDev+"/messages", map[string]any{"text": "继续查"}); rec.Code != 200 || !strings.Contains(rec.Body.String(), idDev) {
		t.Errorf("本人追问: %d %s", rec.Code, rec.Body.String())
	}
	e.waitDoneAs(t, "developer", idDev)
	// 管理员发起的会话，员工读 → 404；列表只含本人
	idAdmin := e.create(t, "platform_admin", diagnostics.Input{Kind: "health"})
	e.waitDone(t, "platform_admin", idAdmin)
	e.eng.Wait()
	if rec := e.as("developer", "GET", t10pBase+"/"+idAdmin, nil); rec.Code != http.StatusNotFound {
		t.Errorf("读管理员会话应 404：%d", rec.Code)
	}
	rec = e.as("viewer", "GET", t10pBase+"?all=1", nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), idDev) || strings.Contains(rec.Body.String(), idAdmin) {
		t.Errorf("员工列表泄露他人会话（all=1 也无效）：%d %s", rec.Code, rec.Body.String())
	}
	rec = e.as("developer", "GET", t10pBase, nil)
	var list []map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list) != 1 || list[0]["id"] != idDev {
		t.Errorf("本人列表应只有自己的会话：%d %s", rec.Code, rec.Body.String())
	}
	// 跨租户：另一租户的管理员 ID 在本租户下查不到
	rec = e.call(t10pSecret, e.tenant, "GET", t10pBase+"?user_id="+e.users["other_admin"].ID, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("他租户用户应 404：%d", rec.Code)
	}
	// 伪造管理员：门户接口不接受 is_admin / all 之类的提权字段
	rec = e.as("viewer", "POST", t10pBase, map[string]any{"is_admin": true, "input": diagnostics.Input{Kind: "health"}})
	if rec.Code != 200 {
		t.Fatalf("健康检查应可创建：%d %s", rec.Code, rec.Body.String())
	}
	e.eng.Wait()
	// 不提供诊断包与设置
	for _, c := range []struct{ method, path string }{
		{"GET", t10pBase + "/" + idDev + "/bundle"},
		{"GET", "/admin/v1/portal-integration/diagnostics/settings"},
	} {
		if rec := e.call(t10pSecret, e.tenant, c.method, c.path+"?user_id="+e.users["developer"].ID, nil); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s 不应存在：%d", c.path, rec.Code)
		}
	}
}

func TestPortalDiagnosticsRequestLookupOnlyOwn(t *testing.T) {
	e := t10pNew(t)
	ctx := context.Background()
	proj := "t10pproj_" + e.sfx
	keyID := "t10pk_" + e.sfx
	if _, err := e.db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'p')`, proj, e.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Exec(ctx, `INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, name) VALUES ($1,$2,$3,$4,$5,$6,'k')`,
		keyID, e.tenant, proj, e.users["developer"].ID, "h10p"+e.sfx, "t10p"+e.sfx[:4]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = e.db.Exec(c, `DELETE FROM request_logs WHERE tenant_id = $1`, e.tenant)
		_, _ = e.db.Exec(c, `DELETE FROM internal_keys WHERE tenant_id = $1`, e.tenant)
		_, _ = e.db.Exec(c, `DELETE FROM projects WHERE tenant_id = $1`, e.tenant)
	})
	reqID := "req_" + uuidLike(e.sfx)
	if _, err := e.db.Exec(ctx, `INSERT INTO request_logs (id, request_id, tenant_id, user_id, client_id, provider_id, model_id, endpoint_type, request_status, upstream_status_code, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,'chat','provider_error',429, now() - interval '5 minutes')`,
		"id_"+reqID, reqID, e.tenant, e.users["developer"].ID, keyID, "t10hp_"+e.sfx, "t10hm_"+e.sfx); err != nil {
		t.Fatal(err)
	}
	// 用真实工具查请求：本人 found=true，他人 found=false
	e.eng.Tools = diagnostics.NewRegistry(diagnostics.RequestTools()...)
	call := func(userKey string) bool {
		scope := diagnostics.Scope{TenantID: e.tenant, UserID: e.users[userKey].ID}
		st := e.eng.Tools.Call(ctx, e.eng.Q, scope, "get_request", json.RawMessage(`{"request_id":"`+reqID+`"}`))
		return strings.Contains(string(st.Output), `"found":true`)
	}
	if !call("developer") {
		t.Fatal("对照失败：本人应能查到自己的请求")
	}
	if call("viewer") {
		t.Fatal("他人请求编号 found 应为 false")
	}
	// 经门户接口发起 request 诊断：viewer 的会话报告不得包含他人请求信息
	id := e.createAs(t, "viewer", diagnostics.Input{Kind: "question", Text: "请看一下 " + reqID + " 为什么失败"})
	e.waitDoneAs(t, "viewer", id)
	rec := e.as("viewer", "GET", t10pBase+"/"+id, nil)
	if strings.Contains(rec.Body.String(), `"found":true`) || strings.Contains(rec.Body.String(), e.users["developer"].ID) {
		t.Errorf("门户员工经接口查到他人请求：%s", rec.Body.String())
	}
}

func TestPortalDiagnosticsRejectsInactiveOrUnknownUser(t *testing.T) {
	e := t10pNew(t)
	id := e.createAs(t, "developer", diagnostics.Input{Kind: "question", Text: "停用前的问题"})
	e.waitDoneAs(t, "developer", id)
	if _, err := e.db.Exec(context.Background(), `UPDATE users SET status = 'disabled' WHERE id = $1`, e.users["developer"].ID); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		method, path string
		body         map[string]any
	}{
		{"POST", t10pBase, map[string]any{"input": diagnostics.Input{Kind: "health"}}},
		{"GET", t10pBase, nil},
		{"GET", t10pBase + "/" + id, nil},
		{"POST", t10pBase + "/" + id + "/messages", map[string]any{"text": "x"}},
	} {
		rec := e.as("developer", c.method, c.path, c.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("停用员工 %s %s 应 403：%d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	// 不存在的员工 / 缺 user_id
	if rec := e.call(t10pSecret, e.tenant, "GET", t10pBase+"?user_id=nobody_"+e.sfx, nil); rec.Code != http.StatusNotFound {
		t.Errorf("未知员工应 404：%d", rec.Code)
	}
	if rec := e.call(t10pSecret, e.tenant, "GET", t10pBase, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("缺 user_id 应 400：%d", rec.Code)
	}
	// 非 question/health 的输入种类被拒绝（门户不开放按用户/模型等管理员向入口）
	if rec := e.as("viewer", "POST", t10pBase, map[string]any{"input": diagnostics.Input{Kind: "user", Ref: "x"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("kind=user 应 400：%d", rec.Code)
	}
}
