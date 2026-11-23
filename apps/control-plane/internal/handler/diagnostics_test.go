package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/diagnostics"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 诊断接口的 handler 测试：真实 PG（DIAG_TEST_DATABASE_URL，未设置则跳过）+ 假的 L1/L2/L3，
// 通过 chi 路由真实走一遍 HTTP，覆盖身份、404 隔离、409 单飞、501 诊断包、设置校验。

type t10hGate struct {
	mu     sync.Mutex
	active map[string]bool
}

func (g *t10hGate) Busy(context.Context) (bool, string) { return false, "" }
func (g *t10hGate) Acquire(_ context.Context, key string) (func(), bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active[key] {
		return func() {}, false
	}
	g.active[key] = true
	var once sync.Once
	return func() { once.Do(func() { g.mu.Lock(); delete(g.active, key); g.mu.Unlock() }) }, true
}

type t10hEnv struct {
	db      *pgxpool.Pool
	eng     *diagnostics.Engine
	router  http.Handler
	tenant  string
	otherT  string
	users   map[string]*repository.User // 角色键 → 用户
	sfx     string
	release chan struct{}
	mu      sync.Mutex
}

func t10hUser(id, tenant, role string) *repository.User {
	return &repository.User{ID: id, TenantID: tenant, Role: role, Status: "active"}
}

func t10hNew(t *testing.T) *t10hEnv {
	t.Helper()
	dsn := os.Getenv("DIAG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("DIAG_TEST_DATABASE_URL 未设置")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	x, err := diagnostics.NewExec(dsn)
	if err != nil {
		t.Fatal(err)
	}
	sfx := fmt.Sprintf("%08x", mrand.Uint32())
	e := &t10hEnv{db: db, sfx: sfx, tenant: "t10h_" + sfx, otherT: "t10ho_" + sfx, users: map[string]*repository.User{}}
	e.users["platform_admin"] = t10hUser("t10h_pa_"+sfx, e.tenant, "platform_admin")
	e.users["tenant_admin"] = t10hUser("t10h_ta_"+sfx, e.tenant, "tenant_admin")
	e.users["developer"] = t10hUser("t10h_dev_"+sfx, e.tenant, "developer")
	e.users["viewer"] = t10hUser("t10h_view_"+sfx, e.tenant, "viewer")
	e.users["chat_user"] = t10hUser("t10h_chat_"+sfx, e.tenant, "chat_user")
	e.users["other_admin"] = t10hUser("t10h_oa_"+sfx, e.otherT, "platform_admin")

	for _, id := range []string{e.tenant, e.otherT} {
		if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1)`, id); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range e.users {
		if _, err := db.Exec(ctx, `INSERT INTO users (id, tenant_id, username, role, department_assignment_mode) VALUES ($1, $2, $1, $3, 'emergency')`, u.ID, u.TenantID, u.Role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO providers (id, tenant_id, name, provider_type, base_url) VALUES ($1, $2, 'p', 'openai', 'https://x.example.com')`, "t10hp_"+sfx, e.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models (id, provider_id, model_name) VALUES ($1, $2, $3)`, "t10hm_"+sfx, "t10hp_"+sfx, "t10h-model-"+sfx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		for _, s := range []string{
			`DELETE FROM audit_operations WHERE tenant_id = $1 OR user_id IN (SELECT id FROM users WHERE tenant_id = $1)`,
			`DELETE FROM diag_sessions WHERE tenant_id = $1`,
			`DELETE FROM diag_settings WHERE tenant_id = $1`,
			`DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = $1)`,
			`DELETE FROM providers WHERE tenant_id = $1`,
			`DELETE FROM users WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			for _, tid := range []string{e.tenant, e.otherT} {
				if _, err := db.Exec(c, s, tid); err != nil {
					t.Errorf("清理失败: %v", err)
				}
			}
		}
		db.Close()
		x.Close()
	})

	e.eng = &diagnostics.Engine{
		DB: db, Q: x, Gate: &t10hGate{active: map[string]bool{}},
		Tools: diagnostics.NewRegistry(diagnostics.RequestTools()...),
		Now:   time.Now,
		RunL1: func(context.Context, diagnostics.Querier, diagnostics.Scope, diagnostics.Input, *diagnostics.HostView) ([]diagnostics.Finding, int, []diagnostics.Step) {
			return nil, 5, nil
		},
		RunL2: func(ctx context.Context, _ diagnostics.Querier, _ *diagnostics.Registry, _ diagnostics.Scope, _ diagnostics.Input, _ *diagnostics.HostView) (*diagnostics.Report, error) {
			e.mu.Lock()
			rel := e.release
			e.mu.Unlock()
			if rel != nil {
				select {
				case <-rel:
				case <-ctx.Done():
				}
			}
			return &diagnostics.Report{Tier: diagnostics.TierL2, Findings: []diagnostics.Finding{{CheckID: "up_param", Severity: diagnostics.SevError, Level: diagnostics.LevelConfirmed, Title: "上游拒绝了参数"}},
				Steps: []diagnostics.Step{{Tool: "get_request", Summary: "查这条请求", Output: json.RawMessage(`{"found":true}`)}}}, nil
		},
		Pick: func(context.Context, diagnostics.Querier, string, string) (*diagnostics.ModelChoice, error) {
			return nil, nil
		},
	}
	t.Cleanup(e.eng.Wait)
	e.router = e.buildRouter(e.eng)
	return e
}

// buildRouter 用中间件注入当前用户（取自请求头 X-Test-User），挂上 8 个诊断路由。
func (e *t10hEnv) buildRouter(eng *diagnostics.Engine) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if key := req.Header.Get("X-Test-User"); key != "" {
				ctx := context.WithValue(req.Context(), auth.UserKey, e.users[key])
				req = req.WithContext(ctx)
			}
			next.ServeHTTP(w, req)
		})
	})
	r.Post("/admin/v1/diagnostics/sessions", CreateDiagnosticsSession(eng))
	r.Get("/admin/v1/diagnostics/sessions", ListDiagnosticsSessions(eng))
	r.Get("/admin/v1/diagnostics/sessions/{id}", GetDiagnosticsSession(eng))
	r.Post("/admin/v1/diagnostics/sessions/{id}/messages", AddDiagnosticsMessage(eng))
	r.Get("/admin/v1/diagnostics/sessions/{id}/bundle", DownloadDiagnosticsBundle(eng))
	r.Get("/admin/v1/diagnostics/settings", GetDiagnosticsSettings(eng))
	r.Put("/admin/v1/diagnostics/settings", PutDiagnosticsSettings(eng))
	r.Get("/admin/v1/diagnostics/badge", GetDiagnosticsBadge(eng))
	return r
}

func (e *t10hEnv) do(user, method, path string, body any) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func (e *t10hEnv) create(t *testing.T, user string, in diagnostics.Input) string {
	t.Helper()
	rec := e.do(user, "POST", "/admin/v1/diagnostics/sessions", map[string]any{"input": in})
	if rec.Code != http.StatusOK {
		t.Fatalf("创建会话 %s: %d %s", user, rec.Code, rec.Body.String())
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

func (e *t10hEnv) waitDone(t *testing.T, user, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rec := e.do(user, "GET", "/admin/v1/diagnostics/sessions/"+id, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("读取会话: %d %s", rec.Code, rec.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		if m["status"] != "running" {
			return m
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("等待诊断完成超时")
	return nil
}

func t10hErrCode(rec *httptest.ResponseRecorder) string {
	var m struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return m.Error.Code
}

func TestDiagnosticsHandlerFlowAndResponseShape(t *testing.T) {
	e := t10hNew(t)
	id := e.create(t, "platform_admin", diagnostics.Input{Kind: "question", Text: "为什么慢"})
	m := e.waitDone(t, "platform_admin", id)
	if m["status"] != "done" {
		t.Fatalf("status=%v", m["status"])
	}
	// 与前端 DiagnosisSession 一致：status、steps[{tool,summary}]、report
	steps, _ := m["steps"].([]any)
	if len(steps) != 1 {
		t.Fatalf("steps=%v", m["steps"])
	}
	step := steps[0].(map[string]any)
	if step["tool"] != "get_request" || step["summary"] == "" {
		t.Fatalf("step=%v", step)
	}
	rep, _ := m["report"].(map[string]any)
	if rep == nil || rep["tier"] != "L2" || rep["id"] != id {
		t.Fatalf("report=%v", rep)
	}
	raw := t10hJSON(m)
	if strings.Contains(raw, `"output"`) {
		t.Fatalf("工具输出不得下发前端：%s", raw)
	}
	// 追问 → 同一 session_id
	rec := e.do("platform_admin", "POST", "/admin/v1/diagnostics/sessions/"+id+"/messages", map[string]string{"text": "继续查"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), id) {
		t.Fatalf("追问: %d %s", rec.Code, rec.Body.String())
	}
	e.waitDone(t, "platform_admin", id)
	e.eng.Wait()
	// 列表
	rec = e.do("platform_admin", "GET", "/admin/v1/diagnostics/sessions", nil)
	var list []map[string]any
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list) != 1 || list[0]["id"] != id || list[0]["status"] != "done" {
		t.Fatalf("列表: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := list[0]["input"].(map[string]any); !ok || list[0]["created_at"] == nil {
		t.Fatalf("列表项缺少 input 或 created_at：%v", list[0])
	}
	// badge 形状
	rec = e.do("platform_admin", "GET", "/admin/v1/diagnostics/badge", nil)
	var b map[string]bool
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &b) != nil {
		t.Fatalf("badge: %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := b["has_issue"]; !ok {
		t.Fatalf("badge 缺少 has_issue：%s", rec.Body.String())
	}
	e.eng.Wait()
}

func t10hJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestDiagnosticsHandlerIdentity(t *testing.T) {
	e := t10hNew(t)
	// 未登录
	if rec := e.do("", "GET", "/admin/v1/diagnostics/badge", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("未登录应 401：%d", rec.Code)
	}
	// chat_user 一律 403，8 个接口都是
	for _, c := range []struct{ method, path string }{
		{"POST", "/admin/v1/diagnostics/sessions"},
		{"GET", "/admin/v1/diagnostics/sessions"},
		{"GET", "/admin/v1/diagnostics/sessions/x"},
		{"POST", "/admin/v1/diagnostics/sessions/x/messages"},
		{"GET", "/admin/v1/diagnostics/sessions/x/bundle"},
		{"GET", "/admin/v1/diagnostics/settings"},
		{"PUT", "/admin/v1/diagnostics/settings"},
		{"GET", "/admin/v1/diagnostics/badge"},
	} {
		if rec := e.do("chat_user", c.method, c.path, map[string]any{}); rec.Code != http.StatusForbidden {
			t.Errorf("chat_user %s %s 应 403：%d", c.method, c.path, rec.Code)
		}
	}
	// platform_admin 与 tenant_admin 都是管理员：能看他人会话、能下载诊断包路径不 403
	id := e.create(t, "developer", diagnostics.Input{Kind: "question", Text: "我的问题"})
	e.waitDone(t, "developer", id)
	e.eng.Wait()
	for _, role := range []string{"platform_admin", "tenant_admin"} {
		if rec := e.do(role, "GET", "/admin/v1/diagnostics/sessions/"+id, nil); rec.Code != 200 {
			t.Errorf("%s 应能读员工会话：%d", role, rec.Code)
		}
	}
}

func TestDiagnosticsHandlerEmployeeIsolation(t *testing.T) {
	e := t10hNew(t)
	idDev := e.create(t, "developer", diagnostics.Input{Kind: "question", Text: "开发的问题"})
	e.waitDone(t, "developer", idDev)
	e.eng.Wait()
	idView := e.create(t, "viewer", diagnostics.Input{Kind: "question", Text: "观察者的问题"})
	e.waitDone(t, "viewer", idView)
	e.eng.Wait()

	// 员工看他人会话 → 404（不是 403，不泄露存在性）
	rec := e.do("developer", "GET", "/admin/v1/diagnostics/sessions/"+idView, nil)
	if rec.Code != http.StatusNotFound || t10hErrCode(rec) != "not_found" {
		t.Fatalf("员工读他人会话应 404：%d %s", rec.Code, rec.Body.String())
	}
	// 不存在的会话与他人会话响应一致
	rec2 := e.do("developer", "GET", "/admin/v1/diagnostics/sessions/dgs_nonexistent", nil)
	if rec2.Code != rec.Code || rec2.Body.String() != rec.Body.String() {
		t.Fatalf("他人会话与不存在的会话响应应完全一致：\n%d %s\n%d %s", rec.Code, rec.Body.String(), rec2.Code, rec2.Body.String())
	}
	// 追问他人会话 → 404
	if rec := e.do("developer", "POST", "/admin/v1/diagnostics/sessions/"+idView+"/messages", map[string]string{"text": "x"}); rec.Code != http.StatusNotFound {
		t.Fatalf("员工追问他人会话应 404：%d", rec.Code)
	}
	// 员工的 ?all=1 无效，只看到自己的
	rec = e.do("developer", "GET", "/admin/v1/diagnostics/sessions?all=1", nil)
	var list []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0]["id"] != idDev {
		t.Fatalf("员工 all=1 仍只能看到自己的：%s", rec.Body.String())
	}
	// 管理员 all=1 看全租户
	rec = e.do("platform_admin", "GET", "/admin/v1/diagnostics/sessions?all=1", nil)
	list = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 2 {
		t.Fatalf("管理员 all=1 应看到 2 条：%s", rec.Body.String())
	}
	// 别的租户的管理员看不到
	if rec := e.do("other_admin", "GET", "/admin/v1/diagnostics/sessions/"+idDev, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("跨租户应 404：%d", rec.Code)
	}
}

func TestDiagnosticsHandlerBundleAndSettingsAdminOnly(t *testing.T) {
	e := t10hNew(t)
	id := e.create(t, "developer", diagnostics.Input{Kind: "question", Text: "问题"})
	e.waitDone(t, "developer", id)
	e.eng.Wait()

	// 员工下载诊断包 → 403（即使是自己的会话）
	for _, role := range []string{"developer", "viewer"} {
		rec := e.do(role, "GET", "/admin/v1/diagnostics/sessions/"+id+"/bundle", nil)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s 下载诊断包应 403：%d", role, rec.Code)
		}
		put := e.do(role, "PUT", "/admin/v1/diagnostics/settings", map[string]any{"ai_enabled": false, "model_id": nil})
		if put.Code != http.StatusForbidden {
			t.Errorf("%s 改设置应 403：%d", role, put.Code)
		}
	}
	// 员工可读设置
	if rec := e.do("developer", "GET", "/admin/v1/diagnostics/settings", nil); rec.Code != 200 {
		t.Fatalf("员工读设置：%d %s", rec.Code, rec.Body.String())
	}

	// BundleBuilder 为 nil → 501
	saved := diagnostics.BundleBuilder
	t.Cleanup(func() { diagnostics.BundleBuilder = saved })
	diagnostics.BundleBuilder = nil
	rec := e.do("platform_admin", "GET", "/admin/v1/diagnostics/sessions/"+id+"/bundle", nil)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("BundleBuilder 为 nil 应 501：%d %s", rec.Code, rec.Body.String())
	}
	// 有构建函数 → 返回 zip 内容
	var gotID string
	diagnostics.BundleBuilder = func(_ context.Context, s diagnostics.BundleSession) ([]byte, error) {
		gotID = s.ID
		return []byte("PK-fake-zip"), nil
	}
	rec = e.do("platform_admin", "GET", "/admin/v1/diagnostics/sessions/"+id+"/bundle", nil)
	if rec.Code != 200 || rec.Body.String() != "PK-fake-zip" || gotID != id {
		t.Fatalf("管理员下载诊断包：%d %q gotID=%s", rec.Code, rec.Body.String(), gotID)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("Content-Type=%s", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, ".zip") {
		t.Fatalf("Content-Disposition=%s", cd)
	}
	// 不存在的会话 → 404；还在运行 / 没有报告 → 409
	if rec := e.do("platform_admin", "GET", "/admin/v1/diagnostics/sessions/dgs_nope/bundle", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("不存在的会话应 404：%d", rec.Code)
	}
	// 构建失败 → 500 且不泄露内部错误
	diagnostics.BundleBuilder = func(context.Context, diagnostics.BundleSession) ([]byte, error) {
		return nil, fmt.Errorf("内部细节 postgres://u:p@h/db")
	}
	rec = e.do("platform_admin", "GET", "/admin/v1/diagnostics/sessions/"+id+"/bundle", nil)
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "postgres://") {
		t.Fatalf("构建失败应 500 且不泄露细节：%d %s", rec.Code, rec.Body.String())
	}
}

func TestDiagnosticsHandlerSettingsPut(t *testing.T) {
	e := t10hNew(t)
	mid := "t10hm_" + e.sfx
	// model_id 必须属于本租户
	foreign := "别的租户的模型"
	rec := e.do("platform_admin", "PUT", "/admin/v1/diagnostics/settings", map[string]any{"ai_enabled": true, "model_id": foreign})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("模型不属于本租户应 400：%d %s", rec.Code, rec.Body.String())
	}
	rec = e.do("other_admin", "PUT", "/admin/v1/diagnostics/settings", map[string]any{"ai_enabled": true, "model_id": mid})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("别的租户的管理员不能引用本租户模型：%d", rec.Code)
	}
	// 缺 ai_enabled → 400；非法 JSON → 400
	if rec := e.do("platform_admin", "PUT", "/admin/v1/diagnostics/settings", map[string]any{"model_id": mid}); rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 ai_enabled 应 400：%d", rec.Code)
	}
	req := httptest.NewRequest("PUT", "/admin/v1/diagnostics/settings", strings.NewReader("{bad"))
	req.Header.Set("X-Test-User", "platform_admin")
	r2 := httptest.NewRecorder()
	e.router.ServeHTTP(r2, req)
	if r2.Code != http.StatusBadRequest {
		t.Fatalf("非法 JSON 应 400：%d", r2.Code)
	}
	// 合法保存后可读到，形状与前端 DiagnosisSettingsData 一致
	rec = e.do("tenant_admin", "PUT", "/admin/v1/diagnostics/settings", map[string]any{"ai_enabled": false, "model_id": mid})
	if rec.Code != 200 {
		t.Fatalf("保存设置：%d %s", rec.Code, rec.Body.String())
	}
	e.eng.Wait()
	rec = e.do("platform_admin", "GET", "/admin/v1/diagnostics/settings", nil)
	var s map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	for _, k := range []string{"ai_enabled", "model_id", "model_name", "selfcheck", "agent_installed", "agent_last_seen"} {
		if _, ok := s[k]; !ok {
			t.Errorf("设置响应缺少字段 %s：%s", k, rec.Body.String())
		}
	}
	if s["ai_enabled"] != false || s["model_id"] != mid || s["model_name"] != "t10h-model-"+e.sfx {
		t.Fatalf("设置内容不对：%s", rec.Body.String())
	}
}

func TestDiagnosticsHandlerBusyIs409(t *testing.T) {
	e := t10hNew(t)
	e.release = make(chan struct{})
	id := e.create(t, "platform_admin", diagnostics.Input{Kind: "question", Text: "第一个"})
	rec := e.do("developer", "POST", "/admin/v1/diagnostics/sessions", map[string]any{"input": diagnostics.Input{Kind: "question", Text: "第二个"}})
	if rec.Code != http.StatusConflict || t10hErrCode(rec) != "diagnosis_busy" {
		t.Fatalf("应 409 diagnosis_busy：%d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "已有诊断在进行，请稍候") {
		t.Fatalf("提示应为中文：%s", rec.Body.String())
	}
	close(e.release)
	e.waitDone(t, "platform_admin", id)
	e.eng.Wait()
}

func TestDiagnosticsHandlerValidation(t *testing.T) {
	e := t10hNew(t)
	// 空输入 → 400
	rec := e.do("platform_admin", "POST", "/admin/v1/diagnostics/sessions", map[string]any{"input": map[string]any{"kind": "question", "text": "  "}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("空输入应 400：%d %s", rec.Code, rec.Body.String())
	}
	// 体检不需要文本
	id := e.create(t, "platform_admin", diagnostics.Input{Kind: "health"})
	e.waitDone(t, "platform_admin", id)
	e.eng.Wait()
	// 超大请求体 → 400
	big := strings.Repeat("a", 200<<10)
	req := httptest.NewRequest("POST", "/admin/v1/diagnostics/sessions", strings.NewReader(`{"input":{"kind":"question","text":"`+big+`"}}`))
	req.Header.Set("X-Test-User", "platform_admin")
	r2 := httptest.NewRecorder()
	e.router.ServeHTTP(r2, req)
	if r2.Code != http.StatusBadRequest {
		t.Fatalf("超大请求体应 400：%d", r2.Code)
	}
}

func TestDiagnosticsHandlerUnavailableIs503(t *testing.T) {
	e := t10hNew(t)
	e.router = e.buildRouter(nil) // 引擎初始化失败：接口返回 503
	for _, c := range []struct{ method, path string }{
		{"POST", "/admin/v1/diagnostics/sessions"},
		{"GET", "/admin/v1/diagnostics/sessions"},
		{"GET", "/admin/v1/diagnostics/sessions/x"},
		{"POST", "/admin/v1/diagnostics/sessions/x/messages"},
		{"GET", "/admin/v1/diagnostics/settings"},
		{"PUT", "/admin/v1/diagnostics/settings"},
		{"GET", "/admin/v1/diagnostics/badge"},
	} {
		rec := e.do("platform_admin", c.method, c.path, map[string]any{"input": map[string]any{"kind": "health"}, "ai_enabled": true, "text": "x"})
		if rec.Code != http.StatusServiceUnavailable || t10hErrCode(rec) != "diagnostics_unavailable" {
			t.Errorf("%s %s 应 503：%d %s", c.method, c.path, rec.Code, rec.Body.String())
			continue
		}
		if !strings.Contains(rec.Body.String(), "诊断功能暂不可用") {
			t.Errorf("503 提示应为中文：%s", rec.Body.String())
		}
	}
	// 员工访问 bundle 先判权限（403），不因引擎不可用泄露信息
	if rec := e.do("developer", "GET", "/admin/v1/diagnostics/sessions/x/bundle", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("员工访问 bundle 应 403：%d", rec.Code)
	}
}
