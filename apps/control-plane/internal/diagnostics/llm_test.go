package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type t8Capture struct {
	path, rawQuery string
	header         http.Header
	body           map[string]any
}

func t8Server(t *testing.T, status int, resp string) (*httptest.Server, *t8Capture) {
	t.Helper()
	c := &t8Capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.path, c.rawQuery, c.header = r.URL.Path, r.URL.RawQuery, r.Header.Clone()
		_ = json.NewDecoder(r.Body).Decode(&c.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

const t8ToolResp = `{"choices":[{"message":{"content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"get_request","arguments":"{\"request_id\":\"req_x\"}"}}]}}],"usage":{"prompt_tokens":11,"completion_tokens":7}}`

var t8Specs = []ToolSpec{{Name: "get_request", Description: "d", Schema: json.RawMessage(`{"type":"object"}`)}}

func TestT8OpenAIChat(t *testing.T) {
	srv, c := t8Server(t, 200, t8ToolResp)
	l := NewHTTPLLM(srv.URL, "sk-test", "bearer", "openai", "gpt-x", srv.Client())
	r, err := l.Chat(context.Background(), []Msg{{Role: "user", Content: "hi"},
		{Role: "assistant", ToolCalls: []ToolCall{{ID: "a", Name: "get_request", Args: json.RawMessage(`{"request_id":"r"}`)}}},
		{Role: "tool", ToolCallID: "a", Name: "get_request", Content: "{}"}}, t8Specs)
	if err != nil {
		t.Fatal(err)
	}
	if c.path != "/v1/chat/completions" || c.header.Get("Authorization") != "Bearer sk-test" || c.header.Get("api-key") != "" {
		t.Fatalf("路径/头不对: %s %v", c.path, c.header)
	}
	if c.body["max_tokens"] == nil || c.body["max_completion_tokens"] != nil || c.body["model"] != "gpt-x" {
		t.Fatalf("max 参数不对: %v", c.body)
	}
	// 请求侧 arguments 必须是字符串
	msgs := c.body["messages"].([]any)
	tc := msgs[1].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)
	if s, ok := tc["arguments"].(string); !ok || s != `{"request_id":"r"}` {
		t.Fatalf("arguments 应为字符串: %v", tc["arguments"])
	}
	if tl := c.body["tools"].([]any)[0].(map[string]any); tl["type"] != "function" {
		t.Fatalf("tools 格式: %v", tl)
	}
	if len(r.ToolCalls) != 1 || r.ToolCalls[0].Name != "get_request" || string(r.ToolCalls[0].Args) != `{"request_id":"req_x"}` ||
		r.PromptTokens != 11 || r.CompletionTokens != 7 || r.ToolCalls[0].ID != "c1" {
		t.Fatalf("解析结果不对: %+v", r)
	}
}

func TestT8AzureByProviderType(t *testing.T) {
	srv, c := t8Server(t, 200, `{"choices":[{"message":{"content":"ok"}}]}`)
	l := NewHTTPLLM(srv.URL, "az-key", "api-key", "azure", "dep1", srv.Client())
	r, err := l.Chat(context.Background(), []Msg{{Role: "user", Content: "hi"}}, nil)
	if err != nil || r.Content != "ok" {
		t.Fatalf("%v %+v", err, r)
	}
	if c.header.Get("api-key") != "az-key" || c.header.Get("Authorization") != "" {
		t.Fatalf("头不对: %v", c.header)
	}
	if c.body["max_completion_tokens"] == nil || c.body["max_tokens"] != nil {
		t.Fatalf("max 参数不对: %v", c.body)
	}
}

func TestT8AzureURLByHost(t *testing.T) {
	for _, base := range []string{"https://foo.openai.azure.com", "https://foo.openai.azure.com/", "https://foo.openai.azure.com/openai/v1", "https://foo.cognitiveservices.azure.com"} {
		got := t8ChatURL(base, "my dep")
		want := "/openai/deployments/my%20dep/chat/completions?api-version=2024-10-21"
		if !strings.HasSuffix(got, want) || strings.Count(got, "/openai/") != 1 {
			t.Errorf("%s -> %s", base, got)
		}
		if !t8IsAzure(base, "custom") {
			t.Errorf("%s 应识别为 Azure", base)
		}
	}
	if t8IsAzure("https://api.openai.com/v1", "openai") {
		t.Error("openai 不应是 Azure")
	}
	if got := t8ChatURL("https://x.example.com/v1", "m"); got != "https://x.example.com/v1/chat/completions" {
		t.Error(got)
	}
}

func TestT8ErrNoTools(t *testing.T) {
	srv, _ := t8Server(t, 400, `{"error":{"message":"This model does not support tools / function calling"}}`)
	l := NewHTTPLLM(srv.URL, "k", "bearer", "openai", "m", srv.Client())
	if _, err := l.Chat(context.Background(), []Msg{{Role: "user", Content: "x"}}, t8Specs); !errors.Is(err, ErrNoTools) {
		t.Fatalf("期望 ErrNoTools, got %v", err)
	}
	// 无关的 400 不算
	srv2, _ := t8Server(t, 400, `{"error":{"message":"invalid model name"}}`)
	l2 := NewHTTPLLM(srv2.URL, "k", "bearer", "openai", "m", srv2.Client())
	if _, err := l2.Chat(context.Background(), []Msg{{Role: "user", Content: "x"}}, t8Specs); err == nil || errors.Is(err, ErrNoTools) {
		t.Fatalf("不应是 ErrNoTools: %v", err)
	}
	// 没传 tools 时不判 ErrNoTools
	if _, err := l.Chat(context.Background(), []Msg{{Role: "user", Content: "x"}}, nil); errors.Is(err, ErrNoTools) {
		t.Fatal("无 tools 时不应返回 ErrNoTools")
	}
}

func TestT8InvalidArgsKeptRaw(t *testing.T) {
	srv, _ := t8Server(t, 200, `{"choices":[{"message":{"tool_calls":[{"id":"","function":{"name":"get_request","arguments":"{not json"}}]}}]}`)
	l := NewHTTPLLM(srv.URL, "k", "bearer", "openai", "m", srv.Client())
	r, err := l.Chat(context.Background(), []Msg{{Role: "user", Content: "x"}}, t8Specs)
	if err != nil || len(r.ToolCalls) != 1 || string(r.ToolCalls[0].Args) != "{not json" || r.ToolCalls[0].ID == "" {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestT8NoRedirect(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	l := NewHTTPLLM(srv.URL, "k", "bearer", "openai", "m", nil)
	if _, err := l.Chat(context.Background(), []Msg{{Role: "user", Content: "x"}}, nil); err == nil || hit {
		t.Fatalf("不应跟随重定向 err=%v hit=%v", err, hit)
	}
}

// ---- PickModel（PG 夹具）----

func TestT8ListUsableModels(t *testing.T) {
	dsn := t8Dsn(t)
	ctx := context.Background()
	x, err := NewExec(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	f := t8NewFixture(t, dsn)
	f.seedModel(t, "good", "openai", "active", "active", 0, 0)
	f.seedModel(t, "azure1", "azure", "active", "active", 0, 0)
	f.seedModel(t, "anth", "anthropic", "active", "active", 0, 0)
	f.seedModel(t, "off", "openai", "disabled", "active", 0, 0)
	f.seedModel(t, "poff", "openai", "active", "disabled", 0, 0)
	f.seedModel(t, "image1", "openai", "active", "active", 0, 0)
	got, err := ListUsableModels(ctx, x, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, m := range got {
		names[m.Name] = true
	}
	if len(got) != 2 || !names["name-good"] || !names["name-azure1"] {
		t.Fatalf("只应列出启用且兼容的非图像模型：%+v", got)
	}
	if other, _ := ListUsableModels(ctx, x, f.tenant+"_other"); len(other) != 0 {
		t.Fatalf("跨租户不应列出：%+v", other)
	}
}

func TestT8PickModel(t *testing.T) {
	dsn := t8Dsn(t)
	ctx := context.Background()
	x, err := NewExec(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	f := t8NewFixture(t, dsn)

	// 无请求、无首选 -> nil
	if c, err := PickModel(ctx, x, f.tenant, ""); err != nil || c != nil {
		t.Fatalf("期望 nil,nil: %v %v", c, err)
	}
	// good: 6 次 5 成功；bad: 6 次 2 成功；few: 4 次全成功；anth: anthropic 渠道全成功
	f.seedModel(t, "good", "openai", "active", "active", 6, 5)
	f.seedModel(t, "bad", "openai", "active", "active", 6, 2)
	f.seedModel(t, "few", "openai", "active", "active", 4, 4)
	f.seedModel(t, "anth", "anthropic", "active", "active", 10, 10)
	f.seedModel(t, "off", "openai", "disabled", "active", 10, 10)
	f.seedModel(t, "poff", "openai", "active", "disabled", 10, 10)
	c, err := PickModel(ctx, x, f.tenant, "")
	if err != nil || c == nil || c.ModelID != f.id("good") {
		t.Fatalf("应选 good: %+v %v", c, err)
	}
	if c.ProviderType != "openai" || c.BaseURL == "" || c.Deployment == "" {
		t.Fatalf("字段缺失: %+v", c)
	}
	// 首选可用 -> 用首选
	c, _ = PickModel(ctx, x, f.tenant, f.id("bad"))
	if c == nil || c.ModelID != f.id("bad") {
		t.Fatalf("应选首选 bad: %+v", c)
	}
	// 首选不可用 -> 回落自动选
	c, _ = PickModel(ctx, x, f.tenant, f.id("off"))
	if c == nil || c.ModelID != f.id("good") {
		t.Fatalf("首选不可用应回落: %+v", c)
	}
	// 首选属于 anthropic（非兼容）-> 回落
	c, _ = PickModel(ctx, x, f.tenant, f.id("anth"))
	if c == nil || c.ModelID != f.id("good") {
		t.Fatalf("非兼容首选应回落: %+v", c)
	}
	// 近 1 小时流量不足时放宽到 24 小时：old 在 2~3 小时前有 3 次成功调用
	g := t8NewFixture(t, dsn)
	g.seedModel(t, "old", "openai", "active", "active", 3, 3)
	t8ExecSQL(t, ctx, g.conn, `UPDATE request_logs SET created_at = now() - interval '2 hours' WHERE tenant_id = $1`, g.tenant)
	if c, err := PickModel(ctx, x, g.tenant, ""); err != nil || c == nil || c.ModelID != g.id("old") {
		t.Fatalf("近 1 小时无流量应放宽窗口选到 old: %+v %v", c, err)
	}
	// 其他租户看不到
	if c, _ := PickModel(ctx, x, f.tenant+"_other", f.id("good")); c != nil {
		t.Fatalf("跨租户不应命中: %+v", c)
	}
}

type t8Fix struct {
	tenant, sfx string
	conn        *pgx.Conn
}

func t8Dsn(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DIAG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("DIAG_TEST_DATABASE_URL 未设置")
	}
	return dsn
}

func t8ExecSQL(t *testing.T, ctx context.Context, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("夹具 SQL 失败: %v\n%s", err, sql)
	}
}

func (f *t8Fix) id(n string) string { return "t8m_" + n + "_" + f.sfx }

func t8NewFixture(t *testing.T, dsn string) *t8Fix {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	sfx := fmt.Sprintf("%08x", rand.Uint32())
	f := &t8Fix{tenant: "t8ten_" + sfx, sfx: sfx, conn: conn}
	t.Cleanup(func() {
		c := context.Background()
		for _, s := range []string{
			`DELETE FROM request_logs WHERE tenant_id = $1`,
			`DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = $1)`,
			`DELETE FROM providers WHERE tenant_id = $1`,
			`DELETE FROM users WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			if _, err := conn.Exec(c, s, f.tenant); err != nil {
				t.Errorf("清理失败: %v", err)
			}
		}
		_ = conn.Close(c)
	})
	t8ExecSQL(t, ctx, conn, `INSERT INTO tenants (id, name) VALUES ($1, $1)`, f.tenant)
	t8ExecSQL(t, ctx, conn, `INSERT INTO users (id, tenant_id, username, department_assignment_mode) VALUES ($1, $2, $1, 'emergency')`, "t8u_"+sfx, f.tenant)
	return f
}

func (f *t8Fix) seedModel(t *testing.T, name, ptype, mstatus, pstatus string, total, ok int) {
	t.Helper()
	ctx := context.Background()
	conn := f.conn
	pid := "t8p_" + name + "_" + f.sfx
	t8ExecSQL(t, ctx, conn, `INSERT INTO providers (id, tenant_id, name, provider_type, base_url, auth_mode, status) VALUES ($1,$2,$1,$3,'https://up.example.com/v1','bearer',$4)`, pid, f.tenant, ptype, pstatus)
	t8ExecSQL(t, ctx, conn, `INSERT INTO models (id, provider_id, model_name, status) VALUES ($1,$2,$3,$4)`, f.id(name), pid, "name-"+name, mstatus)
	for i := 0; i < total; i++ {
		st := "provider_error"
		if i < ok {
			st = "success"
		}
		rid := fmt.Sprintf("t8r_%s_%d_%s", name, i, f.sfx)
		t8ExecSQL(t, ctx, conn, `INSERT INTO request_logs (id, request_id, tenant_id, user_id, provider_id, model_id, endpoint_type, request_status, created_at)
VALUES ($1,$1,$2,$3,$4,$5,'chat',$6, now() - make_interval(mins => $7))`, "id_"+rid, f.tenant, "t8u_"+f.sfx, pid, f.id(name), st, 5+i)
	}
}

var _ = time.Second
