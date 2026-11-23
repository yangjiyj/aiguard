package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type t3Fix struct {
	x        *Exec
	conn     *pgx.Conn
	tenant   string
	adminU   string
	staffA   string
	staffB   string
	provider string
	model    string
	keyA     string
	keyB     string
	prefixA  string
}

func t3Dsn(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DIAG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("DIAG_TEST_DATABASE_URL 未设置")
	}
	return dsn
}

func t3Exec(t *testing.T, ctx context.Context, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("夹具 SQL 失败: %v\n%s", err, sql)
	}
}

func t3NewFixture(t *testing.T) *t3Fix {
	t.Helper()
	dsn := t3Dsn(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("连接测试库: %v", err)
	}
	x, err := NewExec(dsn)
	if err != nil {
		t.Fatal(err)
	}
	sfx := fmt.Sprintf("%08x", rand.Uint32())
	f := &t3Fix{x: x, conn: conn, tenant: "t3ten_" + sfx,
		adminU: "t3adm_" + sfx, staffA: "t3ua_" + sfx, staffB: "t3ub_" + sfx,
		provider: "t3prov_" + sfx, model: "t3mod_" + sfx, keyA: "t3ka_" + sfx, keyB: "t3kb_" + sfx,
		prefixA: "t3p" + sfx[:5]}
	t.Cleanup(func() {
		c := context.Background()
		for _, s := range []string{
			`DELETE FROM request_logs WHERE tenant_id = $1`,
			`DELETE FROM internal_keys WHERE tenant_id = $1`,
			`DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = $1)`,
			`DELETE FROM providers WHERE tenant_id = $1`,
			`DELETE FROM projects WHERE tenant_id = $1`,
			`DELETE FROM users WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			if _, err := conn.Exec(c, s, f.tenant); err != nil {
				t.Errorf("清理失败: %v (%s)", err, s)
			}
		}
		_ = conn.Close(c)
		x.Close()
	})
	t3Exec(t, ctx, conn, `INSERT INTO tenants (id, name) VALUES ($1, $1)`, f.tenant)
	for _, u := range []string{f.adminU, f.staffA, f.staffB} {
		t3Exec(t, ctx, conn, `INSERT INTO users (id, tenant_id, username, department_assignment_mode) VALUES ($1, $2, $1, 'emergency')`, u, f.tenant)
	}
	t3Exec(t, ctx, conn, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'p')`, "t3proj_"+f.tenant, f.tenant)
	t3Exec(t, ctx, conn, `INSERT INTO providers (id, tenant_id, name, provider_type) VALUES ($1, $2, $3, 'openai')`, f.provider, f.tenant, "渠道-"+f.provider)
	t3Exec(t, ctx, conn, `INSERT INTO models (id, provider_id, model_name) VALUES ($1, $2, $3)`, f.model, f.provider, "name-"+f.model)
	t3Exec(t, ctx, conn, `INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix) VALUES ($1,$2,$3,$4,$5,$6)`,
		f.keyA, f.tenant, "t3proj_"+f.tenant, f.staffA, "h_"+f.keyA, f.prefixA)
	t3Exec(t, ctx, conn, `INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix) VALUES ($1,$2,$3,$4,$5,$6)`,
		f.keyB, f.tenant, "t3proj_"+f.tenant, f.staffB, "h_"+f.keyB, "t3pb"+sfx[:4])
	return f
}

// add 插入一条请求。ago 为距现在的分钟数。
func (f *t3Fix) add(t *testing.T, rid, user, key, status string, code int, endpoint string, agoMin int, audit string) {
	t.Helper()
	var a any
	if audit != "" {
		a = audit
	}
	var c any
	if code > 0 {
		c = code
	}
	t3Exec(t, context.Background(), f.conn, `
INSERT INTO request_logs (id, request_id, tenant_id, user_id, client_id, provider_id, model_id, endpoint_type, request_status,
  upstream_status_code, latency_ms, created_at, output_audit_result)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,123, now() - make_interval(mins => $11), $12::jsonb)`,
		"id_"+rid, rid, f.tenant, user, key, f.provider, f.model, endpoint, status, c, agoMin, a)
}

func (f *t3Fix) seed(t *testing.T) {
	// staffA：上游 429 两次、成功 3 次；staffB：quota_exceeded、provider_unsupported(400 带 hint)
	f.add(t, f.rid("429a"), f.staffA, f.keyA, "provider_error", 429, "chat", 5, "")
	f.add(t, f.rid("429b"), f.staffA, f.keyA, "provider_error", 429, "chat", 10, "")
	f.add(t, f.rid("ok1"), f.staffA, f.keyA, "success", 200, "chat", 6, "")
	f.add(t, f.rid("ok2"), f.staffA, f.keyA, "success", 200, "chat", 7, "")
	f.add(t, f.rid("ok3"), f.staffB, f.keyB, "success", 200, "chat", 8, "")
	f.add(t, f.rid("quota"), f.staffB, f.keyB, "quota_exceeded", 0, "chat", 4, "")
	f.add(t, f.rid("unsup"), f.staffB, f.keyB, "provider_unsupported", 400, "chat", 3,
		`{"response_metadata":{"upstream_error_hint":"该渠道不支持此接口","upstream_error_code":"unsupported_x","error_message":"endpoint not supported"}}`)
	// 应被排除
	f.add(t, f.rid("proxy"), f.staffA, f.keyA, "provider_error", 500, "proxy", 2, "")
	f.add(t, f.rid("recv"), f.staffA, f.keyA, "received", 0, "chat", 2, "")
	f.add(t, f.rid("prog"), f.staffA, f.keyA, "in_progress", 0, "chat", 2, "")
	// 窗口外（3 小时前）
	f.add(t, f.rid("old"), f.staffA, f.keyA, "provider_error", 429, "chat", 180, "")
}

func (f *t3Fix) rid(s string) string { return "req_t3_" + f.tenant + "_" + s }

func t3Run(t *testing.T, tool Tool, f *t3Fix, scope Scope, args string) map[string]any {
	t.Helper()
	out, err := tool.Run(context.Background(), f.x, scope, json.RawMessage(args))
	if err != nil {
		t.Fatalf("%s: %v", tool.Name(), err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("输出不是 JSON: %v\n%s", err, out)
	}
	return m
}

func t3Tool(name string) Tool {
	for _, tl := range RequestTools() {
		if tl.Name() == name {
			return tl
		}
	}
	panic("no tool " + name)
}

func (f *t3Fix) admin() Scope { return Scope{TenantID: f.tenant, IsAdmin: true} }
func (f *t3Fix) staff(u string) Scope {
	return Scope{TenantID: f.tenant, UserID: u}
}

func t3Groups(m map[string]any) []map[string]any {
	var out []map[string]any
	for _, g := range m["groups"].([]any) {
		out = append(out, g.(map[string]any))
	}
	return out
}

func t3FindGroup(t *testing.T, gs []map[string]any, cat string, code float64) map[string]any {
	t.Helper()
	for _, g := range gs {
		c, _ := g["upstream_status_code"].(float64)
		if g["failure_category"] == cat && (code < 0 || c == code) {
			return g
		}
	}
	t.Fatalf("未找到分组 %s/%v: %v", cat, code, gs)
	return nil
}

func TestT3ToolMeta(t *testing.T) {
	names := map[string]bool{}
	for _, tl := range RequestTools() {
		names[tl.Name()] = true
		if tl.AdminOnly() {
			t.Errorf("%s 员工应可用", tl.Name())
		}
		if !json.Valid(tl.Schema()) {
			t.Errorf("%s schema 非法", tl.Name())
		}
		if tl.Description() == "" {
			t.Errorf("%s 缺描述", tl.Name())
		}
	}
	for _, n := range []string{"get_request", "search_requests", "compare_windows"} {
		if !names[n] {
			t.Errorf("缺少工具 %s", n)
		}
	}
}

func TestT3GetRequest(t *testing.T) {
	f := t3NewFixture(t)
	f.seed(t)
	tool := t3Tool("get_request")

	m := t3Run(t, tool, f, f.admin(), fmt.Sprintf(`{"request_id":%q}`, f.rid("unsup")))
	if m["found"] != true {
		t.Fatalf("应找到: %v", m)
	}
	r := m["request"].(map[string]any)
	if r["request_status"] != "provider_unsupported" || r["status_class"] != "failed" {
		t.Errorf("状态不对: %v", r)
	}
	if r["upstream_error_hint"] != "该渠道不支持此接口" || r["upstream_error_code"] != "unsupported_x" || r["error_message"] != "endpoint not supported" {
		t.Errorf("hint/code/message 不对: %v", r)
	}
	if r["username"] != f.staffB || r["key_prefix"] != "t3pb"+f.staffB[len(f.staffB)-8:][:4] {
		t.Errorf("用户名/key 前缀不对: %v", r)
	}
	if r["provider_name"] != "渠道-"+f.provider || r["model_name"] != "name-"+f.model {
		t.Errorf("渠道/模型名不对: %v", r)
	}
	if r["failure_category"] == "" || r["failure_category"] == nil {
		t.Errorf("failure_category 为空: %v", r)
	}

	m = t3Run(t, tool, f, f.admin(), fmt.Sprintf(`{"request_id":%q}`, f.rid("429a")))
	if r := m["request"].(map[string]any); r["failure_category"] != "rate_limited" || r["upstream_status_code"] != float64(429) {
		t.Errorf("上游 429 分类不对: %v", r)
	}
	m = t3Run(t, tool, f, f.admin(), fmt.Sprintf(`{"request_id":%q}`, f.rid("quota")))
	if r := m["request"].(map[string]any); r["failure_category"] != "quota_exceeded" {
		t.Errorf("quota_exceeded 分类不对: %v", r)
	}

	// 员工查自己的：能查；查他人的：与不存在一致
	m = t3Run(t, tool, f, f.staff(f.staffB), fmt.Sprintf(`{"request_id":%q}`, f.rid("unsup")))
	if m["found"] != true {
		t.Errorf("员工应能查自己的请求: %v", m)
	}
	other := t3Run(t, tool, f, f.staff(f.staffA), fmt.Sprintf(`{"request_id":%q}`, f.rid("unsup")))
	missing := t3Run(t, tool, f, f.staff(f.staffA), `{"request_id":"req_not_exist"}`)
	ob, _ := json.Marshal(other)
	mb, _ := json.Marshal(missing)
	if string(ob) != `{"found":false}` || string(mb) != string(ob) {
		t.Errorf("他人编号应与不存在无差别: %s vs %s", ob, mb)
	}
	// 其他租户视角
	m = t3Run(t, tool, f, Scope{TenantID: "other_" + f.tenant, IsAdmin: true}, fmt.Sprintf(`{"request_id":%q}`, f.rid("unsup")))
	if m["found"] != false {
		t.Errorf("跨租户不应找到: %v", m)
	}
	if _, err := tool.Run(context.Background(), f.x, f.admin(), json.RawMessage(`{}`)); err == nil {
		t.Error("缺 request_id 应报错")
	}
}

func TestT3SearchRequests(t *testing.T) {
	f := t3NewFixture(t)
	f.seed(t)
	tool := t3Tool("search_requests")

	m := t3Run(t, tool, f, f.admin(), `{"window_hours":1}`)
	// 窗口 1 小时：失败 429×2、quota×1、unsupported×1；成功 3；排除 proxy/received/in_progress/窗口外
	if m["total"] != float64(7) || m["success"] != float64(3) {
		t.Fatalf("总数/成功数不对: %v", m)
	}
	if rate := m["success_rate_pct"].(float64); rate != 42.9 {
		t.Errorf("成功率 %v, 期望 42.9", rate)
	}
	gs := t3Groups(m)
	if len(gs) != 3 {
		t.Fatalf("应有 3 个失败分组: %v", gs)
	}
	g := t3FindGroup(t, gs, "rate_limited", 429)
	if g["count"] != float64(2) || g["affected_users"] != float64(1) || g["provider_id"] != f.provider || g["model_id"] != f.model {
		t.Errorf("429 分组不对: %v", g)
	}
	if g["provider_name"] != "渠道-"+f.provider || g["model_name"] != "name-"+f.model {
		t.Errorf("分组缺渠道/模型名: %v", g)
	}
	samples := g["sample_request_ids"].([]any)
	if len(samples) != 2 || samples[0] != f.rid("429a") {
		t.Errorf("示例编号应按时间倒序: %v", samples)
	}
	if g["first_at"] == nil || g["last_at"] == nil {
		t.Errorf("缺 first_at/last_at: %v", g)
	}
	t3FindGroup(t, gs, "quota_exceeded", -1)
	t3FindGroup(t, gs, "unknown", 400) // provider_unsupported 无尝试记录，由状态码兜底
}

func TestT3SearchRequestsGroupsAndFilters(t *testing.T) {
	f := t3NewFixture(t)
	f.seed(t)
	tool := t3Tool("search_requests")

	// 示例编号最多 3 个
	for i := 0; i < 4; i++ {
		f.add(t, f.rid(fmt.Sprintf("more%d", i)), f.staffA, f.keyA, "provider_error", 429, "chat", 20+i, "")
	}
	m := t3Run(t, tool, f, f.admin(), `{"window_hours":1}`)
	g := t3FindGroup(t, t3Groups(m), "rate_limited", 429)
	if g["count"] != float64(6) || len(g["sample_request_ids"].([]any)) != 3 {
		t.Errorf("示例上限 3 / 计数 6: %v", g)
	}

	// 按名字筛选模型/渠道，按 id 也可以
	for _, args := range []string{
		fmt.Sprintf(`{"model":%q,"window_hours":1}`, "name-"+f.model),
		fmt.Sprintf(`{"model":%q,"window_hours":1}`, f.model),
		fmt.Sprintf(`{"provider":%q,"window_hours":1}`, "渠道-"+f.provider),
		fmt.Sprintf(`{"provider":%q,"window_hours":1}`, f.provider),
	} {
		mm := t3Run(t, tool, f, f.admin(), args)
		if mm["total"] != float64(11) {
			t.Errorf("%s 总数应为 11: %v", args, mm["total"])
		}
	}
	mm := t3Run(t, tool, f, f.admin(), `{"model":"不存在的模型","window_hours":1}`)
	if mm["total"] != float64(0) || mm["success_rate_pct"] != nil {
		t.Errorf("不存在的模型应为空: %v", mm)
	}

	// status_code / failure_category / key_prefix / user
	mm = t3Run(t, tool, f, f.admin(), `{"status_code":400,"window_hours":1}`)
	if len(t3Groups(mm)) != 1 {
		t.Errorf("status_code=400 只应有 1 组: %v", mm)
	}
	mm = t3Run(t, tool, f, f.admin(), `{"failure_category":"quota_exceeded","window_hours":1}`)
	if gs := t3Groups(mm); len(gs) != 1 || gs[0]["failure_category"] != "quota_exceeded" {
		t.Errorf("failure_category 筛选: %v", mm)
	}
	mm = t3Run(t, tool, f, f.admin(), fmt.Sprintf(`{"key_prefix":%q,"window_hours":1}`, f.prefixA))
	if mm["total"] != float64(8) {
		t.Errorf("key_prefix 筛选总数: %v", mm["total"])
	}
	mm = t3Run(t, tool, f, f.admin(), fmt.Sprintf(`{"user":%q,"window_hours":1}`, f.staffB))
	if mm["total"] != float64(3) {
		t.Errorf("user 筛选总数: %v", mm["total"])
	}

	// window_hours 默认 1、上限 24
	if mm = t3Run(t, tool, f, f.admin(), `{}`); mm["window_hours"] != float64(1) {
		t.Errorf("默认窗口: %v", mm["window_hours"])
	}
	mm = t3Run(t, tool, f, f.admin(), `{"window_hours":999}`)
	if mm["window_hours"] != float64(24) {
		t.Errorf("窗口应封顶 24: %v", mm["window_hours"])
	}
	if g := t3FindGroup(t, t3Groups(mm), "rate_limited", 429); g["count"] != float64(7) {
		t.Errorf("24 小时窗口应包含 3 小时前的记录: %v", g)
	}
}

func TestT3EmployeeScopeForced(t *testing.T) {
	f := t3NewFixture(t)
	f.seed(t)
	tool := t3Tool("search_requests")
	// 员工 A 试图通过 user 参数看 B：必须被忽略
	m := t3Run(t, tool, f, f.staff(f.staffA), fmt.Sprintf(`{"user":%q,"window_hours":1}`, f.staffB))
	if m["total"] != float64(4) || m["success"] != float64(2) {
		t.Errorf("员工只能看到自己的 4 条: %v", m)
	}
	for _, g := range t3Groups(m) {
		if g["affected_users"] != float64(1) || g["failure_category"] != "rate_limited" {
			t.Errorf("员工视角混入他人数据: %v", g)
		}
	}
	cw := t3Run(t, t3Tool("compare_windows"), f, f.staff(f.staffA), fmt.Sprintf(`{"user":%q}`, f.staffB))
	if a := cw["a"].(map[string]any); a["total"] != float64(4) {
		t.Errorf("compare_windows 员工视角: %v", a)
	}
}

func TestT3CompareWindows(t *testing.T) {
	f := t3NewFixture(t)
	f.seed(t) // 窗口 A（最近 1 小时）：7 条
	// 窗口 B（24 小时前同一时段）：5 条，4 成功 1 个 502
	for i := 0; i < 4; i++ {
		f.add(t, f.rid(fmt.Sprintf("bok%d", i)), f.staffA, f.keyA, "success", 200, "chat", 24*60+5+i, "")
	}
	f.add(t, f.rid("b502"), f.staffA, f.keyA, "provider_error", 502, "chat", 24*60+9, "")

	m := t3Run(t, t3Tool("compare_windows"), f, f.admin(), `{}`)
	a, b := m["a"].(map[string]any), m["b"].(map[string]any)
	if a["total"] != float64(7) || a["success"] != float64(3) || a["success_rate_pct"] != 42.9 {
		t.Errorf("窗口 A: %v", a)
	}
	if b["total"] != float64(5) || b["success"] != float64(4) || b["success_rate_pct"] != 80.0 {
		t.Errorf("窗口 B: %v", b)
	}
	if es := b["errors"].([]any); len(es) != 1 || es[0].(map[string]any)["upstream_status_code"] != float64(502) {
		t.Errorf("窗口 B 错误分布: %v", b["errors"])
	}
	if es := a["errors"].([]any); len(es) != 3 {
		t.Errorf("窗口 A 错误分布: %v", a["errors"])
	}
	m = t3Run(t, t3Tool("compare_windows"), f, f.admin(), `{"a_hours_ago":24,"b_hours_ago":0,"window_hours":1}`)
	if m["a"].(map[string]any)["total"] != float64(5) {
		t.Errorf("a_hours_ago 参数: %v", m["a"])
	}
}

// search_requests 的两条查询必须有可用的索引路径（不出现 request_logs 的顺序扫描）。
func TestT3SearchRequestsUsesIndex(t *testing.T) {
	f := t3NewFixture(t)
	f.seed(t)
	ctx := context.Background()
	for name, scope := range map[string]Scope{"admin": f.admin(), "staff": f.staff(f.staffA)} {
		in := t3Filter{Model: f.model, Provider: f.provider}
		queries := map[string]func() (string, []any){
			"summary": func() (string, []any) {
				return t3SummarySQL(scope, in, []string{f.model}, []string{f.provider}, 1, 0)
			},
			"groups": func() (string, []any) {
				return t3GroupsSQL(scope, in, []string{f.model}, []string{f.provider}, 1, 0, 50)
			},
		}
		for qn, build := range queries {
			sql, args := build()
			tx, err := f.conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
				t.Fatal(err)
			}
			rows, err := tx.Query(ctx, "EXPLAIN "+sql, args...)
			if err != nil {
				_ = tx.Rollback(ctx)
				t.Fatalf("%s/%s EXPLAIN: %v", name, qn, err)
			}
			var plan strings.Builder
			for rows.Next() {
				var line string
				if err := rows.Scan(&line); err != nil {
					t.Fatal(err)
				}
				plan.WriteString(line + "\n")
			}
			rows.Close()
			_ = tx.Rollback(ctx)
			p := plan.String()
			if strings.Contains(p, "Seq Scan on request_logs") {
				t.Errorf("%s/%s 出现顺序扫描:\n%s", name, qn, p)
			}
			if !strings.Contains(p, "Index") && !strings.Contains(p, "Bitmap") {
				t.Errorf("%s/%s 没有索引路径:\n%s", name, qn, p)
			}
		}
	}
	_ = time.Now
}
