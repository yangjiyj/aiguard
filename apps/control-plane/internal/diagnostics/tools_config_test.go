package diagnostics

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
)

// ---------- 夹具 ----------

type t4Fix struct {
	x      *Exec
	conn   *pgx.Conn
	sfx    string
	tenant string
	team   string
	userA  string // 在部门内，可聊天
	userB  string // 应急账号：无部门，不可聊天
	nameA  string
	prov1  string
	prov2  string
	m1     string // logical-x @ prov1
	m2     string // logical-y @ prov1
	m3     string // logical-x @ prov2（备用渠道）
	logX   string
	logY   string
	keyA   string
	proj   string
}

func t4Exec(t *testing.T, ctx context.Context, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("夹具 SQL 失败: %v\n%s", err, sql)
	}
}

func t4NewFixture(t *testing.T) *t4Fix {
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
	sfx := fmt.Sprintf("%08x", mrand.Uint32())
	f := &t4Fix{x: x, conn: conn, sfx: sfx, tenant: "t4ten_" + sfx, team: "t4team_" + sfx,
		userA: "t4ua_" + sfx, userB: "t4ub_" + sfx, nameA: "t4alice_" + sfx,
		prov1: "t4p1_" + sfx, prov2: "t4p2_" + sfx, m1: "t4m1_" + sfx, m2: "t4m2_" + sfx, m3: "t4m3_" + sfx,
		logX: "t4-logical-x-" + sfx, logY: "t4-logical-y-" + sfx, keyA: "t4ka_" + sfx, proj: "t4proj_" + sfx}
	t.Cleanup(func() {
		c := context.Background()
		for _, s := range []string{
			`DELETE FROM quota_policies WHERE tenant_id = $1`,
			`DELETE FROM request_logs WHERE tenant_id = $1`,
			`DELETE FROM audit_operations WHERE tenant_id = $1 OR user_id IN (SELECT id FROM users WHERE tenant_id = $1)`,
			`DELETE FROM model_ops_config_audit WHERE tenant_id = $1`,
			`DELETE FROM user_model_extra_grants WHERE tenant_id = $1`,
			`DELETE FROM user_model_policies WHERE tenant_id = $1`,
			`DELETE FROM internal_keys WHERE tenant_id = $1`,
			`DELETE FROM team_models WHERE team_id IN (SELECT id FROM teams WHERE tenant_id = $1)`,
			`DELETE FROM routing_policies WHERE tenant_id = $1`,
			`DELETE FROM model_route_health_snapshots WHERE tenant_id = $1`,
			`DELETE FROM provider_credentials WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = $1)`,
			`DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = $1)`,
			`DELETE FROM model_name_history WHERE tenant_id = $1`,
			`DELETE FROM providers WHERE tenant_id = $1`,
			`DELETE FROM projects WHERE tenant_id = $1`,
			`DELETE FROM users WHERE tenant_id = $1`,
			`DELETE FROM teams WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			if _, err := conn.Exec(c, s, f.tenant); err != nil {
				t.Errorf("清理失败: %v (%s)", err, s)
			}
		}
		_, _ = conn.Exec(c, `DELETE FROM upgrade_history WHERE id LIKE $1`, "t4up_"+sfx+"%")
		_, _ = conn.Exec(c, `DELETE FROM audit_operations WHERE id LIKE $1`, "t4a%_"+sfx)
		_, _ = conn.Exec(c, `DELETE FROM audit_operations WHERE id LIKE $1`, "t4n%_"+sfx)
		_ = conn.Close(c)
		x.Close()
	})
	t4Exec(t, ctx, conn, `INSERT INTO tenants (id, name) VALUES ($1, $1)`, f.tenant)
	t4Exec(t, ctx, conn, `INSERT INTO teams (id, tenant_id, name, path, model_access_mode) VALUES ($1, $2, $1, $3, 'allowlist')`, f.team, f.tenant, "/"+f.team)
	t4Exec(t, ctx, conn, `INSERT INTO users (id, tenant_id, username, department_id, department_assignment_mode, department_assignment_source) VALUES ($1, $2, $3, $4, 'manual', 'admin')`, f.userA, f.tenant, f.nameA, f.team)
	t4Exec(t, ctx, conn, `INSERT INTO users (id, tenant_id, username, department_assignment_mode) VALUES ($1, $2, $1, 'emergency')`, f.userB, f.tenant)
	t4Exec(t, ctx, conn, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'p')`, f.proj, f.tenant)
	t4Exec(t, ctx, conn, `INSERT INTO providers (id, tenant_id, name, provider_type, base_url, auth_mode) VALUES ($1, $2, $3, 'openai', $4, 'api_key')`,
		f.prov1, f.tenant, "渠道一-"+sfx, "https://u1:pw-SECRET@api.example.com:8443/v1?key=QUERYSECRET")
	t4Exec(t, ctx, conn, `INSERT INTO providers (id, tenant_id, name, provider_type, base_url) VALUES ($1, $2, $3, 'openai', 'https://backup.example.com')`, f.prov2, f.tenant, "渠道二-"+sfx)
	t4Exec(t, ctx, conn, `INSERT INTO models (id, provider_id, model_name, upstream_model_id) VALUES ($1, $2, $3, 'up-x')`, f.m1, f.prov1, f.logX)
	t4Exec(t, ctx, conn, `INSERT INTO models (id, provider_id, model_name) VALUES ($1, $2, $3)`, f.m2, f.prov1, f.logY)
	t4Exec(t, ctx, conn, `INSERT INTO models (id, provider_id, model_name) VALUES ($1, $2, $3)`, f.m3, f.prov2, f.logX)
	// 部门只授权 logical-x 的两条路由（m1/m3 同名），不含 logical-y
	t4Exec(t, ctx, conn, `INSERT INTO team_models (team_id, model_id, allowed) VALUES ($1, $2, TRUE), ($1, $3, TRUE)`, f.team, f.m1, f.m3)
	t4Exec(t, ctx, conn, `INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, name, key_ciphertext) VALUES ($1,$2,$3,$4,$5,$6,'我的密钥','CIPHER-KEY-SECRET')`,
		f.keyA, f.tenant, f.proj, f.userA, "HASH-SECRET-"+f.keyA, "t4k"+sfx[:5])
	return f
}

func (f *t4Fix) admin() Scope { return Scope{TenantID: f.tenant, IsAdmin: true} }
func (f *t4Fix) staff(u string) Scope {
	return Scope{TenantID: f.tenant, UserID: u}
}

func t4Tool(name string) Tool {
	for _, tl := range append(ConfigTools(), ChangeTools()...) {
		if tl.Name() == name {
			return tl
		}
	}
	panic("no tool " + name)
}

// t4Call 经 Registry.Call 调用（含权限检查、脱敏），返回解码后的输出与原文。
func t4Call(t *testing.T, f *t4Fix, scope Scope, name, args string) (map[string]any, string) {
	t.Helper()
	reg := NewRegistry(append(ConfigTools(), ChangeTools()...)...)
	step := reg.Call(context.Background(), f.x, scope, name, json.RawMessage(args))
	if step.Err != "" {
		t.Fatalf("%s: %s", name, step.Err)
	}
	var m map[string]any
	if err := json.Unmarshal(step.Output, &m); err != nil {
		t.Fatalf("输出不是 JSON 对象: %v\n%s", err, step.Output)
	}
	return m, string(step.Output)
}

func t4Strs(v any) []string {
	var out []string
	for _, e := range v.([]any) {
		out = append(out, e.(string))
	}
	return out
}

func t4Has(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// ---------- 元数据与权限 ----------

func TestT4ToolMeta(t *testing.T) {
	adminOnly := map[string]bool{"get_model_routes": true, "get_provider": true, "get_user_access": false,
		"get_quota_policies": false, "get_license": false, "change_timeline": true}
	seen := map[string]bool{}
	for _, tl := range append(ConfigTools(), ChangeTools()...) {
		want, ok := adminOnly[tl.Name()]
		if !ok {
			t.Errorf("意外的工具 %s", tl.Name())
			continue
		}
		seen[tl.Name()] = true
		if tl.AdminOnly() != want {
			t.Errorf("%s AdminOnly=%v，期望 %v", tl.Name(), tl.AdminOnly(), want)
		}
		if !json.Valid(tl.Schema()) || tl.Description() == "" {
			t.Errorf("%s 的 schema 或描述无效", tl.Name())
		}
	}
	for n := range adminOnly {
		if !seen[n] {
			t.Errorf("缺少工具 %s", n)
		}
	}
}

func TestT4StaffCannotCallAdminOnlyTools(t *testing.T) {
	reg := NewRegistry(append(ConfigTools(), ChangeTools()...)...)
	staff := Scope{TenantID: "x", UserID: "u1"}
	for _, n := range []string{"get_model_routes", "get_provider", "change_timeline"} {
		step := reg.Call(context.Background(), nil, staff, n, json.RawMessage(`{"model":"m","provider":"p"}`))
		if step.Err != ErrForbidden.Error() || step.Output != nil {
			t.Errorf("%s：员工应被拒绝，得到 err=%q output=%s", n, step.Err, step.Output)
		}
	}
	// 员工可见的工具列表不含管理员专用工具
	for _, tl := range reg.For(staff) {
		if tl.AdminOnly() {
			t.Errorf("员工工具列表里不应出现 %s", tl.Name())
		}
	}
}

// ---------- get_model_routes ----------

func TestT4GetModelRoutes(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	t4Exec(t, ctx, f.conn, `INSERT INTO model_route_health_snapshots (tenant_id, model_name, provider_id, state, version, observed_at, expires_at, source_instance, failure_category)
VALUES ($1,$2,$3,'unhealthy',1, now(), now() + interval '5 minutes','t4','rate_limited')`, f.tenant, f.logX, f.prov1)
	t4Exec(t, ctx, f.conn, `INSERT INTO routing_policies (id, tenant_id, scope_type, scope_ref, layer, strategy, config_json) VALUES ($1,$2,'model',$3,'provider','failover','{}')`,
		"t4rp_"+f.sfx, f.tenant, f.logX)

	m, _ := t4Call(t, f, f.admin(), "get_model_routes", fmt.Sprintf(`{"model":%q}`, f.logX))
	routes := m["routes"].([]any)
	if len(routes) != 2 {
		t.Fatalf("logical-x 应有 2 条路由，得到 %d: %v", len(routes), m)
	}
	byProv := map[string]map[string]any{}
	for _, r := range routes {
		rm := r.(map[string]any)
		byProv[rm["provider_id"].(string)] = rm
	}
	if byProv[f.prov1]["health_state"] != "unhealthy" || byProv[f.prov1]["usable"] != false {
		t.Errorf("渠道一应不可用: %v", byProv[f.prov1])
	}
	if byProv[f.prov1]["upstream_model_id"] != "up-x" {
		t.Errorf("upstream_model_id 不对: %v", byProv[f.prov1])
	}
	if byProv[f.prov2]["usable"] != true {
		t.Errorf("渠道二应可用: %v", byProv[f.prov2])
	}
	if m["has_standby"] != false || m["usable_routes"].(float64) != 1 {
		t.Errorf("仅 1 条可用路由，不应有备用: %v", m)
	}
	if len(m["routing_policies"].([]any)) != 1 {
		t.Errorf("应返回 1 条路由策略: %v", m["routing_policies"])
	}

	// 把渠道一恢复后应有备用渠道
	t4Exec(t, ctx, f.conn, `UPDATE model_route_health_snapshots SET state='healthy' WHERE tenant_id=$1`, f.tenant)
	m, _ = t4Call(t, f, f.admin(), "get_model_routes", fmt.Sprintf(`{"model":%q}`, f.logX))
	if m["has_standby"] != true || len(t4Strs(m["standby_providers"])) != 1 {
		t.Errorf("两条都可用时应有备用渠道: %v", m)
	}

	// 找不到
	m, _ = t4Call(t, f, f.admin(), "get_model_routes", `{"model":"no-such-model"}`)
	if m["found"] != false {
		t.Errorf("未知模型应 found=false: %v", m)
	}
	// 其他租户看不到
	m, _ = t4Call(t, f, Scope{TenantID: "other-tenant", IsAdmin: true}, "get_model_routes", fmt.Sprintf(`{"model":%q}`, f.logX))
	if m["found"] != false {
		t.Errorf("跨租户不应看到: %v", m)
	}
}

// ---------- get_provider ----------

func TestT4GetProviderNoCredentials(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	t4Exec(t, ctx, f.conn, `INSERT INTO provider_credentials (id, provider_id, credential_name, secret_ciphertext, kms_key_ref) VALUES ($1,$2,'k','CIPHER-PROVIDER-SECRET','kms-ref-1')`, "t4pc_"+f.sfx, f.prov1)
	for i, st := range []string{"success", "success", "success", "provider_error"} {
		code := 200
		if st != "success" {
			code = 429
		}
		t4Exec(t, ctx, f.conn, `INSERT INTO request_logs (id, request_id, tenant_id, user_id, provider_id, model_id, endpoint_type, request_status, upstream_status_code, latency_ms, created_at)
VALUES ($1,$1,$2,$3,$4,$5,'chat',$6,$7,100, now() - make_interval(mins => $8))`, fmt.Sprintf("t4req_%s_%d", f.sfx, i), f.tenant, f.userA, f.prov1, f.m1, st, code, i+1)
	}
	m, raw := t4Call(t, f, f.admin(), "get_provider", fmt.Sprintf(`{"provider":%q}`, f.prov1))
	if m["base_url_host"] != "api.example.com:8443" {
		t.Errorf("base_url 应只保留 host: %v", m["base_url_host"])
	}
	for _, leak := range []string{"pw-SECRET", "u1:", "QUERYSECRET", "/v1", "CIPHER-PROVIDER-SECRET", "kms-ref-1", "secret_ciphertext"} {
		if strings.Contains(raw, leak) {
			t.Errorf("输出不应包含 %q: %s", leak, raw)
		}
	}
	if m["auth_mode"] != "api_key" || m["status"] != "active" || m["provider_type"] != "openai" {
		t.Errorf("基本字段不对: %s", raw)
	}
	if m["has_active_credential"] != true {
		t.Errorf("应标注存在有效凭据（但不含内容）: %s", raw)
	}
	stats := m["last_hour"].(map[string]any)
	if stats["total"].(float64) != 4 || stats["success"].(float64) != 3 || stats["success_rate"].(float64) != 0.75 {
		t.Errorf("最近 1 小时统计不对: %v", stats)
	}
	cats := stats["failure_categories"].([]any)
	if len(cats) != 1 || cats[0].(map[string]any)["category"] != "rate_limited" {
		t.Errorf("失败分类应为 rate_limited: %v", cats)
	}
	// 按名字也能查
	m, _ = t4Call(t, f, f.admin(), "get_provider", fmt.Sprintf(`{"provider":%q}`, "渠道二-"+f.sfx))
	if m["id"] != f.prov2 || m["base_url_host"] != "backup.example.com" {
		t.Errorf("按名字查询不对: %v", m)
	}
	m, _ = t4Call(t, f, f.admin(), "get_provider", `{"provider":"nope"}`)
	if m["found"] != false {
		t.Errorf("未知渠道应 found=false: %v", m)
	}
}

func TestT4HostOnly(t *testing.T) {
	cases := map[string]string{
		"https://user:pw@api.example.com:8443/v1?key=abc": "api.example.com:8443",
		"http://10.0.0.1/path":                            "10.0.0.1",
		"api.example.com/v1":                              "api.example.com",
		"":                                                "",
	}
	for in, want := range cases {
		if got := t4HostOnly(in); got != want {
			t.Errorf("t4HostOnly(%q)=%q，期望 %q", in, got, want)
		}
	}
}

// ---------- get_user_access ----------

func TestT4GetUserAccess(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()

	m, raw := t4Call(t, f, f.admin(), "get_user_access", fmt.Sprintf(`{"user":%q}`, f.nameA))
	if m["chat_allowed"] != true {
		t.Fatalf("userA 应可聊天: %s", raw)
	}
	eff := t4Strs(m["effective_models"])
	if len(eff) != 1 || eff[0] != f.logX {
		t.Fatalf("可用模型应只有 logical-x: %v", eff)
	}
	if m["department_name"] != f.team {
		t.Errorf("部门名不对: %v", m["department_name"])
	}
	keys := m["keys"].([]any)
	if len(keys) != 1 || keys[0].(map[string]any)["key_prefix"] != "t4k"+f.sfx[:5] {
		t.Errorf("key 列表不对: %v", keys)
	}
	for _, leak := range []string{"HASH-SECRET", "CIPHER-KEY-SECRET", "key_hash", "key_ciphertext"} {
		if strings.Contains(raw, leak) {
			t.Errorf("输出不应包含 %q", leak)
		}
	}

	// 查 logical-y：部门未授权
	m, _ = t4Call(t, f, f.admin(), "get_user_access", fmt.Sprintf(`{"user":%q,"model":%q}`, f.userA, f.logY))
	chk := m["model_check"].(map[string]any)
	if chk["allowed"] != false || chk["reason_code"] != "department_not_granted" {
		t.Errorf("logical-y 应因部门未授权被拒: %v", chk)
	}
	// 查 logical-x：允许
	m, _ = t4Call(t, f, f.admin(), "get_user_access", fmt.Sprintf(`{"user":%q,"model":%q}`, f.userA, f.logX))
	if chk = m["model_check"].(map[string]any); chk["allowed"] != true || chk["source"] != "department" {
		t.Errorf("logical-x 应允许且来源为部门: %v", chk)
	}
	// 不存在的模型
	m, _ = t4Call(t, f, f.admin(), "get_user_access", fmt.Sprintf(`{"user":%q,"model":"ghost-model"}`, f.userA))
	if chk = m["model_check"].(map[string]any); chk["allowed"] != false || chk["reason_code"] != "model_unknown" {
		t.Errorf("未知模型: %v", chk)
	}

	// 个人白名单收窄到空集合后 logical-x 被拒
	t4Exec(t, ctx, f.conn, `INSERT INTO user_model_policies (tenant_id, user_id, mode, model_names, updated_by) VALUES ($1,$2,'allowlist','[]',$2)`, f.tenant, f.userA)
	m, _ = t4Call(t, f, f.admin(), "get_user_access", fmt.Sprintf(`{"user":%q,"model":%q}`, f.userA, f.logX))
	if chk = m["model_check"].(map[string]any); chk["allowed"] != false || chk["reason_code"] != "personal_allowlist_excludes" {
		t.Errorf("个人白名单应拒绝: %v", chk)
	}
	// 额外授权 logical-y 后允许，来源 personal_extra
	t4Exec(t, ctx, f.conn, `INSERT INTO user_model_extra_grants (id, tenant_id, user_id, model, reason, created_by) VALUES ($1,$2,$3,$4,'测试',$3)`, "t4g_"+f.sfx, f.tenant, f.userA, f.logY)
	m, _ = t4Call(t, f, f.admin(), "get_user_access", fmt.Sprintf(`{"user":%q,"model":%q}`, f.userA, f.logY))
	if chk = m["model_check"].(map[string]any); chk["allowed"] != true || chk["source"] != "personal_extra" {
		t.Errorf("额外授权应允许: %v", chk)
	}

	// 应急账号：无部门，chat_allowed=false（网关返回 forbidden_model）
	m, _ = t4Call(t, f, f.admin(), "get_user_access", fmt.Sprintf(`{"user":%q,"model":%q}`, f.userB, f.logX))
	if m["chat_allowed"] != false || len(t4Strs(m["effective_models"])) != 0 {
		t.Errorf("应急账号不应可聊天: %v", m)
	}
	if len(t4Strs(m["chat_denied_reasons"])) == 0 {
		t.Errorf("应说明不可聊天原因: %v", m)
	}
	if chk = m["model_check"].(map[string]any); chk["allowed"] != false || chk["reason_code"] != "chat_not_allowed" {
		t.Errorf("model_check: %v", chk)
	}

	// 找不到的用户
	m, _ = t4Call(t, f, f.admin(), "get_user_access", `{"user":"nobody-here"}`)
	if m["found"] != false {
		t.Errorf("未知用户应 found=false: %v", m)
	}
}

func TestT4GetUserAccessStaffForcedToSelf(t *testing.T) {
	f := t4NewFixture(t)
	// 员工 A 传入别人的 user，必须被忽略，返回的仍是 A 自己
	m, _ := t4Call(t, f, f.staff(f.userA), "get_user_access", fmt.Sprintf(`{"user":%q}`, f.userB))
	if m["user_id"] != f.userA || m["chat_allowed"] != true {
		t.Errorf("员工应只能查自己: %v", m)
	}
	// 员工 B（应急账号）查自己
	m, _ = t4Call(t, f, f.staff(f.userB), "get_user_access", fmt.Sprintf(`{"user":%q}`, f.userA))
	if m["user_id"] != f.userB {
		t.Errorf("员工 B 应只看到自己: %v", m)
	}
	// 员工缺少 UserID 直接报错
	reg := NewRegistry(ConfigTools()...)
	step := reg.Call(context.Background(), f.x, Scope{TenantID: f.tenant}, "get_user_access", json.RawMessage(`{}`))
	if step.Err == "" {
		t.Error("员工身份缺少 UserID 应报错")
	}
}

// 与网关口径对齐的防漂移测试：同一份夹具上，直接调用网关使用的 modelaccess.ReadAccess，
// 结果必须与 get_user_access 一致。
func TestT4GetUserAccessMatchesGatewayReadAccess(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	t4Exec(t, ctx, f.conn, `INSERT INTO user_model_extra_grants (id, tenant_id, user_id, model, reason, created_by) VALUES ($1,$2,$3,$4,'测试',$3)`, "t4g_"+f.sfx, f.tenant, f.userA, f.logY)
	// 再加一个已停用的模型，部门授权不应包含它
	t4Exec(t, ctx, f.conn, `INSERT INTO models (id, provider_id, model_name, status) VALUES ($1,$2,$3,'disabled')`, "t4m4_"+f.sfx, f.prov1, "t4-disabled-"+f.sfx)
	t4Exec(t, ctx, f.conn, `INSERT INTO team_models (team_id, model_id, allowed) VALUES ($1,$2,TRUE)`, f.team, "t4m4_"+f.sfx)

	for _, u := range []string{f.userA, f.userB} {
		want, err := modelaccess.ReadAccess(ctx, f.conn, f.tenant, u)
		if err != nil {
			t.Fatalf("ReadAccess(%s): %v", u, err)
		}
		m, _ := t4Call(t, f, f.admin(), "get_user_access", fmt.Sprintf(`{"user":%q}`, u))
		if m["chat_allowed"] != want.ChatAllowed {
			t.Errorf("%s chat_allowed 与网关不一致: 工具=%v 网关=%v", u, m["chat_allowed"], want.ChatAllowed)
		}
		got := t4Strs(m["effective_models"])
		if strings.Join(got, ",") != strings.Join(want.EffectiveModels, ",") {
			t.Errorf("%s effective_models 与网关不一致:\n工具=%v\n网关=%v", u, got, want.EffectiveModels)
		}
		if want.ChatAllowed && len(got) != 2 {
			t.Errorf("userA 应有 logical-x 与额外授权的 logical-y: %v", got)
		}
	}
}

// ---------- get_quota_policies ----------

func TestT4GetQuotaPolicies(t *testing.T) {
	f := t4NewFixture(t)
	ctx := context.Background()
	t4Exec(t, ctx, f.conn, `INSERT INTO quota_policies (id, tenant_id, scope_type, user_id, daily_token_limit_canonical, rpm_limit_canonical, overage_action, enforcement_mode)
VALUES ($1,$2,'user',$3,1000,30,'block','hard')`, "t4q1_"+f.sfx, f.tenant, f.userA)
	t4Exec(t, ctx, f.conn, `INSERT INTO quota_policies (id, tenant_id, scope_type, user_id, daily_token_limit_canonical, overage_action)
VALUES ($1,$2,'user',$3,5,'block')`, "t4q2_"+f.sfx, f.tenant, f.userB) // 别人的策略
	t4Exec(t, ctx, f.conn, `INSERT INTO quota_policies (id, tenant_id, scope_type, key_id, monthly_token_limit_canonical, daily_budget_micros, overage_action)
VALUES ($1,$2,'key',$3,50000,2000000,'block')`, "t4q3_"+f.sfx, f.tenant, f.keyA)
	t4Exec(t, ctx, f.conn, `INSERT INTO quota_policies (id, tenant_id, scope_type, scope_ref, daily_token_limit_canonical, overage_action)
VALUES ($1,$2,'team',$3,999999,'notify')`, "t4q4_"+f.sfx, f.tenant, f.team)
	for i, tok := range []int{300, 200} {
		t4Exec(t, ctx, f.conn, `INSERT INTO request_logs (id, request_id, tenant_id, user_id, client_id, provider_id, model_id, endpoint_type, request_status, upstream_status_code, input_tokens, output_tokens, created_at)
VALUES ($1,$1,$2,$3,$4,$5,$6,'chat','success',200,$7,$7, now() - make_interval(secs => $8))`, fmt.Sprintf("t4tok_%s_%d", f.sfx, i), f.tenant, f.userA, f.keyA, f.prov1, f.m1, tok/2, i+1)
	}

	// 员工 A 传入 B，也只会看到 A 自己的策略
	m, raw := t4Call(t, f, f.staff(f.userA), "get_quota_policies", fmt.Sprintf(`{"user":%q}`, f.userB))
	if m["user_id"] != f.userA {
		t.Errorf("员工应强制为自己: %v", m["user_id"])
	}
	ids := map[string]map[string]any{}
	for _, p := range m["policies"].([]any) {
		pm := p.(map[string]any)
		ids[pm["id"].(string)] = pm
	}
	if len(ids) != 3 || ids["t4q1_"+f.sfx] == nil || ids["t4q3_"+f.sfx] == nil || ids["t4q4_"+f.sfx] == nil {
		t.Fatalf("应命中用户/密钥/部门三条策略: %v", ids)
	}
	if ids["t4q2_"+f.sfx] != nil || strings.Contains(raw, "t4q2_") {
		t.Errorf("不应出现别人的策略")
	}
	up := ids["t4q1_"+f.sfx]
	if up["daily_token_limit"].(float64) != 1000 || up["rpm_limit"].(float64) != 30 || up["overage_action"] != "block" {
		t.Errorf("用户策略限额不对: %v", up)
	}
	if ids["t4q3_"+f.sfx]["daily_budget_micros"].(float64) != 2000000 {
		t.Errorf("密钥策略预算不对: %v", ids["t4q3_"+f.sfx])
	}
	usage := m["usage"].(map[string]any)
	if usage["day_tokens"].(float64) != 500 || usage["month_tokens"].(float64) < 500 {
		t.Errorf("用量不对: %v", usage)
	}
	ku := m["key_usage"].([]any)
	if len(ku) != 1 || ku[0].(map[string]any)["day_tokens"].(float64) != 500 {
		t.Errorf("密钥用量不对: %v", ku)
	}

	// 管理员按 key 前缀查
	m, _ = t4Call(t, f, f.admin(), "get_quota_policies", fmt.Sprintf(`{"key":%q}`, "t4k"+f.sfx[:5]))
	if m["user_id"] != f.userA {
		t.Errorf("按 key 前缀应定位到其所属用户: %v", m)
	}
	// 员工查别人的 key 前缀：找不到
	m, _ = t4Call(t, f, f.staff(f.userB), "get_quota_policies", fmt.Sprintf(`{"key":%q}`, f.keyA))
	if m["found"] != false {
		t.Errorf("员工查他人 key 应 found=false: %v", m)
	}
	// 管理员不带参数：列出租户内所有生效策略
	m, _ = t4Call(t, f, f.admin(), "get_quota_policies", `{}`)
	if len(m["policies"].([]any)) != 4 {
		t.Errorf("管理员无参应列出 4 条: %v", m["policies"])
	}
}

// ---------- get_license ----------

func t4SaveSettings(t *testing.T, f *t4Fix) {
	t.Helper()
	ctx := context.Background()
	keys := []string{license.SettingKeyLicense, license.SettingKeyImportedAt, license.SettingKeyTimeState,
		license.SettingKeyDeploymentID, license.SettingKeyInstallAnchor}
	saved := map[string]string{}
	rows, err := f.conn.Query(ctx, `SELECT key, value FROM system_settings WHERE key = ANY($1)`, keys)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatal(err)
		}
		saved[k] = v
	}
	rows.Close()
	t.Cleanup(func() {
		c := context.Background()
		_, _ = f.conn.Exec(c, `DELETE FROM system_settings WHERE key = ANY($1)`, keys)
		for k, v := range saved {
			_, _ = f.conn.Exec(c, `INSERT INTO system_settings (key, value) VALUES ($1,$2)`, k, v)
		}
	})
	t4Exec(t, ctx, f.conn, `DELETE FROM system_settings WHERE key = ANY($1)`, keys)
}

func t4SetSetting(t *testing.T, f *t4Fix, k, v string) {
	t.Helper()
	t4Exec(t, context.Background(), f.conn, `INSERT INTO system_settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, k, v)
}

func t4SignedLicense(t *testing.T, expires time.Time, graceDays int) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", "t4key="+base64.RawURLEncoding.EncodeToString(pub))
	t.Setenv("JJD_LICENSE_PUBLIC_KEY", "")
	t.Setenv("JJD_LICENSE_REVOCATION_FILE", "")
	now := time.Now().UTC()
	payload := license.PayloadV2{
		SchemaVersion:     license.SchemaVersionV2,
		LicenseID:         "t4-lic",
		Customer:          license.CustomerV2{ID: "c1", DisplayName: "测试客户"},
		Subject:           license.SubjectV2{DisplayName: "JJDGuard", Products: []string{license.ProductJJDGuardEnterprise}},
		Edition:           "enterprise",
		IssuedAt:          now.Add(-90 * 24 * time.Hour).Format(time.RFC3339),
		NotBefore:         now.Add(-90 * 24 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         expires.UTC().Format(time.RFC3339),
		MaxUsers:          100,
		Features:          []string{"agent_audit"},
		DeploymentBinding: license.DeploymentBinding{Mode: "none"},
		GracePolicy:       license.GracePolicy{ExpiryGraceDays: graceDays},
		Issuer:            "huoxianbao-license-authority-prod",
	}
	file, err := license.SignV2(payload, "t4key", priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := license.MarshalFileV2(*file)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestT4GetLicense(t *testing.T) {
	f := t4NewFixture(t)
	t4SaveSettings(t, f)
	t.Setenv("JJD_LICENSE_REVOCATION_FILE", "")

	// 未导入授权：按安装锚点判试用
	t4SetSetting(t, f, license.SettingKeyInstallAnchor, time.Now().UTC().AddDate(0, 0, -10).Format(time.RFC3339))
	m, _ := t4Call(t, f, f.admin(), "get_license", `{}`)
	if m["status"] != "trial" || m["valid"] != true || m["days_left"].(float64) < 79 {
		t.Errorf("试用期内状态不对: %v", m)
	}

	// 已导入有效授权
	raw := t4SignedLicense(t, time.Now().Add(30*24*time.Hour), 0)
	t4SetSetting(t, f, license.SettingKeyLicense, raw)
	m, _ = t4Call(t, f, f.admin(), "get_license", `{}`)
	if m["status"] != "active" || m["valid"] != true {
		t.Fatalf("有效授权状态不对: %v", m)
	}
	if d := m["days_left"].(float64); d < 29 || d > 31 {
		t.Errorf("剩余天数不对: %v", d)
	}
	if exp, _ := m["expires_at"].(string); !strings.HasPrefix(exp, time.Now().Add(30*24*time.Hour).UTC().Format("2006-01-02")) {
		t.Errorf("到期日不对: %v", m["expires_at"])
	}

	// 员工：只返回状态和到期日
	sm, sraw := t4Call(t, f, f.staff(f.userA), "get_license", `{}`)
	for k := range sm {
		switch k {
		case "status", "status_label", "valid", "expires_at", "days_left", "read_only":
		default:
			t.Errorf("员工输出不应包含字段 %q: %s", k, sraw)
		}
	}
	if sm["status"] != "active" {
		t.Errorf("员工应看到状态: %v", sm)
	}
	for _, leak := range []string{"测试客户", "t4-lic", "agent_audit", "t4key"} {
		if strings.Contains(sraw, leak) {
			t.Errorf("员工输出不应包含 %q", leak)
		}
	}

	// 已过期但在宽限期内
	raw = t4SignedLicense(t, time.Now().Add(-2*24*time.Hour), 10)
	t4SetSetting(t, f, license.SettingKeyLicense, raw)
	m, _ = t4Call(t, f, f.admin(), "get_license", `{}`)
	if m["status"] != "grace" || m["valid"] != true || m["grace_until"] == nil {
		t.Errorf("宽限期状态不对: %v", m)
	}
	// 已过期且无宽限：只读
	raw = t4SignedLicense(t, time.Now().Add(-2*24*time.Hour), 0)
	t4SetSetting(t, f, license.SettingKeyLicense, raw)
	m, _ = t4Call(t, f, f.admin(), "get_license", `{}`)
	if m["status"] != "expired" || m["valid"] != false || m["read_only"] != true || m["days_left"].(float64) != 0 {
		t.Errorf("过期状态不对: %v", m)
	}
	// 公钥不匹配/内容损坏：invalid
	t4SetSetting(t, f, license.SettingKeyLicense, "not-a-license")
	m, _ = t4Call(t, f, f.admin(), "get_license", `{}`)
	if m["status"] != "invalid" || m["valid"] != false {
		t.Errorf("损坏授权应为 invalid: %v", m)
	}
}

func TestT4ModelCheckKeyAllowlistSemantics(t *testing.T) {
	keys := []map[string]any{
		{"key_prefix": "narrow", "model_allowlist": []string{"other"}, "status": "active", "expired": false, "agent_bound": false},
		{"key_prefix": "empty", "model_allowlist": []string{}, "status": "active", "expired": false, "agent_bound": false},
		{"key_prefix": "hit", "model_allowlist": []string{"m1"}, "status": "active", "expired": false, "agent_bound": false},
		{"key_prefix": "revoked", "model_allowlist": []string{"other"}, "status": "revoked", "expired": false, "agent_bound": false},
		{"key_prefix": "expired", "model_allowlist": []string{"other"}, "status": "active", "expired": true, "agent_bound": false},
		{"key_prefix": "agent", "model_allowlist": []string{"other"}, "status": "active", "expired": false, "agent_bound": true},
	}
	chk := t4ModelCheck("m1", true, []string{"m1"}, map[string]string{"m1": "department"}, []string{"m1"}, []string{"m1"}, []string{"m1"}, keys)
	ex, _ := chk["key_allowlist_excludes"].([]string)
	if len(ex) != 1 || ex[0] != "narrow" {
		t.Fatalf("只有仍可用、非智能体绑定、白名单非空且不含该模型的密钥才算被限制: %v", ex)
	}
}
