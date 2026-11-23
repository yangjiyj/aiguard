package diagnostics

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
)

// 任务 16：真实故障回归集。用例在 testdata/regress/*.json，夹具用相对 now 的时间偏移，
// 加载时换算，避免用例过期。所有私有名以 t16 为前缀，不依赖其他任务的辅助函数。

// ---------- 用例格式 ----------

type t16Case struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Fixture     t16Fixture `json:"fixture"`
	Input       t16Input   `json:"input"`
	Expect      t16Expect  `json:"expect"`
}

type t16Fixture struct {
	Teams []struct {
		Key    string   `json:"key"`
		Mode   string   `json:"mode"`
		Models []string `json:"models"`
	} `json:"teams"`
	Providers []struct {
		Key     string `json:"key"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		BaseURL string `json:"base_url"`
		Status  string `json:"status"`
	} `json:"providers"`
	Models []struct {
		Key      string `json:"key"`
		Provider string `json:"provider"`
		Name     string `json:"name"`
	} `json:"models"`
	Users []struct {
		Key      string `json:"key"`
		Username string `json:"username"`
		Team     string `json:"team"`
	} `json:"users"`
	InternalKeys []struct {
		Key            string   `json:"key"`
		User           string   `json:"user"`
		Name           string   `json:"name"`
		ModelAllowlist []string `json:"model_allowlist"`
	} `json:"internal_keys"`
	// 路由策略：config 里的 "{prov:渠道key}" 会换成真实渠道 id；scope_type=tenant 时 scope_ref 自动取租户。
	RoutingPolicies []struct {
		ScopeType     string          `json:"scope_type"`
		ScopeRef      string          `json:"scope_ref"`
		Layer         string          `json:"layer"`
		Strategy      string          `json:"strategy"`
		SchemaVersion int             `json:"schema_version"`
		Enabled       *bool           `json:"enabled"`
		Config        json.RawMessage `json:"config"`
	} `json:"routing_policies"`
	RequestLogs []struct {
		Label           string          `json:"label"`
		Count           int             `json:"count"`
		User            string          `json:"user"`
		Key             string          `json:"key"`
		Provider        string          `json:"provider"`
		Model           string          `json:"model"`
		EndpointType    string          `json:"endpoint_type"`
		Status          string          `json:"status"`
		UpstreamStatus  int             `json:"upstream_status"`
		From            string          `json:"from"`
		To              string          `json:"to"`
		Hint            string          `json:"hint"`
		UpstreamErrCode string          `json:"upstream_error_code"`
		ErrorMessage    string          `json:"error_message"`
		RoutingDecision json.RawMessage `json:"routing_decision_json"`
		BillingOutcome  string          `json:"billing_outcome"`
		LatencyMS       int             `json:"latency_ms"`
		ProxyMode       string          `json:"proxy_mode"`
		ProxyTargetHost string          `json:"proxy_target_host"`
		AgentType       string          `json:"agent_type"`
		UpstreamOutcome string          `json:"upstream_outcome"`
		DeliveryOutcome string          `json:"delivery_outcome"`
	} `json:"request_logs"`
	UpgradeHistory []struct {
		VersionFrom string `json:"version_from"`
		VersionTo   string `json:"version_to"`
		Status      string `json:"status"`
		CreatedAt   string `json:"created_at"`
		CompletedAt string `json:"completed_at"`
	} `json:"upgrade_history"`
	AuditOperations []struct {
		User       string          `json:"user"`
		ActionType string          `json:"action_type"`
		Detail     json.RawMessage `json:"action_detail"`
		TargetType string          `json:"target_type"`
		TargetID   string          `json:"target_id"`
		CreatedAt  string          `json:"created_at"`
	} `json:"audit_operations"`
	QuotaPolicies []struct {
		Key             string `json:"key"`
		ScopeType       string `json:"scope_type"`
		User            string `json:"user"`
		DailyTokenLimit int64  `json:"daily_token_limit"`
		RPMLimit        int64  `json:"rpm_limit"`
		OverageAction   string `json:"overage_action"`
		EnforcementMode string `json:"enforcement_mode"`
		DailyTokenBlock bool   `json:"daily_token_blocked"`
	} `json:"quota_policies"`
	UserModelExtraGrants []struct {
		User  string `json:"user"`
		Model string `json:"model"`
	} `json:"user_model_extra_grants"`
	UserModelPolicies []struct {
		User       string   `json:"user"`
		Mode       string   `json:"mode"`
		ModelNames []string `json:"model_names"`
	} `json:"user_model_policies"`
	License *struct {
		State string `json:"state"` // valid | expired_beyond_grace | grace
	} `json:"license"`
	HostSnapshot json.RawMessage `json:"host_snapshot"`
}

type t16Input struct {
	Kind      string `json:"kind"`
	Text      string `json:"text"`
	Ref       string `json:"ref"`   // 允许 "@标签:序号"，换算成该组第 N 条的请求编号
	Scope     string `json:"scope"` // admin | staff
	ScopeUser string `json:"scope_user"`
}

type t16Expect struct {
	Tier             string              `json:"tier"`
	MustCheckIDsAny  []string            `json:"must_check_ids_any"`
	MustCheckIDsAll  []string            `json:"must_check_ids_all"`
	MustKeywords     []string            `json:"must_keywords"`
	MustKeywordsAny  []string            `json:"must_keywords_any"`
	MustLevel        map[string]string   `json:"must_level"`
	MustSeverity     map[string]string   `json:"must_severity"`
	ForbidKeywords   []string            `json:"forbid_keywords"`
	ForbidConfirmed  []string            `json:"forbid_confirmed"`
	TitleContains    map[string][]string `json:"title_contains"`
	TitleNotContains map[string][]string `json:"title_not_contains"`
	// L3 的 check_id 由模型自由命名，不能按 ID 断言；改用语义断言。
	L3 *t16ExpectL3 `json:"l3"`
}

type t16ExpectL3 struct {
	MustKeywords     []string `json:"must_keywords"`
	MustKeywordsAny  []string `json:"must_keywords_any"`
	MustKeywordsAny2 []string `json:"must_keywords_any2"`
	ForbidKeywords   []string `json:"forbid_keywords"`
	LevelByKw        []struct {
		Kw    []string `json:"kw"`
		Level string   `json:"level"`
	} `json:"level_by_kw"`
	SeverityByKw []struct {
		Kw       []string `json:"kw"`
		Severity string   `json:"severity"`
	} `json:"severity_by_kw"`
	ForbidConfirmedKw []string `json:"forbid_confirmed_kw"`
	TitleRules        []struct {
		Match        []string `json:"match"`
		MatchAny     []string `json:"match_any"` // 标题含其中任一即命中（模型会在“额度/配额”等同义词间切换）
		TitleForbid  []string `json:"title_forbid"`
		TitleRequire []string `json:"title_require"`
	} `json:"title_rules"`
}

func t16LoadCases(t *testing.T) []t16Case {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "regress", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("没有找到回归用例: %v", err)
	}
	sort.Strings(files)
	var out []t16Case
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var c t16Case
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatalf("解析 %s: %v", f, err)
		}
		if c.Name == "" {
			t.Fatalf("%s 缺少 name", f)
		}
		out = append(out, c)
	}
	return out
}

// ---------- 时间偏移 ----------

// t16Off 把 "-30m" / "@-30h" / "0m" 换算成相对 now 的时刻。
func t16Off(t *testing.T, now time.Time, s string) time.Time {
	t.Helper()
	s = strings.TrimPrefix(strings.TrimSpace(s), "@")
	if s == "" {
		return now
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatalf("时间偏移 %q 不合法: %v", s, err)
	}
	return now.Add(d)
}

// t16Walk 递归把 "@偏移" 字符串换成 RFC3339 时间。
func t16Walk(t *testing.T, now time.Time, v any) any {
	switch x := v.(type) {
	case string:
		if strings.HasPrefix(x, "@") {
			return t16Off(t, now, x).UTC().Format(time.RFC3339)
		}
	case []any:
		for i := range x {
			x[i] = t16Walk(t, now, x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = t16Walk(t, now, x[k])
		}
	}
	return v
}

// ---------- 夹具加载器 ----------

type t16Env struct {
	x        *Exec
	conn     *pgx.Conn
	sfx      string
	tenant   string
	ids      map[string]string // 逻辑 key -> 真实 id（带随机后缀）
	reqIDs   map[string][]string
	hostView *HostView
	agent    *AgentClient
	now      time.Time
}

func t16Do(t *testing.T, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("夹具 SQL 失败: %v\n%s", err, sql)
	}
}

func (e *t16Env) id(kind, key string) string {
	if key == "" {
		return ""
	}
	v, ok := e.ids[kind+":"+key]
	if !ok {
		panic(fmt.Sprintf("用例引用了未定义的 %s %q", kind, key))
	}
	return v
}

func (e *t16Env) newID(kind, key string) string {
	v := fmt.Sprintf("t16%s_%s_%s", kind, key, e.sfx)
	e.ids[kind+":"+key] = v
	return v
}

func t16Nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func t16SignLicense(t *testing.T, expires time.Time, graceDays int) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", "t16key="+base64.RawURLEncoding.EncodeToString(pub))
	t.Setenv("JJD_LICENSE_PUBLIC_KEY", "")
	t.Setenv("JJD_LICENSE_REVOCATION_FILE", "")
	now := time.Now().UTC()
	payload := license.PayloadV2{
		SchemaVersion:     license.SchemaVersionV2,
		LicenseID:         "t16-lic",
		Customer:          license.CustomerV2{ID: "c16", DisplayName: "回归客户"},
		Subject:           license.SubjectV2{DisplayName: "JJDGuard", Products: []string{license.ProductJJDGuardEnterprise}},
		Edition:           "enterprise",
		IssuedAt:          now.Add(-400 * 24 * time.Hour).Format(time.RFC3339),
		NotBefore:         now.Add(-400 * 24 * time.Hour).Format(time.RFC3339),
		ExpiresAt:         expires.UTC().Format(time.RFC3339),
		MaxUsers:          100,
		Features:          []string{"agent_audit"},
		DeploymentBinding: license.DeploymentBinding{Mode: "none"},
		GracePolicy:       license.GracePolicy{ExpiryGraceDays: graceDays},
		Issuer:            "huoxianbao-license-authority-prod",
	}
	file, err := license.SignV2(payload, "t16key", priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := license.MarshalFileV2(*file)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func t16Load(t *testing.T, c t16Case) *t16Env {
	t.Helper()
	dsn := os.Getenv("DIAG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("DIAG_TEST_DATABASE_URL 未设置")
	}
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
	e := &t16Env{x: x, conn: conn, sfx: sfx, tenant: "t16ten_" + sfx, ids: map[string]string{}, reqIDs: map[string][]string{}, now: time.Now()}

	// 授权相关的全局配置：先保存，结束后还原。
	licKeys := []string{license.SettingKeyLicense, license.SettingKeyImportedAt, license.SettingKeyTimeState,
		license.SettingKeyDeploymentID, license.SettingKeyInstallAnchor}
	saved := map[string]string{}
	rows, err := conn.Query(ctx, `SELECT key, value FROM system_settings WHERE key = ANY($1)`, licKeys)
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
		for _, s := range []string{
			`DELETE FROM quota_policies WHERE tenant_id = $1`,
			`DELETE FROM request_logs WHERE tenant_id = $1`,
			`DELETE FROM audit_operations WHERE tenant_id = $1 OR user_id IN (SELECT id FROM users WHERE tenant_id = $1)`,
			`DELETE FROM user_model_extra_grants WHERE tenant_id = $1`,
			`DELETE FROM user_model_policies WHERE tenant_id = $1`,
			`DELETE FROM internal_keys WHERE tenant_id = $1`,
			`DELETE FROM team_models WHERE team_id IN (SELECT id FROM teams WHERE tenant_id = $1)`,
			`DELETE FROM routing_policies WHERE tenant_id = $1`,
			`DELETE FROM model_route_health_snapshots WHERE tenant_id = $1`,
			`DELETE FROM provider_credentials WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = $1)`,
			`DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = $1)`,
			`DELETE FROM providers WHERE tenant_id = $1`,
			`DELETE FROM projects WHERE tenant_id = $1`,
			`DELETE FROM users WHERE tenant_id = $1`,
			`DELETE FROM teams WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			if _, err := conn.Exec(c, s, e.tenant); err != nil {
				t.Errorf("清理失败: %v (%s)", err, s)
			}
		}
		_, _ = conn.Exec(c, `DELETE FROM upgrade_history WHERE id LIKE $1`, "t16up_%_"+sfx)
		_, _ = conn.Exec(c, `DELETE FROM system_settings WHERE key = ANY($1)`, licKeys)
		for k, v := range saved {
			_, _ = conn.Exec(c, `INSERT INTO system_settings (key, value) VALUES ($1,$2)`, k, v)
		}
		_ = conn.Close(c)
		x.Close()
	})

	// 授权：默认有效，避免无关的授权告警干扰；license_readonly 用例显式声明过期。
	state := "valid"
	if c.Fixture.License != nil && c.Fixture.License.State != "" {
		state = c.Fixture.License.State
	}
	var raw string
	switch state {
	case "valid":
		raw = t16SignLicense(t, e.now.Add(365*24*time.Hour), 0)
	case "grace":
		raw = t16SignLicense(t, e.now.Add(-2*24*time.Hour), 10)
	case "expired_beyond_grace":
		raw = t16SignLicense(t, e.now.Add(-20*24*time.Hour), 7)
	default:
		t.Fatalf("未知授权状态 %q", state)
	}
	t16Do(t, conn, `DELETE FROM system_settings WHERE key = ANY($1)`, licKeys)
	t16Do(t, conn, `INSERT INTO system_settings (key, value) VALUES ($1,$2)`, license.SettingKeyLicense, raw)

	f := c.Fixture
	t16Do(t, conn, `INSERT INTO tenants (id, name) VALUES ($1, $1)`, e.tenant)
	proj := "t16proj_" + sfx
	t16Do(t, conn, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'p')`, proj, e.tenant)
	for _, p := range f.Providers {
		id := e.newID("prov", p.Key)
		typ := p.Type
		if typ == "" {
			typ = "openai"
		}
		t16Do(t, conn, `INSERT INTO providers (id, tenant_id, name, provider_type, base_url) VALUES ($1,$2,$3,$4,$5)`,
			id, e.tenant, p.Name, typ, p.BaseURL)
		if p.Status != "" {
			t16Do(t, conn, `UPDATE providers SET status = $2 WHERE id = $1`, id, p.Status)
		}
	}
	modelNames := map[string]string{}
	for _, m := range f.Models {
		id := e.newID("model", m.Key)
		modelNames[m.Key] = m.Name
		t16Do(t, conn, `INSERT INTO models (id, provider_id, model_name) VALUES ($1,$2,$3)`, id, e.id("prov", m.Provider), m.Name)
	}
	for _, tm := range f.Teams {
		id := e.newID("team", tm.Key)
		mode := tm.Mode
		if mode == "" {
			mode = "allowlist"
		}
		t16Do(t, conn, `INSERT INTO teams (id, tenant_id, name, path, model_access_mode) VALUES ($1,$2,$1,$3,$4)`, id, e.tenant, "/"+id, mode)
		for _, mk := range tm.Models {
			t16Do(t, conn, `INSERT INTO team_models (team_id, model_id, allowed) VALUES ($1,$2,TRUE)`, id, e.id("model", mk))
		}
	}
	for _, u := range f.Users {
		id := e.newID("user", u.Key)
		if u.Team != "" {
			t16Do(t, conn, `INSERT INTO users (id, tenant_id, username, department_id, department_assignment_mode, department_assignment_source) VALUES ($1,$2,$3,$4,'manual','admin')`,
				id, e.tenant, u.Username, e.id("team", u.Team))
		} else {
			t16Do(t, conn, `INSERT INTO users (id, tenant_id, username, department_assignment_mode) VALUES ($1,$2,$3,'emergency')`, id, e.tenant, u.Username)
		}
	}
	for i, k := range f.InternalKeys {
		id := e.newID("key", k.Key)
		name := k.Name
		if name == "" {
			name = "回归密钥"
		}
		allow := k.ModelAllowlist
		if allow == nil {
			allow = []string{}
		}
		t16Do(t, conn, `INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, name, key_ciphertext, model_allowlist) VALUES ($1,$2,$3,$4,$5,$6,$7,'CIPHER',$8)`,
			id, e.tenant, proj, e.id("user", k.User), "t16hash_"+id, fmt.Sprintf("t16%d%s", i, sfx[:4]), name, allow)
	}
	for i, rp := range f.RoutingPolicies {
		cfg := string(rp.Config)
		for k, v := range e.ids {
			if strings.HasPrefix(k, "prov:") {
				cfg = strings.ReplaceAll(cfg, "{"+k+"}", v)
			}
		}
		scopeType, layer, schema := rp.ScopeType, rp.Layer, rp.SchemaVersion
		if scopeType == "" {
			scopeType = "model"
		}
		if layer == "" {
			layer = "provider"
		}
		if schema == 0 {
			schema = 2
		}
		ref := rp.ScopeRef
		if scopeType == "tenant" {
			ref = e.tenant
		}
		enabled := rp.Enabled == nil || *rp.Enabled
		t16Do(t, conn, `INSERT INTO routing_policies (id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, schema_version) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`,
			fmt.Sprintf("t16rp%d_%s", i, sfx), e.tenant, scopeType, ref, layer, rp.Strategy, cfg, enabled, schema)
	}
	for _, g := range f.UserModelExtraGrants {
		t16Do(t, conn, `INSERT INTO user_model_extra_grants (id, tenant_id, user_id, model, reason, created_by) VALUES ($1,$2,$3,$4,'回归','t16')`,
			"t16g_"+e.id("user", g.User)+"_"+g.Model, e.tenant, e.id("user", g.User), g.Model)
	}
	for _, p := range f.UserModelPolicies {
		names, _ := json.Marshal(p.ModelNames)
		t16Do(t, conn, `INSERT INTO user_model_policies (tenant_id, user_id, mode, model_names, updated_by) VALUES ($1,$2,$3,$4::jsonb,'t16')`,
			e.tenant, e.id("user", p.User), p.Mode, string(names))
	}
	for _, q := range f.QuotaPolicies {
		id := e.newID("quota", q.Key)
		scope := q.ScopeType
		if scope == "" {
			scope = "user"
		}
		oa := q.OverageAction
		if oa == "" {
			oa = "notify"
		}
		em := q.EnforcementMode
		if em == "" {
			em = "soft"
		}
		t16Do(t, conn, `INSERT INTO quota_policies (id, tenant_id, scope_type, user_id, daily_token_limit_canonical, rpm_limit_canonical, overage_action, enforcement_mode, daily_token_blocked)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, e.tenant, scope, t16Nullable(e.idOrEmpty("user", q.User)),
			nullInt(q.DailyTokenLimit), nullInt(q.RPMLimit), oa, em, q.DailyTokenBlock)
	}
	for i, u := range f.UpgradeHistory {
		var done any
		if u.CompletedAt != "" {
			done = t16Off(t, e.now, u.CompletedAt)
		}
		st := u.Status
		if st == "" {
			st = "completed"
		}
		t16Do(t, conn, `INSERT INTO upgrade_history (id, version_from, version_to, status, created_at, completed_at) VALUES ($1,$2,$3,$4,$5,$6)`,
			fmt.Sprintf("t16up_%d_%s", i, sfx), u.VersionFrom, u.VersionTo, st, t16Off(t, e.now, u.CreatedAt), done)
	}
	for i, a := range f.AuditOperations {
		detail := "{}"
		if len(a.Detail) > 0 {
			detail = string(a.Detail)
		}
		t16Do(t, conn, `INSERT INTO audit_operations (id, user_id, action_type, action_detail, target_type, target_id, created_at, tenant_id) VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8)`,
			fmt.Sprintf("t16a%d_%s", i, sfx), t16Nullable(e.idOrEmpty("user", a.User)), a.ActionType, detail, a.TargetType, a.TargetID, t16Off(t, e.now, a.CreatedAt), e.tenant)
	}
	for gi, g := range f.RequestLogs {
		from, to := t16Off(t, e.now, g.From), t16Off(t, e.now, g.To)
		n := g.Count
		if n <= 0 {
			n = 1
		}
		audit := map[string]any{}
		meta := map[string]any{}
		if g.Hint != "" {
			meta["upstream_error_hint"] = g.Hint
		}
		if g.UpstreamErrCode != "" {
			meta["upstream_error_code"] = g.UpstreamErrCode
		}
		if g.ErrorMessage != "" {
			meta["error_message"] = g.ErrorMessage
		}
		if len(meta) > 0 {
			audit["response_metadata"] = meta
		}
		auditJSON, _ := json.Marshal(audit)
		var routing any
		if len(g.RoutingDecision) > 0 {
			routing = string(g.RoutingDecision)
		}
		var code any
		if g.UpstreamStatus > 0 {
			code = g.UpstreamStatus
		}
		ep := g.EndpointType
		if ep == "" {
			ep = "chat"
		}
		billing := g.BillingOutcome
		if billing == "" {
			billing = "unknown"
		}
		lat := g.LatencyMS
		if lat <= 0 {
			lat = 123
		}
		for i := 0; i < n; i++ {
			at := from
			if n > 1 {
				at = from.Add(time.Duration(int64(to.Sub(from)) * int64(i) / int64(n-1)))
			}
			rid := fmt.Sprintf("req_%s-%04x-4000-8000-%012d", sfx, gi+1, i+1)
			e.reqIDs[g.Label] = append(e.reqIDs[g.Label], rid)
			t16Do(t, conn, `INSERT INTO request_logs (id, request_id, tenant_id, user_id, client_id, provider_id, model_id, endpoint_type, request_status,
  upstream_status_code, latency_ms, created_at, output_audit_result, routing_decision_json, billing_outcome,
  proxy_mode, proxy_target_host, agent_type, upstream_outcome, delivery_outcome)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$15,$11,$12::jsonb,$13::jsonb,$14,
  COALESCE(NULLIF($16,''),'chat_completion'), NULLIF($17,''), NULLIF($18,''), COALESCE(NULLIF($19,''),'unknown'), COALESCE(NULLIF($20,''),'unknown'))`,
				"id_"+rid, rid, e.tenant, t16Nullable(e.idOrEmpty("user", g.User)), t16Nullable(e.idOrEmpty("key", g.Key)),
				t16Nullable(e.idOrEmpty("prov", g.Provider)), t16Nullable(e.idOrEmpty("model", g.Model)), ep, g.Status, code, at, string(auditJSON), routing, billing,
				lat, g.ProxyMode, g.ProxyTargetHost, g.AgentType, g.UpstreamOutcome, g.DeliveryOutcome)
		}
	}

	// 宿主机快照：落到临时目录供采集器客户端读取（L3 的 host 工具用），同时构造 HostView（L2 用）。
	dir := filepath.Join(t.TempDir(), "diag")
	e.agent = &AgentClient{Dir: dir, Key: []byte("t16-key")}
	e.hostView = &HostView{Err: ErrAgentMissing}
	if len(f.HostSnapshot) > 0 {
		var generic any
		if err := json.Unmarshal(f.HostSnapshot, &generic); err != nil {
			t.Fatalf("host_snapshot 不是合法 JSON: %v", err)
		}
		generic = t16Walk(t, e.now, generic)
		b, _ := json.Marshal(generic)
		if err := os.MkdirAll(filepath.Join(dir, "snapshot"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "snapshot", "latest.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
		var snap HostSnapshot
		if err := json.Unmarshal(b, &snap); err != nil {
			t.Fatalf("host_snapshot 无法解析为 HostSnapshot: %v", err)
		}
		snap.Fresh, snap.Age = true, 0
		e.hostView = &HostView{Snapshot: &snap}
	}
	return e
}

func (e *t16Env) idOrEmpty(kind, key string) string {
	if key == "" {
		return ""
	}
	return e.id(kind, key)
}

func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// ---------- 输入解析与断言 ----------

func (e *t16Env) input(t *testing.T, c t16Case) (Scope, Input) {
	t.Helper()
	in := Input{Kind: c.Input.Kind, Text: c.Input.Text, Ref: c.Input.Ref}
	if strings.HasPrefix(in.Ref, "@") { // @标签:序号（从 1 开始）
		parts := strings.SplitN(strings.TrimPrefix(in.Ref, "@"), ":", 2)
		ids := e.reqIDs[parts[0]]
		idx := 1
		if len(parts) == 2 {
			fmt.Sscanf(parts[1], "%d", &idx)
		}
		if idx < 1 || idx > len(ids) {
			t.Fatalf("输入引用 %q 越界（该组共 %d 条）", c.Input.Ref, len(ids))
		}
		in.Ref = ids[idx-1]
	}
	scope := Scope{TenantID: e.tenant, IsAdmin: true}
	if c.Input.Scope == "staff" {
		scope = Scope{TenantID: e.tenant, UserID: e.id("user", c.Input.ScopeUser)}
	}
	return scope, in
}

func (e *t16Env) registry() *Registry {
	tools := append(append(append(RequestTools(), ConfigTools()...), ChangeTools()...), HostTools(e.agent)...)
	return NewRegistry(tools...)
}

func t16Text(f Finding) string {
	var b strings.Builder
	b.WriteString(f.Title + "\n" + f.Impact + "\n")
	for _, a := range f.Advice {
		b.WriteString(a.Text + "\n")
	}
	return b.String()
}

func t16Dump(rep *Report) string {
	b, _ := json.MarshalIndent(rep, "", "  ")
	return string(b)
}

// t16Check 返回所有不满足的 expect（空表示通过）。wantTier 为空时不比较档位。
func t16Check(rep *Report, ex t16Expect, wantTier string) []string {
	var bad []string
	if wantTier != "" && string(rep.Tier) != wantTier {
		bad = append(bad, fmt.Sprintf("档位应为 %s，实际 %s（降档原因：%s）", wantTier, rep.Tier, rep.Degraded))
	}
	byID := map[string][]Finding{}
	var all strings.Builder
	for _, f := range rep.Findings {
		byID[f.CheckID] = append(byID[f.CheckID], f)
		all.WriteString(t16Text(f))
	}
	text := all.String()
	if len(ex.MustCheckIDsAny) > 0 {
		ok := false
		for _, id := range ex.MustCheckIDsAny {
			if len(byID[id]) > 0 {
				ok = true
			}
		}
		if !ok {
			bad = append(bad, fmt.Sprintf("没有出现任何期望的检查项 %v", ex.MustCheckIDsAny))
		}
	}
	for _, id := range ex.MustCheckIDsAll {
		if len(byID[id]) == 0 {
			bad = append(bad, "缺少检查项 "+id)
		}
	}
	for _, k := range ex.MustKeywords {
		if !strings.Contains(text, k) {
			bad = append(bad, "结论缺少关键词 "+k)
		}
	}
	if len(ex.MustKeywordsAny) > 0 {
		ok := false
		for _, k := range ex.MustKeywordsAny {
			if strings.Contains(text, k) {
				ok = true
			}
		}
		if !ok {
			bad = append(bad, fmt.Sprintf("结论没有包含任一关键词 %v", ex.MustKeywordsAny))
		}
	}
	for _, k := range ex.ForbidKeywords {
		if strings.Contains(text, k) {
			bad = append(bad, "结论出现禁止关键词 "+k)
		}
	}
	for id, lv := range ex.MustLevel {
		ok := false
		for _, f := range byID[id] {
			if string(f.Level) == lv {
				ok = true
			}
		}
		if !ok {
			bad = append(bad, fmt.Sprintf("检查项 %s 应有级别 %s", id, lv))
		}
	}
	for id, sv := range ex.MustSeverity {
		ok := false
		for _, f := range byID[id] {
			if string(f.Severity) == sv {
				ok = true
			}
		}
		if !ok {
			bad = append(bad, fmt.Sprintf("检查项 %s 应有严重度 %s", id, sv))
		}
	}
	for _, id := range ex.ForbidConfirmed {
		for _, f := range byID[id] {
			if f.Level == LevelConfirmed {
				bad = append(bad, fmt.Sprintf("检查项 %s 不允许是确定级别", id))
			}
		}
	}
	for id, kws := range ex.TitleContains {
		for _, k := range kws {
			ok := false
			for _, f := range byID[id] {
				if strings.Contains(f.Title, k) {
					ok = true
				}
			}
			if !ok {
				bad = append(bad, fmt.Sprintf("%s 的标题应包含 %q", id, k))
			}
		}
	}
	for id, kws := range ex.TitleNotContains {
		for _, k := range kws {
			for _, f := range byID[id] {
				if strings.Contains(f.Title, k) {
					bad = append(bad, fmt.Sprintf("%s 的标题不应包含 %q：%s", id, k, f.Title))
				}
			}
		}
	}
	return bad
}

// ---------- L2 ----------

func TestT16RegressL2(t *testing.T) {
	for _, c := range t16LoadCases(t) {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			e := t16Load(t, c)
			scope, in := e.input(t, c)
			rep, err := RunTree(context.Background(), e.x, e.registry(), scope, in, e.hostView)
			if err != nil {
				t.Fatalf("RunTree（含 FactCheck）失败: %v\n%s", err, t16Dump(rep))
			}
			if err := FactCheck(rep); err != nil {
				t.Fatalf("FactCheck: %v\n%s", err, t16Dump(rep))
			}
			tier := c.Expect.Tier
			if tier == "" {
				tier = "L2"
			}
			if bad := t16Check(rep, c.Expect, tier); len(bad) > 0 {
				t.Fatalf("回归失败：\n  - %s\n完整报告：\n%s", strings.Join(bad, "\n  - "), t16Dump(rep))
			}
		})
	}
}

// ---------- L3（需要真实模型） ----------

func TestT16RegressL3(t *testing.T) {
	url, key, name := os.Getenv("DIAG_L3_MODEL_URL"), os.Getenv("DIAG_L3_MODEL_KEY"), os.Getenv("DIAG_L3_MODEL_NAME")
	if url == "" || key == "" || name == "" {
		t.Skip("DIAG_L3_MODEL_URL / DIAG_L3_MODEL_KEY / DIAG_L3_MODEL_NAME 未设置")
	}
	for _, c := range t16LoadCases(t) {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			e := t16Load(t, c)
			scope, in := e.input(t, c)
			llm := &t16TimedLLM{inner: NewHTTPLLM(url, key, "", "openai", name, &http.Client{}), t: t}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			rep, err := RunAgent(ctx, llm, e.x, e.registry(), scope, in, nil, nil)
			if err != nil || rep == nil {
				t.Fatalf("RunAgent 出错: %v", err)
			}
			// 用户原话里的数字（如“一直 403”）也算有据可查，与 RunAgent 内部口径一致。
			uin, _ := json.Marshal(map[string]string{"text": in.Text, "ref": in.Ref})
			chk := *rep
			chk.Steps = append(append([]Step{}, rep.Steps...), Step{Tool: "user_input", Output: uin})
			if err := FactCheck(&chk); err != nil {
				t.Fatalf("FactCheck: %v\n%s", err, t16Dump(rep))
			}
			// 验收口径：用户看到的结论永远不能是错的。L3 正常完成时按 L3 断言；
			// 降档时用户看到的是 L2 结论，按 L2 断言（同样不允许错），并单独统计降档率。
			if rep.Tier == TierL3 {
				if bad := t16CheckL3(rep, c.Expect.L3); len(bad) > 0 {
					t.Fatalf("L3 回归失败：\n  - %s\n完整报告：\n%s", strings.Join(bad, "\n  - "), t16Dump(rep))
				}
				t.Logf("L3 完成，未降档")
				return
			}
			if bad := t16Check(rep, c.Expect, "L2"); len(bad) > 0 {
				t.Fatalf("降档后的 L2 结论错误：\n  - %s\n完整报告：\n%s", strings.Join(bad, "\n  - "), t16Dump(rep))
			}
			t.Logf("L3 降档（%s），降档后结论正确", rep.Degraded)
		})
	}
}

// t16TimedLLM 记录每次模型调用的耗时、token 与错误，便于定位 L3 慢在哪。
type t16TimedLLM struct {
	inner LLM
	t     *testing.T
	n     int
}

func (l *t16TimedLLM) Chat(ctx context.Context, msgs []Msg, tools []ToolSpec) (Reply, error) {
	l.n++
	i, t0 := l.n, time.Now()
	r, err := l.inner.Chat(ctx, msgs, tools)
	l.t.Logf("模型调用#%d 耗时 %.1fs prompt=%d completion=%d tool_calls=%d err=%v", i, time.Since(t0).Seconds(), r.PromptTokens, r.CompletionTokens, len(r.ToolCalls), err)
	return r, err
}

// t16HitAffirmed 判断 kw 是否在 text 中以肯定语气出现（前 8 个字内带“不/非/没/无/排除”视为否定语境）。
func t16HitAffirmed(text, kw string) bool {
	rs := []rune(text)
	k := []rune(kw)
	for i := 0; i+len(k) <= len(rs); i++ {
		if string(rs[i:i+len(k)]) != kw {
			continue
		}
		lo := i - 8
		if lo < 0 {
			lo = 0
		}
		pre := string(rs[lo:i])
		if strings.ContainsAny(pre, "不非没无未") || strings.Contains(pre, "排除") {
			continue
		}
		return true
	}
	return false
}

func t16AnyIn(text string, kws []string) bool {
	for _, k := range kws {
		if strings.Contains(text, k) {
			return true
		}
	}
	return false
}

// t16CheckL3 是 L3 的语义断言。
func t16CheckL3(rep *Report, ex *t16ExpectL3) []string {
	var bad []string
	if rep.Tier != TierL3 {
		bad = append(bad, fmt.Sprintf("档位应为 L3，实际 %s（降档原因：%s）", rep.Tier, rep.Degraded))
	}
	if ex == nil {
		return bad
	}
	var all strings.Builder
	for _, f := range rep.Findings {
		all.WriteString(t16Text(f))
	}
	text := all.String()
	for _, k := range ex.MustKeywords {
		if !strings.Contains(text, k) {
			bad = append(bad, "结论缺少关键词 "+k)
		}
	}
	if len(ex.MustKeywordsAny) > 0 && !t16AnyIn(text, ex.MustKeywordsAny) {
		bad = append(bad, fmt.Sprintf("结论没有包含任一关键词 %v", ex.MustKeywordsAny))
	}
	if len(ex.MustKeywordsAny2) > 0 && !t16AnyIn(text, ex.MustKeywordsAny2) {
		bad = append(bad, fmt.Sprintf("结论没有包含任一关键词 %v", ex.MustKeywordsAny2))
	}
	// 禁止词只看"下了判断"的结论标题（confirmed/suspected）：模型在 unknown 结论或建议里
	// 写"尚不能确认是否上游返回"属于如实交代证据缺口，不算把责任归给上游。
	for _, k := range ex.ForbidKeywords {
		for _, f := range rep.Findings {
			if f.Level != LevelUnknown && t16HitAffirmed(f.Title, k) {
				bad = append(bad, "结论标题肯定地出现了禁止关键词 "+k+"："+f.Title)
			}
		}
	}
	for _, r := range ex.LevelByKw {
		ok := false
		for _, f := range rep.Findings {
			if t16AnyIn(f.Title, r.Kw) && string(f.Level) == r.Level {
				ok = true
			}
		}
		if !ok {
			bad = append(bad, fmt.Sprintf("标题含 %v 的结论应有级别 %s", r.Kw, r.Level))
		}
	}
	for _, r := range ex.SeverityByKw {
		ok := false
		for _, f := range rep.Findings {
			if t16AnyIn(f.Title, r.Kw) && string(f.Severity) == r.Severity {
				ok = true
			}
		}
		if !ok {
			bad = append(bad, fmt.Sprintf("标题含 %v 的结论应有严重度 %s", r.Kw, r.Severity))
		}
	}
	for _, f := range rep.Findings {
		if f.Level == LevelConfirmed && t16AnyIn(f.Title, ex.ForbidConfirmedKw) {
			bad = append(bad, "不允许把该类结论判为确定级别："+f.Title)
		}
	}
	for _, r := range ex.TitleRules {
		matched := false
		for _, f := range rep.Findings {
			hit := true
			for _, m := range r.Match {
				if !strings.Contains(f.Title, m) {
					hit = false
				}
			}
			if len(r.MatchAny) > 0 && !t16AnyIn(f.Title, r.MatchAny) {
				hit = false
			}
			if !hit {
				continue
			}
			matched = true
			for _, k := range r.TitleForbid {
				if t16HitAffirmed(f.Title, k) {
					bad = append(bad, fmt.Sprintf("标题含 %v 的结论不应肯定地包含 %q：%s", r.Match, k, f.Title))
				}
			}
			for _, k := range r.TitleRequire {
				if !strings.Contains(f.Title, k) {
					bad = append(bad, fmt.Sprintf("标题含 %v 的结论应包含 %q：%s", r.Match, k, f.Title))
				}
			}
		}
		if !matched {
			bad = append(bad, fmt.Sprintf("没有标题含 %v%v 的结论", r.Match, r.MatchAny))
		}
	}
	return bad
}

func TestT16HitAffirmed(t *testing.T) {
	cases := map[string]bool{
		"主渠道请求被记录为网关额度拦截，而非上游限流": false,
		"已排除上游限流":           false,
		"上游返回 429 限流":       true,
		"不是上游的问题":           false,
		"渠道 B 上游限流，渠道 A 正常": true,
	}
	for text, want := range cases {
		if got := t16HitAffirmed(text, "上游"); got != want {
			t.Errorf("%s: got %v want %v", text, got, want)
		}
	}
}
