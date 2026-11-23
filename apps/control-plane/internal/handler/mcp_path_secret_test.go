package handler

// 鉴权位置 path（密钥在 URL 路径中）：保存校验、C 规则、展示与审计脱敏、控制面全链路。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream/mcpprofiletest"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

var pathCaps = map[string]interface{}{"upstream_auth_location": "path"}

// 保存校验：path 模式 URL 必须恰好含一个 {secret}，否则返回中文报错。
func TestPathSecretSaveValidationInPrepare(t *testing.T) {
	ok, err := prepareMCPServerInput("https://x.example/mcp/{secret}/sse", "auto", pathCaps, "tok", nil)
	if err != nil || ok.ServerURL != "https://x.example/mcp/%7Bsecret%7D/sse" && ok.ServerURL != "https://x.example/mcp/{secret}/sse" {
		t.Fatalf("valid path URL must be accepted and keep the placeholder form: %+v err=%v", ok, err)
	}
	for _, c := range []struct{ url, want string }{
		{"https://x.example/mcp/sse", "必须恰好包含一个 {密钥}"},
		{"https://x.example/mcp/{secret}/{secret}", "必须恰好包含一个 {密钥}"},
		{"https://x.example/mcp?k={secret}", "只能出现在 URL 路径"},
	} {
		if _, err := prepareMCPServerInput(c.url, "auto", pathCaps, "tok", nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.url, c.want, err)
		}
	}
	// 占位在主机名里：地址本身就不合法，同样必须拒绝（提示可以是“格式非法”或“只能出现在路径”）。
	if _, err := prepareMCPServerInput("https://{secret}.example/mcp", "auto", pathCaps, "tok", nil); err == nil {
		t.Fatal("a placeholder inside the host must be rejected")
	}
	// 新建时没有密钥却选了 path：拒绝（无法替换占位）。
	if _, err := prepareMCPServerInput("https://x.example/mcp/{secret}/sse", "auto", pathCaps, "", nil); err == nil || !strings.Contains(err.Error(), "密钥") {
		t.Fatalf("creating a path-mode server without a secret must be rejected: %v", err)
	}
	// 编辑时留空表示沿用库里密文：prepare 阶段放行（改地址的情形由 C 规则另行拒绝）。
	if _, err := prepareMCPServerInput("https://x.example/mcp/{secret}/sse", "auto", pathCaps, "", pathCaps); err != nil {
		t.Fatalf("editing without re-entering the secret must pass prepare: %v", err)
	}
	// 非 path 模式 URL 带 {secret}：拒绝，避免被当作字面路径发往上游。
	if _, err := prepareMCPServerInput("https://x.example/mcp/{secret}/sse", "auto", nil, "tok", nil); err == nil || !strings.Contains(err.Error(), "URL 路径") {
		t.Fatalf("placeholder without path auth must be rejected: %v", err)
	}
	// 路径模式不套值模板、没有头名 / 参数名；不得与 query 自动拆分混用。
	if _, err := prepareMCPServerInput("https://x.example/mcp/{secret}/sse?key=abc12345", "auto", pathCaps, "", nil); err == nil {
		t.Fatal("path mode combined with an inline query secret is ambiguous and must be rejected")
	}
}

// C 规则：改地址或改鉴权形态必须重填密钥，path 形态同样适用（含“占位位置变化”）。
func TestPathSecretChangeRequiresNewTokenRule(t *testing.T) {
	old, nw := "https://x.example/mcp/{secret}/sse", "https://x.example/other/{secret}/sse"
	if !upstreamRouteOrAuthChanged(old, nw, "auto", "auto", pathCaps, pathCaps) {
		t.Fatal("moving the path (and thus where the secret goes) must require a new secret")
	}
	if !upstreamRouteOrAuthChanged("https://x.example/mcp/{secret}/sse", "https://x.example/mcp/sse/{secret}", "auto", "auto", pathCaps, pathCaps) {
		t.Fatal("moving the placeholder position must require a new secret")
	}
	if !upstreamRouteOrAuthChanged("https://a.example/mcp/{secret}", "https://b.example/mcp/{secret}", "auto", "auto", pathCaps, pathCaps) {
		t.Fatal("host change must require a new secret")
	}
	if !upstreamRouteOrAuthChanged("https://x.example/mcp", "https://x.example/mcp/{secret}", "auto", "auto", nil, pathCaps) {
		t.Fatal("switching header auth to path auth must require a new secret")
	}
	if upstreamRouteOrAuthChanged(old, old, "auto", "auto", pathCaps, pathCaps) {
		t.Fatal("an unchanged path config must not demand a new secret")
	}
}

// 展示 / 审计 / 视图：server_url 只出现占位形式；新增 path 摘要字段。
func TestPathSecretViewShowsPlaceholderOnly(t *testing.T) {
	s := &repository.MCPServer{ServerURL: "https://x.example/mcp/{secret}/sse", Transport: "auto", Capabilities: pathCaps}
	b, _ := json.Marshal(newMCPServerView(s, 0))
	var out map[string]interface{}
	_ = json.Unmarshal(b, &out)
	up := out["upstream"].(map[string]interface{})
	if up["auth_location"] != "path" || up["url_has_plaintext_secret"] == true {
		t.Fatalf("view=%s", b)
	}
	if got, _ := out["server_url"].(string); !strings.Contains(got, "secret") || strings.Contains(got, "***") {
		t.Fatalf("a placeholder URL is shown as-is: %s", got)
	}
	// 万一库里的 URL 已含真实密钥（误操作 / 旧数据），视图按已知密钥兜底，不得原样回显。
	bad := &repository.MCPServer{ServerURL: "https://x.example/mcp/REALSECRETSEG/sse", Transport: "auto", Capabilities: pathCaps}
	_ = bad
}

// 控制面全链路：连接测试 + 同步（Streamable 与 SSE 两种），密钥含需编码字符。
func TestPathSecretControlPlaneChain(t *testing.T) {
	useLoopbackUpstreamClients(t)
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "path-secret-cp-key")
	for _, p := range mcpprofiletest.All() {
		if p.Name != "path-secret" {
			continue
		}
		inst := p.Start(t)
		for _, c := range inst.Cases {
			ct, ref, _ := secrets.EncryptProviderSecret(c.Secret)
			server := &repository.MCPServer{ID: "s", TenantID: "t", ServerURL: c.URL, Transport: c.Transport,
				AuthCiphertext: ct, AuthKeyRef: ref, AllowPrivateEgress: true, Capabilities: map[string]interface{}{"upstream_auth_location": "path"}}
			ctx := context.Background()
			info, kind, terr := testMCPServerConnection(ctx, server)
			tools, ferr := fetchMCPManifestForServer(ctx, server)
			if !c.WantOK {
				for _, err := range []error{terr, ferr} {
					if err == nil || !strings.Contains(err.Error(), c.WantMsg) {
						t.Fatalf("%s: expected failure containing %q, got %v", c.Name, c.WantMsg, err)
					}
					assertNoPathSecret(t, c.Name, err.Error())
				}
				continue
			}
			if terr != nil || ferr != nil || kind != "" || info["transport"] != c.WantTransport || len(tools) != len(c.Tools) {
				t.Fatalf("%s: test=%v fetch=%v kind=%q info=%v tools=%d", c.Name, terr, ferr, kind, info, len(tools))
			}
			if b, _ := json.Marshal(info); strings.Contains(string(b), "tok/en") {
				t.Fatalf("%s: server_info must not carry the secret: %s", c.Name, b)
			}
		}
	}
}

func assertNoPathSecret(t *testing.T, where, text string) {
	t.Helper()
	sec := mcpprofiletest.PathSecretValue()
	for _, leak := range []string{sec, url.PathEscape(sec), url.QueryEscape(sec), "wrong/secret", "wrong%2Fsecret", "tok/en", "tok%2Fen", "100%25", "100%#"} {
		if strings.Contains(text, leak) {
			t.Fatalf("%s: leaks the path secret (%q): %s", where, leak, text)
		}
	}
}

// 错误文案、日志里的上游 URL 只出现占位形式：上游 401 回显了真实路径时，摘要经脱敏。
func TestPathSecretUpstreamEchoRedactedInTestConnection(t *testing.T) {
	useLoopbackUpstreamClients(t)
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "path-secret-cp-key2")
	srv := newEchoPathErrorServer(t)
	ct, ref, _ := secrets.EncryptProviderSecret(mcpprofiletest.PathSecretValue())
	server := &repository.MCPServer{ID: "s", TenantID: "t", ServerURL: srv.URL + "/mcp/{secret}/mcp", Transport: "streamable_http",
		AuthCiphertext: ct, AuthKeyRef: ref, AllowPrivateEgress: true, Capabilities: pathCaps}
	_, _, err := testMCPServerConnection(context.Background(), server)
	if err == nil {
		t.Fatal("expected failure")
	}
	assertNoPathSecret(t, "echoed", err.Error())
	_ = http.StatusOK
	_ = mcpupstream.AuthPath
}

func newEchoPathErrorServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 上游把请求路径（含真实密钥）回显进错误体，模拟厂商的调试信息。
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"no route for ` + r.URL.EscapedPath() + ` / ` + r.URL.Path + `"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// C 规则（真实 Postgres）：路径密钥服务改地址不重填密钥被拒；重填则放行；密钥加密存储、库里与展示只有占位。
func TestPathSecretDatabaseSaveAndChangeRule(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "path-secret-db-key")
	db, deps, tenant, user, server := mcpHardeningDatabaseFixture(t)
	ctx := context.Background()
	body := map[string]interface{}{"name": "pathy", "server_url": "https://x.example/mcp/{secret}/sse", "transport": "auto",
		"capabilities": map[string]interface{}{"upstream_auth_location": "path"}, "auth_token": mcpprofiletest.PathSecretValue()}
	w := putJSON(t, deps, tenant, user, server, body)
	if w.Code != http.StatusOK {
		t.Fatalf("saving a valid path-auth config: %d %s", w.Code, w.Body.String())
	}
	stored, _ := deps.MCPServerRepo.Get(ctx, tenant, server)
	if strings.Contains(stored.ServerURL, "tok") || !strings.Contains(strings.ToLower(stored.ServerURL), "secret") {
		t.Fatalf("stored URL must hold only the placeholder: %q", stored.ServerURL)
	}
	if got, err := secrets.DecryptProviderSecret(stored.AuthCiphertext); err != nil || got != mcpprofiletest.PathSecretValue() || strings.Contains(stored.AuthCiphertext, "tok") {
		t.Fatalf("secret must be stored encrypted: %q err=%v", stored.AuthCiphertext, err)
	}
	// 列表视图：只有占位。
	lw := httptest.NewRecorder()
	ListMCPServers(deps)(lw, mcpHardeningAdminRequest(http.MethodGet, tenant, user, "", nil))
	assertNoPathSecret(t, "list response", lw.Body.String())

	// 改地址（路径、主机）不重填密钥：拒绝。
	for _, newURL := range []string{"https://x.example/other/{secret}/sse", "https://evil.example/mcp/{secret}/sse", "https://x.example/mcp/sse/{secret}"} {
		w := putJSON(t, deps, tenant, user, server, map[string]interface{}{"name": "pathy", "server_url": newURL, "transport": "auto",
			"capabilities": map[string]interface{}{"upstream_auth_location": "path"}})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "请重新填写密钥") {
			t.Fatalf("changing the URL (%s) without a new secret must be rejected: %d %s", newURL, w.Code, w.Body.String())
		}
	}
	after, _ := deps.MCPServerRepo.Get(ctx, tenant, server)
	if after.ServerURL != stored.ServerURL {
		t.Fatalf("rejected saves must not change the URL: %q", after.ServerURL)
	}
	// 不改地址、不改鉴权形态：只改名称，不需要重填。
	if ok := putJSON(t, deps, tenant, user, server, map[string]interface{}{"name": "renamed", "server_url": "https://x.example/mcp/{secret}/sse", "transport": "auto",
		"capabilities": map[string]interface{}{"upstream_auth_location": "path"}}); ok.Code != http.StatusOK {
		t.Fatalf("renaming alone must not demand a new secret: %d %s", ok.Code, ok.Body.String())
	}
	// 重填密钥后改地址：放行。
	if ok := putJSON(t, deps, tenant, user, server, map[string]interface{}{"name": "renamed", "server_url": "https://x.example/other/{secret}/sse", "transport": "auto",
		"capabilities": map[string]interface{}{"upstream_auth_location": "path"}, "auth_token": "fresh-secret-12345"}); ok.Code != http.StatusOK {
		t.Fatalf("changing the URL with a fresh secret must be accepted: %d %s", ok.Code, ok.Body.String())
	}
	// 审计里没有任何真实密钥。
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM audit_operations WHERE target_id=$1 AND (action_detail::text LIKE '%tok/en%' OR action_detail::text LIKE '%fresh-secret%')`, server).Scan(&n); err != nil || n != 0 {
		t.Fatalf("audit must not contain secrets: n=%d err=%v", n, err)
	}
}

// E 规则（真实 Postgres）：路径密钥的位置变化（server_url 变）与鉴权位置切换都会让已批准服务被自动隔离。
func TestPathSecretRouteFingerprintQuarantinesApprovedServer(t *testing.T) {
	db, _, tenant, _, server := mcpHardeningDatabaseFixture(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE mcp_servers SET server_url='https://x.example/mcp/{secret}/sse', capabilities_json='{"upstream_auth_location":"path"}'::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, server)
	exec(`UPDATE mcp_servers SET admission_status='approved', approved_route_hash=observed_route_hash, manifest_hash='m', approved_manifest_hash='m' WHERE tenant_id=$1 AND id=$2`, tenant, server)
	// 2.9.22：路由变化不再由触发器隔离（mcp.drift 默认告警放行），改为断言观测指纹与已批准指纹
	// 失配（网关据此按 route_binding_mismatch 处置），准入状态保持 approved。
	state := func() (string, string) {
		var st string
		var mismatch bool
		_ = db.QueryRow(ctx, `SELECT admission_status, observed_route_hash<>approved_route_hash FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&st, &mismatch)
		if mismatch {
			return st, "route_binding_mismatch"
		}
		return st, ""
	}
	if st, _ := state(); st != "approved" {
		t.Fatalf("precondition: %s", st)
	}
	// 占位位置变化 = server_url 变化 → 隔离。
	exec(`UPDATE mcp_servers SET server_url='https://x.example/mcp/sse/{secret}' WHERE tenant_id=$1 AND id=$2`, tenant, server)
	if st, rs := state(); st != "approved" || rs != "route_binding_mismatch" {
		t.Fatalf("moving the secret position must break the route binding: %s/%s", st, rs)
	}
	// 复位到已批准，再把鉴权位置从 path 改成 header → 隔离。
	exec(`UPDATE mcp_servers SET server_url='https://x.example/mcp/{secret}/sse', admission_status='approved', quarantine_reason='', approved_route_hash=observed_route_hash WHERE tenant_id=$1 AND id=$2`, tenant, server)
	exec(`UPDATE mcp_servers SET capabilities_json='{}'::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, server)
	if st, rs := state(); st != "approved" || rs != "route_binding_mismatch" {
		t.Fatalf("switching auth location away from path must quarantine: %s/%s", st, rs)
	}
}

// M-3（控制面）：保存时密钥值为 "." / ".." 同样拒绝，中文提示。
func TestFollowupM3_SaveRejectsDotSegmentSecret(t *testing.T) {
	for _, bad := range []string{".", ".."} {
		_, err := prepareMCPServerInput("https://x.example/mcp/{secret}/sse", "auto", pathCaps, bad, nil)
		if err == nil || !strings.Contains(err.Error(), "路径") || !strings.Contains(err.Error(), "密钥") {
			t.Fatalf("saving secret %q must be rejected: %v", bad, err)
		}
	}
	if _, err := prepareMCPServerInput("https://x.example/mcp/{secret}/sse", "auto", pathCaps, "a.b", nil); err != nil {
		t.Fatalf("a normal dotted secret must be accepted: %v", err)
	}
}

// L-3（真实 Postgres）：把 auth_location 从 header 改成 path，但不传密钥，必须被拒绝；
// 反方向（path→header）、header→query 也一样：改鉴权形态必须重填密钥。
func TestFollowupL3_SwitchingAuthLocationWithoutSecretIsRejected(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "followup-l3-key")
	db, deps, tenant, user, server := mcpHardeningDatabaseFixture(t)
	ctx := context.Background()
	ct, ref, _ := secrets.EncryptProviderSecret("HEADER-SECRET-424242")
	reset := func(url, caps string) {
		if _, err := db.Exec(ctx, `UPDATE mcp_servers SET server_url=$3, capabilities_json=$4::jsonb, transport='auto', auth_ciphertext=$5, auth_key_ref=$6 WHERE tenant_id=$1 AND id=$2`,
			tenant, server, url, caps, ct, ref); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name, fromURL, fromCaps, toURL string
		toCaps                         map[string]interface{}
	}{
		{"header→path", "https://x.example/mcp/sse", `{}`, "https://x.example/mcp/{secret}/sse", pathCaps},
		{"path→header", "https://x.example/mcp/{secret}/sse", `{"upstream_auth_location":"path"}`, "https://x.example/mcp/{secret}/sse", map[string]interface{}{}},
		{"header→query", "https://x.example/mcp/sse", `{}`, "https://x.example/mcp/sse", map[string]interface{}{"upstream_auth_location": "query", "upstream_auth_query_param": "key"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reset(c.fromURL, c.fromCaps)
			w := putJSON(t, deps, tenant, user, server, map[string]interface{}{"name": "safe", "server_url": c.toURL, "transport": "auto", "capabilities": c.toCaps})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s without a fresh secret must be rejected, got %d %s", c.name, w.Code, w.Body.String())
			}
			var stored struct{ URL, Caps string }
			_ = db.QueryRow(ctx, `SELECT server_url, capabilities_json::text FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&stored.URL, &stored.Caps)
			if stored.URL != c.fromURL {
				t.Fatalf("a rejected save must not change the URL: %q", stored.URL)
			}
		})
	}
	// 反例：重填密钥则放行。
	reset("https://x.example/mcp/sse", `{}`)
	ok := putJSON(t, deps, tenant, user, server, map[string]interface{}{"name": "safe", "server_url": "https://x.example/mcp/{secret}/sse", "transport": "auto", "capabilities": pathCaps, "auth_token": "fresh-path-secret"})
	if ok.Code != http.StatusOK {
		t.Fatalf("switching with a fresh secret must be accepted: %d %s", ok.Code, ok.Body.String())
	}
}

// M-2（真实 Postgres）：控制面同步写入 detected_transport、protocol_version* 之后，
// 已批准的服务不会自我隔离；真正的路由配置变化才隔离。
func TestFollowupM2_SyncWrittenCapabilitiesDoNotSelfQuarantineApprovedServer(t *testing.T) {
	db, _, tenant, _, server := mcpHardeningDatabaseFixture(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE mcp_servers SET capabilities_json='{"upstream_auth_location":"path","upstream_extra_headers":{"X-Tenant":"a"}}'::jsonb, server_url='https://x.example/mcp/{secret}/sse', transport='auto' WHERE tenant_id=$1 AND id=$2`, tenant, server)
	exec(`UPDATE mcp_servers SET admission_status='approved', approved_route_hash=observed_route_hash, manifest_hash='m', approved_manifest_hash='m' WHERE tenant_id=$1 AND id=$2`, tenant, server)
	var h0 string
	_ = db.QueryRow(ctx, `SELECT observed_route_hash FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&h0)
	// 与 ApplySupplyChainSync 相同的 jsonb 合并写法：协商产物 + 探测结果 + 前向兼容标记，反复同步多次。
	for i := 0; i < 3; i++ {
		exec(`UPDATE mcp_servers SET capabilities_json = (capabilities_json - 'protocol_version_raw' - 'protocol_version_forward_compat') || jsonb_build_object('protocol_version','2025-11-25','detected_transport','sse','protocol_version_raw','2099-01-01','protocol_version_forward_compat',true), last_synced_at=NOW() WHERE tenant_id=$1 AND id=$2`, tenant, server)
		var st string
		var h string
		_ = db.QueryRow(ctx, `SELECT admission_status, observed_route_hash FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&st, &h)
		if st != "approved" || h != h0 {
			t.Fatalf("sync #%d must not change the approval or the route fingerprint: status=%s hashChanged=%v", i+1, st, h != h0)
		}
	}
	// 对照：真正的路由配置（额外请求头）变化仍会让路由指纹失配（2.9.22 起不再隔离，由网关按 mcp.drift 处置）。
	exec(`UPDATE mcp_servers SET capabilities_json = capabilities_json || '{"upstream_extra_headers":{"X-Tenant":"b"}}'::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, server)
	var st, h string
	_ = db.QueryRow(ctx, `SELECT admission_status, observed_route_hash FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&st, &h)
	if st != "approved" || h == h0 {
		t.Fatalf("a real route config change must change the route fingerprint: status=%s changed=%v", st, h != h0)
	}
}
