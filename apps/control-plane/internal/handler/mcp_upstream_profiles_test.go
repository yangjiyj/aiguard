package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream/mcpprofiletest"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// 用测试 loopback 工厂替换出站 client（生产工厂经 safetarget，单独有测试覆盖）。
func useLoopbackUpstreamClients(t *testing.T) {
	t.Helper()
	old := mcpUpstreamClientFactory
	mcpUpstreamClientFactory = func(_ context.Context, rawURL string, _ safetarget.Options) (*http.Client, *http.Client, *url.URL, error) {
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, nil, nil, err
		}
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		return c, c, u, nil
	}
	t.Cleanup(func() { mcpUpstreamClientFactory = old })
}

func profileServer(t *testing.T, c mcpprofiletest.Case) *repository.MCPServer {
	t.Helper()
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-profile-test-key")
	srv := &repository.MCPServer{
		ID: "mcp_profile", TenantID: "t1", Name: c.Name, ServerURL: c.URL,
		Transport: c.Transport, Capabilities: map[string]interface{}{}, AllowPrivateEgress: true,
	}
	for k, v := range c.Caps {
		srv.Capabilities[k] = v
	}
	if c.Secret != "" {
		ct, ref, err := secrets.EncryptProviderSecret(c.Secret)
		if err != nil {
			t.Fatal(err)
		}
		srv.AuthCiphertext, srv.AuthKeyRef = ct, ref
	}
	return srv
}

// 每个画像都跑 control-plane 链路：连接测试（testMCPServerConnection）与同步取清单（fetchMCPManifestForServer）。
func TestMCPVendorProfilesControlPlaneChain(t *testing.T) {
	useLoopbackUpstreamClients(t)
	for _, p := range mcpprofiletest.All() {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			inst := p.Start(t)
			for _, c := range inst.Cases {
				c := c
				t.Run(c.Name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer cancel()
					info, kind, terr := testMCPServerConnection(ctx, profileServer(t, c))
					server := profileServer(t, c)
					tools, ferr := fetchMCPManifestForServer(ctx, server)

					if !c.WantOK {
						if terr == nil || ferr == nil {
							t.Fatalf("expected both to fail: test=%v fetch=%v", terr, ferr)
						}
						for _, err := range []error{terr, ferr} {
							if !strings.Contains(err.Error(), c.WantMsg) {
								t.Fatalf("message %q missing %q", err.Error(), c.WantMsg)
							}
							if strings.Contains(err.Error(), mcpprofiletest.SecretValue()) {
								t.Fatalf("error leaks secret: %v", err)
							}
						}
						wantKind := c.WantKind
						if wantKind == "protocol_version" {
							wantKind = "parse" // 既有 kind 口径
						}
						if kind != wantKind {
							t.Fatalf("test-connection kind=%q want %q (err=%v)", kind, wantKind, terr)
						}
						return
					}
					if terr != nil || kind != "" {
						t.Fatalf("test connection: kind=%q err=%v", kind, terr)
					}
					if info["transport"] != c.WantTransport || info["protocol_version"] != c.WantProtocol {
						t.Fatalf("info=%v want transport=%s proto=%s", info, c.WantTransport, c.WantProtocol)
					}
					if ferr != nil {
						t.Fatalf("fetch manifest: %v", ferr)
					}
					var names []string
					for _, tl := range tools {
						names = append(names, tl.Name)
					}
					if strings.Join(names, ",") != strings.Join(c.Tools, ",") {
						t.Fatalf("tools=%v want %v", names, c.Tools)
					}
					if got, _ := server.Capabilities["protocol_version"].(string); got != c.WantProtocol {
						t.Fatalf("protocol_version not recorded: %v", server.Capabilities)
					}
					if c.WantRawProto != "" {
						if server.Capabilities["protocol_version_raw"] != c.WantRawProto || server.Capabilities["protocol_version_forward_compat"] != true {
							t.Fatalf("raw version not recorded: %v", server.Capabilities)
						}
					}
					if c.Transport == "auto" && server.Capabilities["detected_transport"] != c.WantTransport {
						t.Fatalf("auto detection not recorded: %v", server.Capabilities)
					}
					if c.Transport != "auto" {
						if _, has := server.Capabilities["detected_transport"]; has {
							t.Fatalf("explicit transport must not write detected_transport: %v", server.Capabilities)
						}
					}
				})
			}
		})
	}
}

// 存量 streamable_http 服务（客户现网：智慧芽、威科先行；协商 2025-11-25）：
// capabilities 没有任何新字段时，行为与改造前完全一致——只发 POST，不发 GET，不写 detected_transport，
// 请求头 Authorization: Bearer，协商结果仍是 2025-11-25，且请求序列是 initialize → initialized → tools/list。
func TestMCPLegacyStreamableServersBehaveExactlyAsBefore(t *testing.T) {
	useLoopbackUpstreamClients(t)
	var p mcpprofiletest.Profile
	for _, c := range mcpprofiletest.All() {
		if c.Name == "legacy-qianwen-existing-corp" {
			p = c
		}
	}
	inst := p.Start(t)
	c := inst.Cases[0]
	server := profileServer(t, c)
	server.Capabilities = map[string]interface{}{} // 存量：没有任何新字段
	ctx := context.Background()
	if _, err := fetchMCPManifestForServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	if server.Capabilities["protocol_version"] != "2025-11-25" {
		t.Fatalf("negotiated version changed: %v", server.Capabilities)
	}
	for _, key := range []string{"detected_transport", "protocol_version_raw", "protocol_version_forward_compat"} {
		if _, has := server.Capabilities[key]; has {
			t.Fatalf("legacy server must not gain %s: %v", key, server.Capabilities)
		}
	}
	var methods []string
	for _, r := range inst.Requests() {
		if r.Method != http.MethodPost {
			t.Fatalf("legacy streamable server must only receive POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer "+mcpprofiletest.SecretValue() {
			t.Fatalf("legacy auth header changed: %q", r.Header.Get("Authorization"))
		}
		if r.RawQuery != "" {
			t.Fatalf("legacy request must not gain query params: %q", r.RawQuery)
		}
		var m struct{ Method string }
		_ = json.Unmarshal(r.Body, &m)
		methods = append(methods, m.Method)
	}
	if strings.Join(methods, ",") != "initialize,notifications/initialized,tools/list,tools/list" {
		t.Fatalf("request sequence changed: %v", methods)
	}
	if patch := mcpSyncCapabilityPatch(server); len(patch) != 0 {
		t.Fatalf("legacy sync must persist no new capability keys: %v", patch)
	}
}

func TestMCPPrepareServerInputSplitsURLSecrets(t *testing.T) {
	res, err := prepareMCPServerInput("https://mcp.amap.com/mcp?key=abc123XYZ&lang=zh", "auto", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.ServerURL, "abc123XYZ") || res.ServerURL != "https://mcp.amap.com/mcp?lang=zh" {
		t.Fatalf("URL still carries secret: %s", res.ServerURL)
	}
	if res.AuthToken != "abc123XYZ" ||
		res.Capabilities[mcpupstream.CapAuthLocation] != "query" || res.Capabilities[mcpupstream.CapAuthQueryParam] != "key" {
		t.Fatalf("not converted to query auth: %+v", res)
	}
	// 百度：值带 Bearer 前缀 → Bearer 模板，密钥不含前缀。
	res, err = prepareMCPServerInput("https://qianfan.baidubce.com/v2/ai_search/mcp/sse?api_key=Bearer+bce-xyz-12345", "sse", nil, "", nil)
	if err != nil || res.AuthToken != "bce-xyz-12345" || res.Capabilities[mcpupstream.CapAuthTemplate] != "Bearer {secret}" {
		t.Fatalf("baidu split: %+v err=%v", res, err)
	}
	// 同时填了另一个密钥：拒绝，中文提示。
	if _, err = prepareMCPServerInput("https://x.example/mcp?key=aaaa", "auto", nil, "bbbb", nil); err == nil || !strings.Contains(err.Error(), "无法判断以哪个为准") {
		t.Fatalf("conflicting secrets must be rejected: %v", err)
	}
	// 多个疑似密钥：拒绝。
	if _, err = prepareMCPServerInput("https://x.example/mcp?key=aaaa&token=bbbb", "auto", nil, "", nil); err == nil || !strings.Contains(err.Error(), "多个疑似密钥") {
		t.Fatalf("multiple secrets must be rejected: %v", err)
	}
	// 非法 transport / 非法配置 / 疑似密钥的额外请求头。
	for _, tc := range []struct {
		transport string
		caps      map[string]interface{}
	}{
		{"websocket", nil},
		{"auto", map[string]interface{}{"upstream_extra_headers": map[string]interface{}{"Host": "x"}}},
		{"auto", map[string]interface{}{"upstream_extra_headers": map[string]interface{}{"X-Api-Token": "plaintext"}}},
		{"auto", map[string]interface{}{"upstream_auth_location": "query"}},
	} {
		if _, err := prepareMCPServerInput("https://x.example/mcp", tc.transport, tc.caps, "", nil); err == nil {
			t.Fatalf("expected rejection for %v %v", tc.transport, tc.caps)
		}
	}
	// 干净 URL 不受影响（存量行为）。
	res, err = prepareMCPServerInput("https://mcp.example/rpc?route=saved", "streamable_http", nil, "tok", nil)
	if err != nil || res.ServerURL != "https://mcp.example/rpc?route=saved" || res.AuthToken != "tok" || res.Capabilities != nil {
		t.Fatalf("clean URL changed: %+v err=%v", res, err)
	}
}

// 错误信息 / 日志里不得出现密钥与 URL query 值。
func TestMCPUpstreamErrorsNeverContainSecretsOrQueryValues(t *testing.T) {
	useLoopbackUpstreamClients(t)
	inst := mcpprofiletest.StartServer(t, mcpprofiletest.Options{
		Name: "amap", StreamablePath: "/mcp", Version: "2025-11-25",
		StreamAuth: mcpprofiletest.AuthSpec{Mode: "query", Name: "key", Template: "{secret}", Secret: "RIGHT-KEY-123456", Unauth: "amap"},
	})
	const wrong = "WRONG-KEY-987654"
	server := profileServer(t, mcpprofiletest.Case{
		Name: "x", URL: inst.URL() + "/mcp?region=cn", Transport: "streamable_http", Secret: wrong,
		Caps: map[string]interface{}{"upstream_auth_location": "query", "upstream_auth_query_param": "key"},
	})
	_, _, terr := testMCPServerConnection(context.Background(), server)
	_, ferr := fetchMCPManifestForServer(context.Background(), server)
	for _, err := range []error{terr, ferr} {
		if err == nil {
			t.Fatal("wrong key must fail")
		}
		for _, leak := range []string{wrong, "RIGHT-KEY-123456", "key=" + wrong, "region=cn"} {
			if strings.Contains(err.Error(), leak) {
				t.Fatalf("error leaks %q: %v", leak, err)
			}
		}
	}
	// 摘要里即使上游回显了密钥也要脱敏。
	echo := mcpupstream.NotJSONRPC(200, []byte(`{"info":"INVALID key=`+wrong+` url=https://a.example/x?key=`+wrong+`"}`), wrong)
	if strings.Contains(echo.Error(), wrong) {
		t.Fatalf("echoed secret not redacted: %v", echo)
	}
	if !strings.Contains(echo.Error(), "已脱敏，截断到 300 字") {
		t.Fatalf("missing redaction notice: %v", echo)
	}
}

func TestMCPLongBodySummaryTruncatedTo300(t *testing.T) {
	e := mcpupstream.NotJSONRPC(200, []byte(strings.Repeat("错", 2000)))
	if n := len([]rune(e.Error())); n > 300+120 {
		t.Fatalf("summary not truncated, message runes=%d", n)
	}
}

func TestMCPForwardCompatPatchPersistedOnlyWhenForward(t *testing.T) {
	server := &repository.MCPServer{Transport: "auto", Capabilities: map[string]interface{}{
		"detected_transport": "sse", "protocol_version_raw": "2099-01-01", "protocol_version_forward_compat": true,
	}}
	patch := mcpSyncCapabilityPatch(server)
	if patch["detected_transport"] != "sse" || patch["protocol_version_raw"] != "2099-01-01" {
		t.Fatalf("patch=%v", patch)
	}
	server.Transport = "streamable_http"
	if _, has := mcpSyncCapabilityPatch(server)["detected_transport"]; has {
		t.Fatal("explicit transport must not persist detected_transport")
	}
}

func TestMCPRestoreRedactedQueryValues(t *testing.T) {
	got, err := restoreRedactedQueryValues("https://mcp.amap.com/mcp?key=***&lang=zh", "https://mcp.amap.com/mcp?key=REALKEY1&lang=zh")
	if err != nil || got != "https://mcp.amap.com/mcp?key=REALKEY1&lang=zh" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	// 还原后再拆分：密钥进入鉴权，URL 干净。
	res, err := prepareMCPServerInput(got, "auto", nil, "", nil)
	if err != nil || res.AuthToken != "REALKEY1" || strings.Contains(res.ServerURL, "REALKEY1") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if _, err := restoreRedactedQueryValues("https://x.example/mcp?key=***", "https://x.example/mcp"); err == nil || !strings.Contains(err.Error(), "脱敏占位符") {
		t.Fatalf("unrestorable placeholder must be rejected: %v", err)
	}
	// 无占位符：原样返回。
	if got, err := restoreRedactedQueryValues("https://x.example/mcp?a=1", "https://old.example"); err != nil || got != "https://x.example/mcp?a=1" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestMCPServerViewRedactsURLAndSummarizesUpstream(t *testing.T) {
	s := &repository.MCPServer{
		ServerURL: "https://mcp.amap.com/mcp?key=LEAKME99&lang=zh", Transport: "auto",
		Capabilities: map[string]interface{}{"detected_transport": "streamable_http", "protocol_version": "2025-11-25",
			"upstream_auth_location": "query", "upstream_auth_query_param": "key"},
	}
	b, _ := json.Marshal(newMCPServerView(s, 3))
	if strings.Contains(string(b), "LEAKME99") {
		t.Fatalf("view leaks URL secret: %s", b)
	}
	var out map[string]interface{}
	_ = json.Unmarshal(b, &out)
	up := out["upstream"].(map[string]interface{})
	if up["effective_transport"] != "streamable_http" || up["auth_location"] != "query" || up["url_has_plaintext_secret"] != true ||
		out["server_url"] != "https://mcp.amap.com/mcp?key=***&lang=zh" {
		t.Fatalf("view=%s", b)
	}
}
