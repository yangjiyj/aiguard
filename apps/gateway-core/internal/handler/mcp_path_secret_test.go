package handler

// 鉴权位置 path：网关代理（Streamable 与 SSE 桥接两种）、HITL 重放、错误 / 审计 / 缓存里无密钥。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream/mcpprofiletest"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

func newPathSecretEnv(t *testing.T, caseIndex int, opts bridgeOpts) *bridgeEnv {
	t.Helper()
	opts.profile, opts.caseIndex = "path-secret", caseIndex
	opts.secret = mcpprofiletest.PathSecretValue()
	return newBridgeEnv(t, opts)
}

func assertNoPathSecretIn(t *testing.T, where, text string) {
	t.Helper()
	sec := mcpprofiletest.PathSecretValue()
	for _, leak := range []string{sec, url.PathEscape(sec), url.QueryEscape(sec), "tok/en", "tok%2Fen", "100%25"} {
		if strings.Contains(text, leak) {
			t.Fatalf("%s leaks the path secret (%q): %s", where, leak, text)
		}
	}
}

// Streamable 上游：initialize / tools/list / tools/call 全链路成功；密钥以单个编码路径段送达。
func TestPathSecretGatewayStreamableChain(t *testing.T) {
	env := newPathSecretEnv(t, 0, bridgeOpts{caps: map[string]interface{}{"detected_transport": "streamable_http"}})
	h := map[string]string{"Accept": "application/json, text/event-stream"}
	w := env.do(t, http.MethodPost, bridgeInitBody, h)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"result"`) {
		t.Fatalf("initialize: %d %s", w.Code, w.Body.String())
	}
	if sid := w.Header().Get("Mcp-Session-Id"); sid != "" {
		h["Mcp-Session-Id"] = sid
	}
	h["MCP-Protocol-Version"] = "2025-06-18"
	if l := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), h); l.Code != http.StatusOK || !strings.Contains(l.Body.String(), `"tools"`) {
		t.Fatalf("tools/list: %d %s", l.Code, l.Body.String())
	}
	c := env.do(t, http.MethodPost, rpcBody(3, "tools/call", `{"name":"echo","arguments":{"text":"你好"}}`), h)
	if c.Code != http.StatusOK || !strings.Contains(c.Body.String(), "echo: 你好") {
		t.Fatalf("tools/call: %d %s", c.Code, c.Body.String())
	}
	want := "/mcp/" + url.PathEscape(mcpprofiletest.PathSecretValue()) + "/"
	for _, r := range env.upstream.Requests() {
		if !strings.HasPrefix(r.EscapedPath, want) || strings.Count(r.EscapedPath, "/") != 3 {
			t.Fatalf("secret must arrive as one encoded segment: %q", r.EscapedPath)
		}
	}
	assertNoPathSecretIn(t, "downstream response", w.Body.String()+c.Body.String())
}

// SSE 桥接：下游 Streamable，上游旧 SSE，密钥在路径里；GET 与 POST endpoint 都带密钥段。
func TestPathSecretGatewaySSEBridgeChain(t *testing.T) {
	env := newPathSecretEnv(t, 1, bridgeOpts{caps: map[string]interface{}{"detected_transport": "sse"}})
	sid := bridgeSession(t, env)
	h := map[string]string{"Mcp-Session-Id": sid}
	if l := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), h); l.Code != http.StatusOK || !strings.Contains(l.Body.String(), `"tools"`) {
		t.Fatalf("tools/list: %d %s", l.Code, l.Body.String())
	}
	c := env.do(t, http.MethodPost, rpcBody(3, "tools/call", `{"name":"echo","arguments":{"text":"桥接"}}`), h)
	if c.Code != http.StatusOK || !strings.Contains(c.Body.String(), "echo: 桥接") {
		t.Fatalf("tools/call: %d %s", c.Code, c.Body.String())
	}
	want := "/mcp/" + url.PathEscape(mcpprofiletest.PathSecretValue()) + "/"
	var gets, posts int
	for _, r := range env.upstream.Requests() {
		if !strings.HasPrefix(r.EscapedPath, want) {
			t.Fatalf("every upstream request must carry the encoded secret segment: %s %q", r.Method, r.EscapedPath)
		}
		if r.Method == http.MethodGet {
			gets++
		} else {
			posts++
		}
	}
	if gets != 1 || posts < 4 {
		t.Fatalf("one SSE stream and several POSTs expected: gets=%d posts=%d", gets, posts)
	}
}

// 红线 / 拦截在 path 鉴权的桥接路径上照旧生效：上游收不到请求。
func TestPathSecretRedlineStillBlockedOnBridge(t *testing.T) {
	env := newPathSecretEnv(t, 1, bridgeOpts{caps: map[string]interface{}{"detected_transport": "sse"}})
	// 2.9.22：元数据不再是内置底线，这里把云元数据红线配成阻断。
	bridgeSetRedlineBlock(env, "cloud_metadata")
	sid := bridgeSession(t, env)
	before := len(env.upstream.Requests())
	w := env.do(t, http.MethodPost, rpcBody(7, "tools/call", `{"name":"fetch","arguments":{"url":"http://169.254.169.254/latest/meta-data/iam"}}`), map[string]string{"Mcp-Session-Id": sid})
	if rpcErrorCode(t, w.Body.String()) != -32000 || len(env.upstream.ToolCalls()) != 0 {
		t.Fatalf("redline must block before the upstream: %s calls=%v", w.Body.String(), env.upstream.ToolCalls())
	}
	for _, r := range env.upstream.Requests()[before:] {
		if strings.Contains(string(r.Body), "169.254.169.254") {
			t.Fatal("redline payload reached the upstream")
		}
	}
}

// 错误响应 / 审计 / 缓存的路由结构：不含真实密钥，server_url 只有占位形式。
func TestPathSecretErrorsAndAuditHoldNoSecret(t *testing.T) {
	// 密钥错误：上游 401，网关错误体不含密钥。
	env := newBridgeEnv(t, bridgeOpts{profile: "path-secret", caseIndex: 0, secret: "wrong/secret 1",
		caps: map[string]interface{}{"detected_transport": "streamable_http"}})
	w := env.do(t, http.MethodPost, bridgeInitBody, map[string]string{"Accept": "application/json, text/event-stream"})
	assertNoPathSecretIn(t, "error body", w.Body.String())
	if strings.Contains(w.Body.String(), "wrong/secret") || strings.Contains(w.Body.String(), "wrong%2Fsecret") {
		t.Fatalf("error body leaks the configured secret: %s", w.Body.String())
	}
	route, _ := env.handler.serverCache.get("tenant_test\x1fmcp_srv1")
	if !strings.Contains(route.ServerURL, "secret") || strings.Contains(route.ServerURL, "wrong") {
		t.Fatalf("cached route URL must stay in placeholder form: %s", route.ServerURL)
	}
	// 审计里的 TargetHost / TargetPath 不含密钥。
	req := newMCPTestRequest("")
	rec := env.handler.newMCPAuditRecord(nil, route, req, 0, 0, "failed", 0, 0)
	assertNoPathSecretIn(t, "audit record", rec.TargetHost+rec.TargetPath)
}

// 构造请求：密钥含空格 / 中文 / 斜杠时路径模式仍可用（头值约束只对 header 模式适用）；控制字符仍拒绝。
func TestPathSecretAllowsCharsThatAreInvalidAsHeaderValues(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "path-secret-gw-key")
	ct, ref, _ := secrets.EncryptProviderSecret("带空格和 中文/slash")
	server := &mcpServerRoute{ServerURL: "https://x.example/mcp/{secret}/sse", Transport: "sse",
		AuthCiphertext: ct, AuthKeyRef: ref, Capabilities: map[string]interface{}{"upstream_auth_location": "path"}}
	in := httptest.NewRequest(http.MethodPost, "/mcp/s1", strings.NewReader(`{}`))
	out, err := buildMCPUpstreamRequest(context.Background(), server, in, []byte(`{}`))
	if err != nil {
		t.Fatalf("path mode must not apply header-value validation to the secret: %v", err)
	}
	if strings.Count(out.URL.EscapedPath(), "/") != 3 || strings.Contains(out.URL.EscapedPath(), "{") {
		t.Fatalf("secret must be substituted as one encoded segment: %s", out.URL.EscapedPath())
	}
	if out.Header.Get("Authorization") != "" {
		t.Fatal("path mode must not add an Authorization header")
	}
	if out.URL.RawQuery != "" {
		t.Fatalf("no query may appear: %q", out.URL.RawQuery)
	}
	// 控制字符（如制表符、换行）仍然拒绝：这是对注入的通用护栏，路径模式也不放宽。
	badCT, badRef, _ := secrets.EncryptProviderSecret("含\t制表符")
	ctl := *server
	ctl.AuthCiphertext, ctl.AuthKeyRef = badCT, badRef
	if _, err := buildMCPUpstreamRequest(context.Background(), &ctl, in, []byte(`{}`)); err == nil {
		t.Fatal("control characters in the secret must still be rejected")
	}
	// 缺密钥：fail-closed，且不回显 URL。
	bare := *server
	bare.AuthCiphertext = ""
	if _, err := buildMCPUpstreamRequest(context.Background(), &bare, in, []byte(`{}`)); err == nil || strings.Contains(err.Error(), "x.example") {
		t.Fatalf("a path-mode server without a secret must fail closed without echoing the URL: %v", err)
	}
}

// 上游不可达时 client.Do 返回的 *url.Error 带有真实请求 URL（含路径密钥）：任何对外错误都不得带出。
func TestPathSecretDialErrorDoesNotEchoRealURL(t *testing.T) {
	env := newPathSecretEnv(t, 0, bridgeOpts{caps: map[string]interface{}{"detected_transport": "streamable_http"}})
	env.upstream.Server.CloseClientConnections()
	env.upstream.Server.Close() // 上游关闭 → 连接被拒，*url.Error 里会带真实 URL
	w := env.do(t, http.MethodPost, bridgeInitBody, map[string]string{"Accept": "application/json, text/event-stream"})
	if w.Code < 400 {
		t.Fatalf("unreachable upstream must fail: %d", w.Code)
	}
	assertNoPathSecretIn(t, "downstream error body", w.Body.String())
	if strings.Contains(w.Body.String(), "/mcp/") {
		t.Fatalf("error body must not echo the upstream path: %s", w.Body.String())
	}
}

// 构造请求失败（例如密钥解出的路径段在替换后让 URL 非法）：返回的错误不得带出替换后的 URL。
func TestPathSecretBuildRequestErrorHasNoURL(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "path-secret-gw-key3")
	ct, ref, _ := secrets.EncryptProviderSecret(mcpprofiletest.PathSecretValue())
	// 方法非法会让 http.NewRequestWithContext 返回错误，错误文本里带 URL。
	server := &mcpServerRoute{ServerURL: "https://x.example/mcp/{secret}/sse", Transport: "sse",
		AuthCiphertext: ct, AuthKeyRef: ref, Capabilities: map[string]interface{}{"upstream_auth_location": "path"}}
	in := httptest.NewRequest(http.MethodPost, "/mcp/s1", strings.NewReader(`{}`))
	in.Method = "BAD METHOD"
	_, err := buildMCPUpstreamRequest(context.Background(), server, in, []byte(`{}`))
	if err == nil {
		t.Fatal("an invalid method must fail")
	}
	assertNoPathSecretIn(t, "build error", err.Error())
	if strings.Contains(err.Error(), "x.example") {
		t.Fatalf("build error must not echo the upstream URL: %v", err)
	}
}

// *url.Error 携带完整 URL 的情形（构造失败的任意来源）经 sanitize 后只剩根因。
func TestPathSecretSanitizeRequestBuildErrorStripsURL(t *testing.T) {
	real := "https://x.example/mcp/" + url.PathEscape(mcpprofiletest.PathSecretValue()) + "/sse"
	err := sanitizeMCPRequestBuildError(&url.Error{Op: "parse", URL: real, Err: errors.New("net/url: invalid control character in URL")})
	assertNoPathSecretIn(t, "sanitized build error", err.Error())
	if strings.Contains(err.Error(), "x.example") || !strings.Contains(err.Error(), "invalid control character") {
		t.Fatalf("only the root cause may remain: %v", err)
	}
}
