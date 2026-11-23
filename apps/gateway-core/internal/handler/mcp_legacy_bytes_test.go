package handler

// 对抗式审查 G：存量 streamable_http 行（含智慧芽、威科先行形态）网关转发字节级兼容。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

func buildLegacyRequest(t *testing.T, caps map[string]interface{}, inboundUA string, headerName string) *http.Request {
	t.Helper()
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "legacy-bytes-key")
	ct, ref, _ := secrets.EncryptProviderSecret("upstream-secret")
	server := &mcpServerRoute{
		ServerURL: "https://mcp.example/rpc?route=saved", Transport: "streamable_http",
		AuthCiphertext: ct, AuthKeyRef: ref, AuthHeaderName: headerName, Capabilities: caps,
	}
	in := httptest.NewRequest(http.MethodPost, "/mcp/s1", strings.NewReader(`{}`))
	if inboundUA != "" {
		in.Header.Set("User-Agent", inboundUA)
	}
	in.Header.Set("Mcp-Session-Id", "s-1")
	in.Header.Set("MCP-Protocol-Version", "2025-11-25")
	out, err := buildMCPUpstreamRequest(context.Background(), server, in, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func headerDump(h http.Header) string {
	var keys []string
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + strings.Join(h[k], "|") + ";")
	}
	return b.String()
}

// G. 存量行：下游带 UA 就透传下游 UA；下游没带 UA 时不得凭空出现 JJDGuard-MCP UA（保持原有行为）。
func TestAdvReviewG_LegacyRowKeepsDownstreamUserAgentBehaviour(t *testing.T) {
	out := buildLegacyRequest(t, nil, "Cursor/1.2 (client)", "")
	if got := out.Header.Get("User-Agent"); got != "Cursor/1.2 (client)" {
		t.Fatalf("legacy row must pass the downstream UA through unchanged, got %q", got)
	}
	out = buildLegacyRequest(t, nil, "", "")
	if ua := out.Header.Get("User-Agent"); strings.Contains(ua, "JJDGuard-MCP") {
		t.Fatalf("legacy row without downstream UA must not gain the product UA, got %q", ua)
	}
	// 存量 capabilities 只有 protocol_version（控制面既有字段）时同样视为存量。
	out = buildLegacyRequest(t, map[string]interface{}{"protocol_version": "2025-11-25"}, "", "")
	if ua := out.Header.Get("User-Agent"); strings.Contains(ua, "JJDGuard-MCP") {
		t.Fatalf("a row whose only capability is protocol_version is still legacy: %q", ua)
	}
}

// G. 显式配置了新字段的行（或 sse 桥接）才使用统一 UA；额外请求头生效。
func TestAdvReviewG_NewCapabilityRowsUseProductUserAgent(t *testing.T) {
	out := buildLegacyRequest(t, map[string]interface{}{"upstream_extra_headers": map[string]interface{}{"Stripe-Account": "acct_1"}}, "Cursor/1.2", "")
	if got := out.Header.Get("User-Agent"); !strings.HasPrefix(got, "JJDGuard-MCP/") {
		t.Fatalf("rows with new capability fields use the product UA, got %q", got)
	}
	if out.Header.Get("Stripe-Account") != "acct_1" {
		t.Fatal("extra header must be applied")
	}
	out = buildLegacyRequest(t, map[string]interface{}{"upstream_auth_location": "query", "upstream_auth_query_param": "key"}, "", "")
	if !strings.HasPrefix(out.Header.Get("User-Agent"), "JJDGuard-MCP/") {
		t.Fatal("query-auth rows use the product UA")
	}
}

// G. 字节级一致：存量行转发的请求头集合与改造前逐项相同（以 main 上的实现为基准，固化期望值）。
func TestAdvReviewG_LegacyForwardedHeadersAreExactlyThePreRefactorSet(t *testing.T) {
	out := buildLegacyRequest(t, map[string]interface{}{"protocol_version": "2025-11-25"}, "Cursor/1.2", "")
	// 与改造前（main 7d7b4e885 实测基准）相比，唯一的差异是 Accept-Encoding: identity——这是验收缺陷 D2 有意的、
	// 修复所必需的存量行为变化：下游带 Accept-Encoding: gzip 时，原先该头被透传给上游，上游回压缩体而网关按 JSON
	// 校验导致 502。其余头（含透传的下游 User-Agent、鉴权头、会话与协议版本头）逐项不变。
	want := "Accept=application/json, text/event-stream;Accept-Encoding=identity;Authorization=Bearer upstream-secret;Content-Type=application/json;" +
		"Mcp-Protocol-Version=2025-11-25;Mcp-Session-Id=s-1;User-Agent=Cursor/1.2;"
	if got := headerDump(out.Header); got != want {
		t.Fatalf("legacy forwarded header set changed:\n got: %s\nwant: %s", got, want)
	}
	if out.URL.RawQuery != "route=saved" {
		t.Fatalf("legacy URL query changed: %q", out.URL.RawQuery)
	}
	// 自定义头名（存量 X-MCP-Token）：值原样，不带 Bearer。
	out = buildLegacyRequest(t, nil, "", "X-MCP-Token")
	if out.Header.Get("X-Mcp-Token") != "upstream-secret" || out.Header.Get("Authorization") != "" {
		t.Fatalf("custom header legacy behaviour changed: %v", out.Header)
	}
}

// G. 存量行里已存的鉴权头名即使落在新增黑名单里，网关转发时仍可用（只对新建/修改保存做校验）。
func TestAdvReviewG_StoredAuthHeaderNameStillWorksAtRuntime(t *testing.T) {
	for _, name := range []string{"Accept", "User-Agent", "Te", "Upgrade", "Expect", "Keep-Alive", "Trailer"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("JJD_PROVIDER_SECRET_KEY", "legacy-bytes-key2")
			ct, ref, _ := secrets.EncryptProviderSecret("stored-secret")
			server := &mcpServerRoute{ServerURL: "https://mcp.example/rpc", Transport: "streamable_http",
				AuthCiphertext: ct, AuthKeyRef: ref, AuthHeaderName: name}
			in := httptest.NewRequest(http.MethodPost, "/mcp/s1", strings.NewReader(`{}`))
			out, err := buildMCPUpstreamRequest(context.Background(), server, in, []byte(`{}`))
			if err != nil {
				t.Fatalf("stored header name %q must keep working (legacy), got: %v", name, err)
			}
			if got := out.Header.Get(name); got != "stored-secret" {
				t.Fatalf("stored header %q must carry the secret, got %q", name, got)
			}
		})
	}
}
