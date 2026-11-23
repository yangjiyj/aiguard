package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type mcpSeenRequest struct{ Version, Session string }

// 把 env 的上游换成能记录 MCP-Protocol-Version 头的 mock，并设置服务器记录的已协商版本。
func useMCPRecordingUpstream(t *testing.T, env *mcpFixEnv, negotiated string) (*[]mcpSeenRequest, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	seen := []mcpSeenRequest{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, mcpSeenRequest{r.Header.Get("MCP-Protocol-Version"), r.Header.Get("Mcp-Session-Id")})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	t.Cleanup(up.Close)
	useMCPTestUpstream(env.handler, up)
	env.handler.serverCache.set("tenant_test\x1fmcp_srv1", &mcpServerRoute{
		ID: "mcp_srv1", TenantID: "tenant_test", Name: "demo", ServerURL: up.URL, Status: "active",
		AllowPrivateEgress: true, RouteHash: strings.Repeat("a", 64), ProtocolVersion: negotiated,
	})
	return &seen, &mu
}

func mcpInitBody(version string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + version + `","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`
}

const mcpToolsListBody = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`

func TestMCPProxyAcceptsInitializeFromEverySupportedClientVersion(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"} {
		t.Run(version, func(t *testing.T) {
			env := newMCPFixEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}, http.StatusOK)
			seen, mu := useMCPRecordingUpstream(t, env, "")
			w := httptest.NewRecorder()
			env.router.ServeHTTP(w, newMCPTestRequest(mcpInitBody(version)))
			if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"error"`) {
				t.Fatalf("initialize %s rejected: %d %s", version, w.Code, w.Body.String())
			}
			mu.Lock()
			defer mu.Unlock()
			if len(*seen) != 1 || (*seen)[0].Version != "" {
				t.Fatalf("initialize 不应带版本头（版本在 params 里协商）: %#v", *seen)
			}
		})
	}
}

func TestMCPProxyRejectsUnknownClientVersions(t *testing.T) {
	for _, tc := range []struct{ name, header, initVersion string }{
		{"init 2023", "", "2023-01-01"},
		{"init garbage", "", "garbage"},
		{"init empty", "", ""},
		{"header 2099", "2099-01-01", "2025-03-26"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newMCPFixEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}, http.StatusOK)
			req := newMCPTestRequest(mcpInitBody(tc.initVersion))
			if tc.header != "" {
				req.Header.Set("MCP-Protocol-Version", tc.header)
			}
			w := httptest.NewRecorder()
			env.router.ServeHTTP(w, req)
			if !strings.Contains(w.Body.String(), `"code":-32600`) || !strings.Contains(w.Body.String(), "不支持的 MCP 协议版本") {
				t.Fatalf("非法版本必须被拒: %d %s", w.Code, w.Body.String())
			}
			if atomic.LoadInt32(env.upstreamHits) != 0 {
				t.Fatal("非法版本不得触达上游")
			}
		})
	}
}

// 2025-06-18 之前的客户端不发 MCP-Protocol-Version：带会话也要放行，并补协商版本转发上游。
func TestMCPProxyLegacyClientWithoutVersionHeaderGetsNegotiatedVersionUpstream(t *testing.T) {
	for _, tc := range []struct{ name, recorded, want string }{
		{"记录为 2024-11-05", "2024-11-05", "2024-11-05"},
		{"记录为 2025-06-18", "2025-06-18", "2025-06-18"},
		{"未记录则取规范默认 2025-03-26", "", "2025-03-26"},
		{"记录值非法也回落默认", "2023-01-01", "2025-03-26"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newMCPFixEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}, http.StatusOK)
			seen, mu := useMCPRecordingUpstream(t, env, tc.recorded)
			registerStreamableTestSession(t, env.handler, "tenant_test", "mcp_srv1", "sess-legacy", "\x1fuser_test\x1fproject_test", strings.Repeat("a", 64))
			req := newMCPTestRequest(mcpToolsListBody)
			req.Header.Set("Mcp-Session-Id", "sess-legacy")
			w := httptest.NewRecorder()
			env.router.ServeHTTP(w, req)
			if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"error"`) {
				t.Fatalf("缺头的旧客户端请求被拒: %d %s", w.Code, w.Body.String())
			}
			mu.Lock()
			defer mu.Unlock()
			if len(*seen) != 1 || (*seen)[0].Version != tc.want || (*seen)[0].Session != "sess-legacy" {
				t.Fatalf("上游应收到 %q: %#v", tc.want, *seen)
			}
		})
	}
}

func TestMCPProxyForwardsClientVersionHeaderUnchanged(t *testing.T) {
	env := newMCPFixEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}, http.StatusOK)
	seen, mu := useMCPRecordingUpstream(t, env, "2025-11-25")
	registerStreamableTestSession(t, env.handler, "tenant_test", "mcp_srv1", "s", "\x1fuser_test\x1fproject_test", strings.Repeat("a", 64))
	req := newMCPTestRequest(mcpToolsListBody)
	req.Header.Set("Mcp-Session-Id", "s")
	req.Header.Set("MCP-Protocol-Version", "2024-11-05")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	mu.Lock()
	defer mu.Unlock()
	if w.Code != http.StatusOK || len(*seen) != 1 || (*seen)[0].Version != "2024-11-05" {
		t.Fatalf("客户端显式声明的版本应原样透传: %d %#v", w.Code, *seen)
	}
}

// batch 保持拒绝：即使客户端声明 2025-03-26（唯一规范允许 batch 的版本）。
func TestMCPProxyBatchStillRejectedForBatchEraVersion(t *testing.T) {
	env := newMCPFixEnv(t, false, MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}, http.StatusOK)
	req := newMCPTestRequest(buildMCPBatch(2, true))
	req.Header.Set("MCP-Protocol-Version", "2025-03-26")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `"code":-32600`) || atomic.LoadInt32(env.upstreamHits) != 0 ||
		atomic.LoadInt32(env.effectivePolicyHits) != 0 {
		t.Fatalf("batch 必须在决策前拒绝: %d %s", w.Code, w.Body.String())
	}
}
