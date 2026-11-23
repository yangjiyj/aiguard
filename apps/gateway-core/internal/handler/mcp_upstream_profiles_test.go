package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream/mcpprofiletest"
)

// 每个厂商画像都经 gateway-core 代理跑完整链路：initialize → tools/list → tools/call。
// 下游始终是 Streamable HTTP；上游可能是 Streamable 或旧 SSE，由 server 配置（transport / auto 探测记录）决定。
// 仅成功类用例：失败类（鉴权失败 / 版本拒绝 / 跨源）的网关侧行为由专项测试覆盖，
// 控制面侧的错误分类见 control-plane 的画像测试。
func TestMCPVendorProfilesThroughGatewayProxy(t *testing.T) {
	for _, p := range mcpprofiletest.All() {
		p := p
		probe := p.Start(t)
		for i, c := range probe.Cases {
			if !c.WantOK {
				continue
			}
			i, c := i, c
			t.Run(p.Name+"/"+c.Name, func(t *testing.T) {
				// auto 且未探测：网关热路径按路径推断；这里按“控制面已同步并记录探测结果”的真实状态给路由。
				caps := map[string]interface{}{}
				if c.Transport == "auto" {
					caps["detected_transport"] = c.WantTransport
				}
				env := newBridgeEnv(t, bridgeOpts{profile: p.Name, caseIndex: i, caps: caps})
				initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`
				w := env.do(t, http.MethodPost, initBody, map[string]string{"Accept": "application/json, text/event-stream"})
				if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"result"`) {
					t.Fatalf("initialize: %d %s", w.Code, w.Body.String())
				}
				headers := map[string]string{"Accept": "application/json, text/event-stream"}
				if sid := w.Header().Get("Mcp-Session-Id"); sid != "" {
					headers["Mcp-Session-Id"] = sid
				}
				// Mcp-Session-Id 由上游签发（Streamable）或网关签发（桥接）；下游原样回传。
				pv := c.WantProtocol
				if c.WantRawProto != "" {
					pv = "2025-11-25"
				}
				headers["MCP-Protocol-Version"] = pv
				_ = env.do(t, http.MethodPost, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, headers)

				list := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), headers)
				if list.Code != http.StatusOK {
					t.Fatalf("tools/list: %d %s", list.Code, list.Body.String())
				}
				body := list.Body.String()
				// Streamable 上游可能以 SSE 回包：取其中 data 行。
				if strings.Contains(list.Header().Get("Content-Type"), "text/event-stream") {
					body = firstSSEData(body)
				}
				var lr struct {
					Result struct {
						Tools      []struct{ Name string } `json:"tools"`
						NextCursor string                  `json:"nextCursor"`
					} `json:"result"`
				}
				if err := json.Unmarshal([]byte(body), &lr); err != nil {
					t.Fatalf("tools/list body %q: %v", body, err)
				}
				// 网关对 tools/list 是逐页透传（翻页由客户端驱动）：首页至少有工具，
				// 或像 pagination-weird 画像那样是“空页 + nextCursor”，此时 nextCursor 必须原样透传。
				if len(lr.Result.Tools) == 0 && lr.Result.NextCursor == "" {
					t.Fatalf("tools/list returned neither tools nor nextCursor: %s", body)
				}

				call := env.do(t, http.MethodPost, rpcBody(3, "tools/call", `{"name":"echo","arguments":{"text":"你好"}}`), headers)
				cb := call.Body.String()
				if strings.Contains(call.Header().Get("Content-Type"), "text/event-stream") {
					cb = firstSSEData(cb)
				}
				if call.Code != http.StatusOK || !strings.Contains(cb, "echo: 你好") || strings.Contains(cb, `"error"`) {
					t.Fatalf("tools/call: %d %s", call.Code, cb)
				}
				if got := env.upstream.ToolCalls(); len(got) != 1 || got[0] != "echo" {
					t.Fatalf("upstream tool calls=%v", got)
				}
				// 统一产品 UA 只用于新能力（sse / auto 传输、query 鉴权、额外请求头等）；
				// 存量 streamable_http 行保持改造前的请求头，不得凭空出现该 UA。
				route, _ := env.handler.serverCache.get("tenant_test\x1fmcp_srv1")
				cfg, _ := route.upstreamConfig()
				for _, r := range env.upstream.Requests() {
					hasProductUA := strings.HasPrefix(r.Header.Get("User-Agent"), "JJDGuard-MCP/")
					if cfg.UsesNewCapabilities && !hasProductUA {
						t.Fatalf("new-capability row must use the product UA: %q", r.Header.Get("User-Agent"))
					}
					if !cfg.UsesNewCapabilities && hasProductUA {
						t.Fatalf("legacy streamable row must not gain the product UA: %q", r.Header.Get("User-Agent"))
					}
					// 下游调用方的凭据（此处为测试请求头）绝不能漏到上游。
					if strings.Contains(r.RawQuery+r.Header.Get("Cookie")+r.Header.Get("X-Api-Key"), "caller") {
						t.Fatalf("caller credential leaked upstream: %+v", r)
					}
				}
			})
		}
	}
}

func firstSSEData(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "data:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
	}
	return body
}

// 存量 streamable_http 服务（客户现网：智慧芽、威科先行；协商 2025-11-25）不受影响：
// capabilities 没有新字段时，网关转发的请求头与改造前一致（Authorization: Bearer，无额外 query，无 GET），
// 且不经桥接（不签发网关会话 id，沿用上游自己的会话语义）。
func TestMCPLegacyStreamableServerUnchangedThroughGateway(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-qianwen-existing-corp", caseIndex: 0})
	route, _ := env.handler.serverCache.get("tenant_test\x1fmcp_srv1")
	route.Capabilities = nil // 存量：没有新字段
	if route.usesSSEBridge() {
		t.Fatal("legacy streamable_http server must not use the SSE bridge")
	}
	w := env.do(t, http.MethodPost, bridgeInitBody, map[string]string{"Accept": "application/json, text/event-stream"})
	if w.Code != http.StatusOK || w.Header().Get("Mcp-Session-Id") != "" && strings.HasPrefix(w.Header().Get("Mcp-Session-Id"), "mcpgw-") {
		t.Fatalf("legacy server must keep upstream-defined session semantics: %d sid=%q", w.Code, w.Header().Get("Mcp-Session-Id"))
	}
	w = env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), map[string]string{"MCP-Protocol-Version": "2025-11-25"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"echo"`) {
		t.Fatalf("tools/list: %d %s", w.Code, w.Body.String())
	}
	for _, r := range env.upstream.Requests() {
		if r.Method != http.MethodPost || r.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+mcpprofiletest.SecretValue() {
			t.Fatalf("legacy forwarding changed: %+v", r)
		}
	}
}

// query 鉴权的 Streamable 上游：下游请求里夹带同名 query（试图覆盖上游密钥）必须被丢弃；
// 上游收到的是管理员配置的密钥，响应与日志不含密钥。
func TestMCPQueryAuthStreamableCallerCannotOverrideUpstreamKey(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "amap-style", caseIndex: 0})
	req := newMCPTestRequest(bridgeInitBody)
	req.URL.RawQuery = "key=caller-supplied&other=1"
	w := httptestRecord(env, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"result"`) {
		t.Fatalf("initialize: %d %s", w.Code, w.Body.String())
	}
	for _, r := range env.upstream.Requests() {
		if strings.Contains(r.RawQuery, "caller-supplied") || !strings.Contains(r.RawQuery, "key="+mcpprofiletest.SecretValue()) {
			t.Fatalf("caller query must not reach/override upstream auth: %q", r.RawQuery)
		}
	}
	if strings.Contains(w.Body.String(), mcpprofiletest.SecretValue()) {
		t.Fatalf("response leaks upstream key: %s", w.Body.String())
	}
}
