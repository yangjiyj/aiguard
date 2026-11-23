package handler

// 复审 High-1：重复的 Mcp-Session-Id 可绕过归属校验。校验用 Header.Get 只看第一个值，而 copyHeaders 会把所有值转发给上游，
// 于是「第一个是自己的合法会话、第二个是别人的」时，上游实际收到并采用的可能是第二个。
// 现在：多值一律 400 且不转发；转发时只发出校验通过的那个值。关键头 MCP-Protocol-Version 同样「多值即拒」。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func doAsKeyMulti(env *bridgeEnv, keyID, method, body string, set map[string]string, add map[string][]string) *httptest.ResponseRecorder {
	req := newMCPTestRequest(body)
	req.Method = method
	for k, v := range set {
		req.Header.Set(k, v)
	}
	for k, vs := range add {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req = req.WithContext(withKeyID(req.Context(), keyID))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	return w
}

func TestHigh1_DuplicateSessionIdHeadersAreRejectedAndNeverForwarded(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	mine := initSession(t, env, "key-a")
	victim := initSession(t, env, "key-b") // 受害者的合法会话
	before := up.hitCount()

	w := doAsKeyMulti(env, "key-a", http.MethodPost, sessCall, nil,
		map[string][]string{"Mcp-Session-Id": {mine, victim}}) // 第一个是自己的，第二个是别人的
	if w.Code != http.StatusBadRequest {
		t.Fatalf("重复的 Mcp-Session-Id 必须 400，实际 %d %s", w.Code, w.Body.String())
	}
	if up.hitCount() != before {
		t.Fatalf("多值会话头的请求不得到达上游")
	}
	// 顺序颠倒也一样
	w = doAsKeyMulti(env, "key-a", http.MethodPost, sessCall, nil,
		map[string][]string{"Mcp-Session-Id": {victim, mine}})
	if w.Code != http.StatusBadRequest || up.hitCount() != before {
		t.Fatalf("顺序颠倒同样必须拒绝: %d", w.Code)
	}
	// 审计：未转发
	found := false
	for _, l := range env.logs() {
		if l["tool_name"] == "demo__echo" && l["execution_forwarded"] == false {
			found = true
		}
	}
	if !found {
		t.Fatalf("被拒的 tools/call 也必须有 execution_forwarded=false 的审计行: %#v", env.logs())
	}
}

func TestHigh1_OnlyTheValidatedSessionIdReachesUpstream(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	sid := initSession(t, env, "key-a")
	// 单值时上游收到的恰是校验通过的那一个，且只有一个值
	var got []string
	up.onRequest = func(r *http.Request) { got = r.Header.Values("Mcp-Session-Id") }
	w := doAsKey(env, "key-a", http.MethodPost, sessCall, map[string]string{"Mcp-Session-Id": sid})
	if w.Code != http.StatusOK {
		t.Fatalf("合法单值会话: %d", w.Code)
	}
	if len(got) != 1 || got[0] != sid {
		t.Fatalf("上游应只收到校验通过的会话 id %q，实际 %v", sid, got)
	}
}

func TestHigh1_DuplicateProtocolVersionHeadersAreRejected(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	before := up.hitCount()
	w := doAsKeyMulti(env, "key-a", http.MethodPost, sessInit, nil,
		map[string][]string{"MCP-Protocol-Version": {"2025-11-25", "2024-11-05"}})
	if w.Code != http.StatusBadRequest && !strings.Contains(w.Body.String(), "error") {
		t.Fatalf("重复的 MCP-Protocol-Version 必须被拒: %d %s", w.Code, w.Body.String())
	}
	if up.hitCount() != before {
		t.Fatalf("重复协议版本头的请求不得到达上游")
	}
}

func TestHigh1_DeleteAndGetWithDuplicateSessionIdAreRejected(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	mine := initSession(t, env, "key-a")
	victim := initSession(t, env, "key-b")
	before := up.hitCount()
	for _, m := range []string{http.MethodDelete, http.MethodGet} {
		w := doAsKeyMulti(env, "key-a", m, "", map[string]string{"MCP-Protocol-Version": "2025-11-25"},
			map[string][]string{"Mcp-Session-Id": {mine, victim}})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s 带重复会话头必须 400: %d %s", m, w.Code, w.Body.String())
		}
	}
	if up.hitCount() != before {
		t.Fatalf("不得转发")
	}
	// 受害者的会话没有被误删
	if w := doAsKey(env, "key-b", http.MethodPost, sessCall, map[string]string{"Mcp-Session-Id": victim}); w.Code != http.StatusOK {
		t.Fatalf("受害者会话应仍然有效: %d", w.Code)
	}
}

func TestHigh1_BridgePathRejectsDuplicateSessionIdToo(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	w := doAsKeyMulti(env, "key-a", http.MethodPost, sessCall, nil,
		map[string][]string{"Mcp-Session-Id": {"mcpgw-a", "mcpgw-b"}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("SSE 桥接路径同样必须拒绝重复会话头: %d %s", w.Code, w.Body.String())
	}
}
