package handler

// R2：通知（没有 id 的 JSON-RPC）按 MCP 规范不需要响应体。上游对通知回了非 2xx 且没有合法 Content-Type 时，
// 网关此前返回 502「MCP 上游返回了不受支持的 Content-Type」，把 Content-Type 校验失败当成了报错原因。
// 现在：通知类请求的上游响应不再做 JSON / Content-Type 校验；2xx 一律回下游 202；4xx/5xx 透传状态码，
// body 为空或带脱敏摘要的 JSON 错误；审计照常写；Streamable 和 SSE 桥接两条路径都覆盖。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const notifInitialized = `{"jsonrpc":"2.0","method":"notifications/initialized"}`

// mixed 画像：对通知回 404 + text/plain（Go 的 http.NotFound）。这正是验收环境里复现 502 的上游。
func TestR2_Streamable404NotificationIsNotReportedAsUnsupportedContentType(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "streamable-mixed", caseIndex: 0})
	// 先走真实 initialize 取得会话（mixed 的会话头大小写混用），再发 initialized 通知。
	init := env.do(t, http.MethodPost, sessInit, nil)
	sid := init.Header().Get("Mcp-Session-Id")
	if init.Code != http.StatusOK || sid == "" {
		t.Fatalf("前置：initialize 失败 %d sid=%q", init.Code, sid)
	}
	w := env.do(t, http.MethodPost, notifInitialized, map[string]string{"Mcp-Session-Id": sid})
	if strings.Contains(w.Body.String(), "Content-Type") {
		t.Fatalf("通知收到上游 404 时，不得把 Content-Type 校验失败当报错原因: %d %q", w.Code, w.Body.String())
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("上游 4xx 应透传给下游（通知无响应体）: %d %q", w.Code, w.Body.String())
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "404 page not found") {
		t.Fatalf("不应把上游的原始 text/plain 响应体原样透传: %q", w.Body.String())
	}
}

func notifUpstream(t *testing.T, status int, contentType, body string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestR2_NotificationStatusMatrixOnStreamable(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        int
	}{
		{"200 无 Content-Type 无 body", 200, "", "", 202},
		{"200 text/plain", 200, "text/plain", "ok", 202},
		{"200 非法 JSON body", 200, "application/json", "{not json", 202},
		{"202", 202, "", "", 202},
		{"204", 204, "", "", 202},
		{"404 text/plain", 404, "text/plain", "404 page not found", 404},
		{"400 无 Content-Type", 400, "", "bad", 400},
		{"500 html", 500, "text/html", "<html>boom</html>", 502},
		{"503 无 Content-Type", 503, "", "", 502},
	}
	for _, c := range cases {
		up := notifUpstream(t, c.status, c.contentType, c.body)
		env := newGzipProxyEnv(t, up.URL)
		w := env.do(t, http.MethodPost, notifInitialized, nil)
		if w.Code != c.want {
			t.Fatalf("%s：下游期望 %d，实际 %d %q", c.name, c.want, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "Content-Type") {
			t.Fatalf("%s：不得以 Content-Type 校验失败作为原因: %q", c.name, w.Body.String())
		}
		if c.want == 202 && w.Body.Len() != 0 {
			t.Fatalf("%s：202 通知应答不带 body: %q", c.name, w.Body.String())
		}
	}
}

func TestR2_NotificationErrorBodyNeverEchoesUpstreamContent(t *testing.T) {
	up := notifUpstream(t, 500, "text/plain", "internal: db at 10.1.2.3:5432 password=hunter2")
	env := newGzipProxyEnv(t, up.URL)
	w := env.do(t, http.MethodPost, notifInitialized, nil)
	if strings.Contains(w.Body.String(), "hunter2") || strings.Contains(w.Body.String(), "10.1.2.3") {
		t.Fatalf("上游错误原文含内部信息，不得透传: %q", w.Body.String())
	}
}

func TestR2_NotificationAuditIsStillWrittenWithRealOutcome(t *testing.T) {
	up := notifUpstream(t, 404, "text/plain", "nope")
	env := newGzipProxyEnv(t, up.URL)
	db := &execRecordingAuditDB{fakeMCPAuditDB: *newFakeAuditDB()}
	env.handler.auditRecorder = &mcpProxyAuditRecorder{db: db}
	_ = env.do(t, http.MethodPost, notifInitialized, nil)
	if db.tx.execedSQL == nil || len(db.tx.execedSQL) == 0 {
		t.Fatalf("通知请求也必须写 request_logs 审计")
	}
	// 上游 404 → 审计记为 failed，状态码 404
	args := db.tx.execedArgs[0]
	if args[8] != "failed" || args[9] != http.StatusNotFound {
		t.Fatalf("审计应如实记 failed/404，实际 status=%v code=%v", args[8], args[9])
	}
	// 成功通知记 success
	up2 := notifUpstream(t, 202, "", "")
	env2 := newGzipProxyEnv(t, up2.URL)
	db2 := &execRecordingAuditDB{fakeMCPAuditDB: *newFakeAuditDB()}
	env2.handler.auditRecorder = &mcpProxyAuditRecorder{db: db2}
	_ = env2.do(t, http.MethodPost, notifInitialized, nil)
	if a := db2.tx.execedArgs[0]; a[8] != "success" {
		t.Fatalf("2xx 通知应记 success: %v", a[8])
	}
}

// 带 id 的请求（非通知）的 Content-Type 校验保持不变。
func TestR2_RequestsWithIdStillRequireJSONContentType(t *testing.T) {
	up := notifUpstream(t, 200, "text/plain", "hello")
	env := newGzipProxyEnv(t, up.URL)
	w := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "Content-Type") {
		t.Fatalf("带 id 的请求仍须校验 Content-Type: %d %q", w.Code, w.Body.String())
	}
}

// SSE 桥接路径：上游消息端点对通知回非 2xx。
func TestR2_BridgeNotificationUpstreamNon2xxIsNotA502ContentTypeError(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	init := env.do(t, http.MethodPost, sessInit, nil)
	sid := init.Header().Get("Mcp-Session-Id")
	if init.Code != http.StatusOK || sid == "" {
		t.Fatalf("前置：桥接 initialize 失败 %d", init.Code)
	}
	env.upstream.SetMessageStatus(http.StatusNotFound) // 消息端点之后对任何 POST 回 404
	w := env.do(t, http.MethodPost, notifInitialized, map[string]string{"Mcp-Session-Id": sid})
	if strings.Contains(w.Body.String(), "Content-Type") {
		t.Fatalf("桥接通知：不得以 Content-Type 校验失败作为原因: %d %q", w.Code, w.Body.String())
	}
	if w.Code != http.StatusNotFound && w.Code != http.StatusBadGateway {
		t.Fatalf("桥接通知收到上游 404 应透传或映射为 4xx/502: %d %q", w.Code, w.Body.String())
	}
	if w.Code == http.StatusBadGateway && !strings.Contains(w.Body.String(), "通知") {
		t.Fatalf("映射为 502 时应说明是通知投递失败，而不是笼统的上游无效: %q", w.Body.String())
	}
}

func TestR2_BridgeNotificationSuccessStays202(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	init := env.do(t, http.MethodPost, sessInit, nil)
	sid := init.Header().Get("Mcp-Session-Id")
	w := env.do(t, http.MethodPost, notifInitialized, map[string]string{"Mcp-Session-Id": sid})
	if w.Code != http.StatusAccepted || w.Body.Len() != 0 {
		t.Fatalf("桥接通知成功应回 202 空体: %d %q", w.Code, w.Body.String())
	}
}
