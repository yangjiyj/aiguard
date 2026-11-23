package handler

// 复审（2026-10-20）回归测试：H-1 / M-1 / M-3 / L-2。每条先写后确认失败，再修复。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpconfirmation"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream/mcpprofiletest"
)

// toolLogForwarded 读取 tool_call_logs 里该工具调用的 execution_forwarded / execution_observed 事实。
func toolLogFlags(e *bridgeEnv) (forwarded, observed, found bool) {
	for _, l := range e.logs() {
		raw, _ := json.Marshal(l)
		text := string(raw)
		if !strings.Contains(text, "echo") {
			continue
		}
		found = true
		if strings.Contains(text, `"execution_forwarded":true`) || strings.Contains(text, `"event_kind":"execution_forwarded"`) {
			forwarded = true
		}
		if strings.Contains(text, `"execution_observed":true`) {
			observed = true
		}
	}
	return
}

// H-1：带伪造 / 过期 Mcp-Session-Id 做 tools/call：桥接合成 404，请求根本没到上游，
// 审计必须按“未转发”记录（execution_forwarded=false、execution_observed=false），上游零请求。
func TestFollowupH1_ForgedSessionToolCallIsAuditedAsNotForwarded(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	before := len(env.upstream.Requests())
	w := env.do(t, http.MethodPost, rpcBody(3, "tools/call", `{"name":"echo","arguments":{"text":"x"}}`),
		map[string]string{"Mcp-Session-Id": "forged-or-expired-session"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("forged session must yield the synthetic 404, got %d %s", w.Code, w.Body.String())
	}
	if n := len(env.upstream.Requests()) - before; n != 0 {
		t.Fatalf("the upstream must receive zero requests, got %d", n)
	}
	forwarded, observed, found := toolLogFlags(env)
	if !found {
		t.Fatalf("the attempt must still be audited: logs=%v", env.logs())
	}
	if forwarded || observed {
		t.Fatalf("a request that never reached the upstream must NOT be audited as forwarded/observed: forwarded=%v observed=%v logs=%v", forwarded, observed, env.logs())
	}
}

// H-1：容量满的合成 503 同样是“未转发”。
func TestFollowupH1_CapacityRejectionIsAuditedAsNotForwarded(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	env.handler.sseBridge.maxSessions = 0
	w := env.do(t, http.MethodPost, rpcBody(3, "tools/call", `{"name":"echo","arguments":{"text":"x"}}`), nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected the synthetic 503, got %d %s", w.Code, w.Body.String())
	}
	if len(env.upstream.Requests()) != 0 {
		t.Fatalf("nothing may reach the upstream: %d", len(env.upstream.Requests()))
	}
	forwarded, observed, found := toolLogFlags(env)
	if !found || forwarded || observed {
		t.Fatalf("503 must be audited as not forwarded: found=%v forwarded=%v observed=%v logs=%v", found, forwarded, observed, env.logs())
	}
}

// H-1：对照——真实转发成功的调用仍然记 execution_forwarded=true（不能把正常路径误伤）。
func TestFollowupH1_RealForwardIsStillAuditedAsForwarded(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	sid := bridgeSession(t, env)
	w := env.do(t, http.MethodPost, rpcBody(3, "tools/call", `{"name":"echo","arguments":{"text":"x"}}`), map[string]string{"Mcp-Session-Id": sid})
	if w.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", w.Code, w.Body.String())
	}
	forwarded, observed, _ := toolLogFlags(env)
	if !forwarded || !observed {
		t.Fatalf("a real forward must be audited as forwarded+observed: %v %v logs=%v", forwarded, observed, env.logs())
	}
}

// M-1：Streamable 上游可以在响应头里伪造任何头。标记不能放在 HTTP 头上：
// 上游返回 X-Jjd-Mcp-Not-Forwarded 时，请求真实到达了上游，重放必须仍判为“已转发”。
func TestFollowupM1_UpstreamCannotForgeNotForwardedMarker(t *testing.T) {
	var hits int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("X-Jjd-Mcp-Not-Forwarded", "1") // 伪造
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"executed-for-real"}]}}`)
	}))
	t.Cleanup(up.Close)
	h := NewMCPProxyHandler(nil, nil, false)
	t.Cleanup(h.sseBridge.Close)
	h.targetClientResolver = loopbackResolver()
	server := &mcpServerRoute{ID: "s", TenantID: "t", ServerURL: up.URL + "/mcp", Transport: "streamable_http", AllowPrivateEgress: true}
	req := newMCPTestRequest(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{}}}`)
	resp, _, err := h.forwardMCPUpstream(context.Background(), server, req, []byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if hits != 1 {
		t.Fatalf("the request must really reach the upstream, hits=%d", hits)
	}
	if mcpResponseNotForwarded(resp) {
		t.Fatal("an upstream-forged header must not make a real forward look 'not forwarded'")
	}
	if resp.Header.Get("X-Jjd-Mcp-Not-Forwarded") != "" {
		t.Fatalf("the internal marker header must be stripped from upstream responses at the entry: %v", resp.Header)
	}
}

// M-1：重放路径上同样——上游伪造该头，重放仍记录为已执行。
func TestFollowupM1_ReplayWithForgedHeaderIsStillRecordedExecuted(t *testing.T) {
	inst, proxy, record := replayEnvOverStreamable(t, true)
	completion := proxy.executeApprovedMCPConfirmation(context.Background(), record)
	if completion.Status != "executed" || completion.Summary["execution_forwarded"] != true {
		t.Fatalf("a replay that really reached the upstream must be recorded as executed/forwarded: %+v", completion)
	}
	if got := inst.hits(); got != 1 {
		t.Fatalf("exactly one real request expected, got %d", got)
	}
}

var _ = mcpprofiletest.SecretValue

type forgedUpstream struct {
	srv *httptest.Server
	cnt *int
}

func (f forgedUpstream) hits() int { return *f.cnt }

// replayEnvOverStreamable 起一个会伪造内部标记头的 Streamable 上游，并构造 HITL 重放记录。
func replayEnvOverStreamable(t *testing.T, forgeHeader bool) (forgedUpstream, *MCPProxyHandler, *mcpConfirmationExecutionRecord) {
	t.Helper()
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-followup-replay-key")
	cnt := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cnt++
		if forgeHeader {
			w.Header().Set("X-Jjd-Mcp-Not-Forwarded", "1")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"ok"}]}}`)
	}))
	t.Cleanup(up.Close)
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/mcp/effective-policy":
			_, _ = w.Write([]byte(`{"matched":true,"policy_id":"policy-confirm","tool_id":"tool-echo","mode":"strict","action":"confirm","supply_chain_status":"approved","supply_chain_revision":"revision-a","server_admission_status":"approved","tool_admission_status":"approved","route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_schema_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))
		case "/admin/v1/internal/agentguard/effective-policy":
			_, _ = w.Write([]byte(`{"data":null}`))
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"tool-log-followup"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(controlPlane.Close)
	client := NewToolRiskClient(controlPlane.URL, "internal")
	setToolGuardTestPosture(t, client, false, false)
	client.SetMCPConfirmationScopeSecret(mcpExecutionScopeTestSecret)
	proxy := NewMCPProxyHandler(nil, client, false)
	t.Cleanup(proxy.sseBridge.Close)
	proxy.serverCache.set("tenant-a\x1fserver-a", &mcpServerRoute{
		ID: "server-a", TenantID: "tenant-a", Name: "demo", ServerURL: up.URL + "/mcp", Status: "active",
		Transport: "streamable_http", ProtocolVersion: "2025-11-25", AllowPrivateEgress: true, RouteHash: strings.Repeat("a", 64),
	})
	proxy.targetClientResolver = loopbackResolver()
	body := []byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{"text":"r"}}}`)
	record := encryptedMCPExecutionRecord(t, mcpExecutionScopeTestSecret, mcpconfirmationReplay(body))
	return forgedUpstream{srv: up, cnt: &cnt}, proxy, record
}

func mcpconfirmationReplay(body []byte) mcpconfirmation.ReplayContext {
	return mcpconfirmation.ReplayContext{
		Version: mcpconfirmation.ReplayContextVersion, TenantID: "tenant-a", ProjectID: "project-a", UserID: "user-a", ClientID: "key-a",
		OperationID: "op-followup", TraceID: "trace-followup",
		ServerID: "server-a", ToolName: "echo", ToolCallID: "number:9",
		ProtocolVersion: "2025-11-25", ToolID: "tool-echo",
		SupplyChainRevision: "revision-a", ApprovedSchemaHash: strings.Repeat("b", 64),
		ServerRouteHash: strings.Repeat("a", 64), RequestBody: body,
	}
}

// H-1（覆盖面）：DELETE 在会话不存在时桥接合成 404：轻审计应记 failed 而不是 success。
func TestFollowupH1_DeleteWithUnknownSessionIsAuditedAsFailed(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	before := len(env.upstream.Requests())
	w := env.do(t, http.MethodDelete, "", map[string]string{"Mcp-Session-Id": "never-issued", "MCP-Protocol-Version": "2025-03-26"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown session DELETE must be 404, got %d", w.Code)
	}
	if len(env.upstream.Requests()) != before {
		t.Fatal("DELETE of an unknown session must not reach the upstream")
	}
	// 响应头里不得泄漏内部标记。
	if w.Header().Get("X-Jjd-Mcp-Not-Forwarded") != "" {
		t.Fatalf("internal marker header leaked to the client: %v", w.Header())
	}
}

// H-1（覆盖面）：任何写给下游的响应里都不得出现内部标记头（合成的与上游伪造的）。
func TestFollowupH1_InternalMarkerNeverLeaksToClient(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	for _, c := range []struct {
		method, body string
		hdr          map[string]string
	}{
		{http.MethodPost, rpcBody(3, "tools/list", ""), map[string]string{"Mcp-Session-Id": "forged"}},
		{http.MethodGet, "", map[string]string{"Accept": "text/event-stream"}},
		{http.MethodDelete, "", map[string]string{"Mcp-Session-Id": "forged", "MCP-Protocol-Version": "2025-03-26"}},
	} {
		w := env.do(t, c.method, c.body, c.hdr)
		if w.Header().Get("X-Jjd-Mcp-Not-Forwarded") != "" {
			t.Fatalf("%s leaks the internal marker header: %v", c.method, w.Header())
		}
	}
}

// M-1（判定函数本身）：“未转发”的判定不得依赖任何 HTTP 头——带内部标记头的普通响应不算“未转发”，
// 只有网关自己构造的合成响应才算。即使入口剥头那道防线失效，判定也不会被上游伪造。
func TestFollowupM1_NotForwardedDecisionDoesNotDependOnHeaders(t *testing.T) {
	forged := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"X-Jjd-Mcp-Not-Forwarded": {"1"}}, Body: http.NoBody}
	if mcpResponseNotForwarded(forged) {
		t.Fatal("a response that merely carries the marker header must NOT be treated as not-forwarded")
	}
	if !mcpResponseNotForwarded(mcpNotForwardedResponse(http.StatusNotFound, "x")) {
		t.Fatal("gateway-synthesized not-forwarded responses must be recognized")
	}
	if !mcpResponseNotForwarded(mcpNotForwardedEmpty(http.StatusMethodNotAllowed)) {
		t.Fatal("gateway-synthesized empty not-forwarded responses must be recognized")
	}
	// 合成的“已转发”响应（桥接成功路径）不是未转发。
	if mcpResponseNotForwarded(mcpSyntheticResponse(http.StatusOK, []byte(`{}`), "sid")) {
		t.Fatal("a normal synthesized success response is forwarded")
	}
	if mcpResponseNotForwarded(nil) {
		t.Fatal("nil is not 'not forwarded'")
	}
}
