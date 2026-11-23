package handler

// 对抗式审查（2026-10-19）回归测试。每条先写后确认失败，再修复。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpconfirmation"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream/mcpprofiletest"
)

// A. 并发会话额度泄漏：临时调用、失败的 initialize 归还额度后，同一主体不会被永久锁死。
func TestAdvReviewA_EphemeralCallsDoNotLeakPerPrincipalQuota(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	limit := env.handler.sseBridge.maxPerPrin
	for i := 0; i < limit+3; i++ {
		w := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), nil) // 无会话头：临时会话
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"echo"`) {
			t.Fatalf("ephemeral call #%d must succeed (limit=%d): %d %s", i+1, limit, w.Code, w.Body.String())
		}
	}
	if n := env.handler.sseBridge.quotaInUse(); n != 0 {
		t.Fatalf("all quota must be returned after ephemeral calls, still in use: %d", n)
	}
}

func TestAdvReviewA_FailedInitializeReturnsQuota(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "amap-style", caseIndex: 1, secret: "WRONG-KEY-111111"})
	limit := env.handler.sseBridge.maxPerPrin
	for i := 0; i < limit+3; i++ {
		w := env.do(t, http.MethodPost, bridgeInitBody, nil)
		if w.Code == http.StatusServiceUnavailable && strings.Contains(w.Body.String(), "mcp_bridge_capacity") {
			t.Fatalf("failed initialize #%d leaked quota and locked the principal out (limit=%d)", i+1, limit)
		}
	}
	if n := env.handler.sseBridge.quotaInUse(); n != 0 {
		t.Fatalf("failed initialize must return all quota, in use: %d", n)
	}
	// 修正密钥后仍能建会话。
	route, _ := env.handler.serverCache.get("tenant_test\x1fmcp_srv1")
	fixed := newBridgeEnv(t, bridgeOpts{profile: "amap-style", caseIndex: 1})
	_ = route
	if w := fixed.do(t, http.MethodPost, bridgeInitBody, nil); w.Code != http.StatusOK {
		t.Fatalf("control: correct key must work: %d", w.Code)
	}
}

// 额度只归还一次：转正后的会话由 remove/reap 归还，重复 release 不会多还。
func TestAdvReviewA_QuotaReturnedExactlyOnce(t *testing.T) {
	b := newMCPSSEBridge()
	b.maxPerPrin = 2
	defer b.Close()
	r1, err := b.reserve("p")
	if err != nil {
		t.Fatal(err)
	}
	r1.Release()
	r1.Release() // 重复调用无副作用
	if b.quotaInUse() != 0 {
		t.Fatalf("double release must not under-count: %d", b.quotaInUse())
	}
	a, _ := b.reserve("p")
	c, _ := b.reserve("p")
	if _, err := b.reserve("p"); err == nil {
		t.Fatal("third reservation must be rejected at the per-principal cap")
	}
	a.Release()
	c.Release()
	if b.quotaInUse() != 0 {
		t.Fatalf("quota leaked: %d", b.quotaInUse())
	}
	// 转正后：Release 不再归还（避免与 remove 重复归还），由 remove 归还一次。
	tok, _ := b.reserve("p")
	sess := &mcpBridgeSession{tenantID: "t", serverID: "s", principal: "p", conn: mcpupstream.NewClosedSSEConnForTest()}
	id, err := b.register(sess, tok)
	if err != nil {
		t.Fatal(err)
	}
	tok.Release() // 转正后调用：必须是空操作
	if b.quotaInUse() != 1 || b.principalQuotaInUse("p") != 1 {
		t.Fatalf("promoted session must keep exactly one unit: global=%d principal=%d", b.quotaInUse(), b.principalQuotaInUse("p"))
	}
	if !b.remove(id, "t", "s", "p") {
		t.Fatal("remove must find the registered session")
	}
	if b.quotaInUse() != 0 || b.principalQuotaInUse("p") != 0 {
		t.Fatalf("remove must return the unit exactly once: global=%d principal=%d", b.quotaInUse(), b.principalQuotaInUse("p"))
	}
}

// B. HITL 重放：ReplayContext 带 MCPSessionID 也必须真正到达上游，且主体取自 replay 记录而不是空主体。
func TestAdvReviewB_ReplayWithMCPSessionIDReachesSSEUpstream(t *testing.T) {
	env, proxy, record := replayEnvOverSSE(t, "downstream-session-id-that-bridge-never-issued")
	completion := proxy.executeApprovedMCPConfirmation(context.Background(), record)
	if completion.Status != "executed" || completion.ErrorCode != "" {
		t.Fatalf("replay must execute: %+v", completion)
	}
	if got := env.ToolCalls(); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("replay with MCPSessionID must reach the upstream exactly once: %v", got)
	}
}

// B. 上游可达，但桥接因容量满而合成 503（请求并未到达上游）：审批单不能被记为 executed/execution_forwarded。
func TestAdvReviewB_ReplayNotForwardedByBridgeIsNotMarkedExecuted(t *testing.T) {
	env, proxy, record := replayEnvOverSSE(t, "")
	proxy.sseBridge.maxSessions = 0 // 桥接拒绝（合成 503），上游本身完全可达
	completion := proxy.executeApprovedMCPConfirmation(context.Background(), record)
	if completion.Status == "executed" {
		t.Fatalf("bridge-rejected replay must not be recorded as executed: %+v", completion)
	}
	if completion.Summary["execution_forwarded"] == true {
		t.Fatalf("execution_forwarded must not be claimed: %+v", completion.Summary)
	}
	if got := env.ToolCalls(); len(got) != 0 {
		t.Fatalf("nothing may reach the upstream: %v", got)
	}
}

// B. 桥接合成的 404/503 等“未转发”响应带内部标记，调用方据此区分。
func TestAdvReviewB_SyntheticNotForwardedResponsesAreMarked(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	route, _ := env.handler.serverCache.get("tenant_test\x1fmcp_srv1")
	req := newMCPTestRequest(rpcBody(2, "tools/list", ""))
	req.Header.Set("Mcp-Session-Id", "no-such-session")
	resp, _, err := env.handler.forwardMCPUpstream(context.Background(), route, req, []byte(rpcBody(2, "tools/list", "")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || !mcpResponseNotForwarded(resp) {
		t.Fatalf("synthetic 404 must be marked not-forwarded: status=%d", resp.StatusCode)
	}
	env.handler.sseBridge.maxSessions = 0
	req2 := newMCPTestRequest(bridgeInitBody)
	resp2, _, _ := env.handler.forwardMCPUpstream(context.Background(), route, req2, []byte(bridgeInitBody))
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable || !mcpResponseNotForwarded(resp2) {
		t.Fatalf("synthetic 503 must be marked not-forwarded: %d", resp2.StatusCode)
	}
}

func replayEnvOverSSE(t *testing.T, mcpSessionID string) (*mcpprofiletest.Instance, *MCPProxyHandler, *mcpConfirmationExecutionRecord) {
	t.Helper()
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-review-replay-key")
	var prof mcpprofiletest.Profile
	for _, p := range mcpprofiletest.All() {
		if p.Name == "legacy-sse-relative-endpoint" {
			prof = p
		}
	}
	inst := prof.Start(t)
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
			_, _ = w.Write([]byte(`{"id":"tool-log-review"}`))
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
		ID: "server-a", TenantID: "tenant-a", Name: "demo", ServerURL: inst.Cases[0].URL, Status: "active",
		Transport: "sse", ProtocolVersion: "2025-11-25", AllowPrivateEgress: true, RouteHash: strings.Repeat("a", 64),
	})
	proxy.targetClientResolver = loopbackResolver()
	body := []byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{"text":"replayed"}}}`)
	record := encryptedMCPExecutionRecord(t, mcpExecutionScopeTestSecret, mcpconfirmation.ReplayContext{
		Version: mcpconfirmation.ReplayContextVersion, TenantID: "tenant-a", ProjectID: "project-a", UserID: "user-a", ClientID: "key-a",
		OperationID: "op-review", TraceID: "trace-review", MCPSessionID: mcpSessionID,
		ServerID: "server-a", ToolName: "echo", ToolCallID: "number:9",
		ProtocolVersion: "2025-11-25", ToolID: "tool-echo",
		SupplyChainRevision: "revision-a", ApprovedSchemaHash: strings.Repeat("b", 64),
		ServerRouteHash: strings.Repeat("a", 64), RequestBody: body,
	})
	return inst, proxy, record
}

var _ = auth.KeyIDKey
var _ = time.Second

// I. 上游心跳/事件不能无限续命：空闲回收只看下游活动；另有会话最大存活时长。
func TestAdvReviewI_UpstreamHeartbeatDoesNotKeepIdleSessionAlive(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "sse-ping-events", caseIndex: 0})
	env.handler.sseBridge.idleTimeout = 120 * time.Millisecond
	_ = bridgeSession(t, env)
	// 上游每 15ms 发一次心跳/注释；下游完全空闲。真实经过时间 > idleTimeout 后必须被回收。
	time.Sleep(350 * time.Millisecond)
	if n := env.handler.sseBridge.reap(time.Now()); n != 1 {
		t.Fatalf("upstream heartbeats must not keep an idle session alive, reaped=%d", n)
	}
}

func TestAdvReviewI_SessionMaxLifetimeEvenWhenActive(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	env.handler.sseBridge.maxLifetime = 150 * time.Millisecond
	sid := bridgeSession(t, env)
	h := map[string]string{"Mcp-Session-Id": sid}
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) { // 持续有下游活动，始终不空闲
		if w := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), h); w.Code != http.StatusOK && w.Code != http.StatusNotFound {
			t.Fatalf("unexpected %d", w.Code)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := env.handler.sseBridge.reap(time.Now()); n < 1 && env.handler.sseBridge.openSessions() != 0 {
		t.Fatalf("session older than max lifetime must be reaped even if constantly used, reaped=%d open=%d", n, env.handler.sseBridge.openSessions())
	}
}

// H. 排队等会话锁期间客户端断开，要能立即退出，而不是一直阻塞到前一个请求结束。
func TestAdvReviewH_QueuedCallReturnsOnContextCancel(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	sid := bridgeSession(t, env)
	route, _ := env.handler.serverCache.get("tenant_test\x1fmcp_srv1")
	// 构造 principal 与 do() 一致
	req := newMCPTestRequest("")
	principal := mcpBridgePrincipal(auth.GetAuthInfo(req))
	sess := env.handler.sseBridge.lookup(sid, "tenant_test", "mcp_srv1", principal, route.RouteHash)
	if sess == nil {
		t.Fatal("session lookup failed")
	}
	if !sess.lock(context.Background()) { // 占住锁，模拟前一个请求还在执行
		t.Fatal("first lock must succeed")
	}
	defer sess.unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- sess.lock(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case got := <-done:
		if got {
			t.Fatal("cancelled waiter must not acquire the lock")
		}
	case <-time.After(time.Second):
		t.Fatal("queued call did not return after context cancel (blocked on callMu)")
	}
}

// J. 会话 id 生成失败要返回错误，而不是静默得到全零 id。
func TestAdvReviewJ_SessionIDGenerationReportsRandError(t *testing.T) {
	old := mcpBridgeRandRead
	mcpBridgeRandRead = func([]byte) (int, error) { return 0, errors.New("entropy exhausted") }
	defer func() { mcpBridgeRandRead = old }()
	if id, err := newMCPBridgeSessionID(); err == nil || id != "" {
		t.Fatalf("rand failure must surface as error, got id=%q err=%v", id, err)
	}
	b := newMCPSSEBridge()
	defer b.Close()
	tok, _ := b.reserve("p")
	if _, err := b.register(&mcpBridgeSession{principal: "p"}, tok); err == nil {
		t.Fatal("register must fail when id generation fails")
	}
	tok.Release()
	if b.quotaInUse() != 0 || b.principalQuotaInUse("p") != 0 {
		t.Fatal("failed registration must still return quota")
	}
}

// F. 桥接 initialize 的协议版本统一走 mcpprotocol.Negotiate：
// 未来版本前向兼容并向下游回写生效版本；过旧版本拒绝；原始版本另存，会话版本取生效值。
func TestAdvReviewF_BridgeInitializeNegotiatesProtocolVersion(t *testing.T) {
	cases := []struct {
		profile string
		wantOK  bool
		want    string
	}{
		{"sse-future-version", true, "2025-11-25"},
		{"sse-ancient-version", false, ""},
	}
	for _, c := range cases {
		t.Run(c.profile, func(t *testing.T) {
			env := newBridgeEnv(t, bridgeOpts{profile: c.profile, caseIndex: 0})
			w := env.do(t, http.MethodPost, bridgeInitBody, nil)
			if !c.wantOK {
				if w.Code < 400 || w.Header().Get("Mcp-Session-Id") != "" || env.handler.sseBridge.openSessions() != 0 {
					t.Fatalf("ancient version must be rejected without creating a session: %d %s", w.Code, w.Body.String())
				}
				if env.handler.sseBridge.quotaInUse() != 0 {
					t.Fatal("rejected initialize must return quota")
				}
				return
			}
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"protocolVersion":"`+c.want+`"`) {
				t.Fatalf("downstream must see the effective version %s, got: %d %s", c.want, w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "2099-01-01") {
				t.Fatalf("raw unknown version must not leak downstream: %s", w.Body.String())
			}
			sid := w.Header().Get("Mcp-Session-Id")
			route, _ := env.handler.serverCache.get("tenant_test\x1fmcp_srv1")
			principal := mcpBridgePrincipal(auth.GetAuthInfo(newMCPTestRequest("")))
			sess := env.handler.sseBridge.lookup(sid, "tenant_test", "mcp_srv1", principal, route.RouteHash)
			if sess == nil || sess.protocol != c.want || sess.protocolRaw != "2099-01-01" {
				t.Fatalf("session must store effective+raw versions: %+v", sess)
			}
		})
	}
}

// E. 会话 lookup 发现路由指纹（含配置/密钥）已变更时，立即关闭对应上游连接并归还额度，
// 而不是等到空闲回收；旧会话 id 之后返回 404。
func TestAdvReviewE_StaleRouteHashSessionIsClosedAndQuotaReturned(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	sid := bridgeSession(t, env)
	if env.handler.sseBridge.openSessions() != 1 || env.upstream.OpenStreams() != 1 {
		t.Fatal("precondition: one live session")
	}
	// 管理员改了上游配置 → 路由指纹变化（缓存失效后网关读到新指纹）。
	route, _ := env.handler.serverCache.get("tenant_test\x1fmcp_srv1")
	route.RouteHash = strings.Repeat("c", 64)
	w := env.do(t, http.MethodPost, rpcBody(7, "tools/list", ""), map[string]string{"Mcp-Session-Id": sid})
	if w.Code != http.StatusNotFound {
		t.Fatalf("a session bound to a stale route must be rejected: %d %s", w.Code, w.Body.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for env.upstream.OpenStreams() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if env.upstream.OpenStreams() != 0 {
		t.Fatalf("stale session's upstream stream must be closed immediately, still open: %d", env.upstream.OpenStreams())
	}
	if env.handler.sseBridge.openSessions() != 0 || env.handler.sseBridge.quotaInUse() != 0 {
		t.Fatalf("stale session must be removed and quota returned: sessions=%d quota=%d", env.handler.sseBridge.openSessions(), env.handler.sseBridge.quotaInUse())
	}
	if got := env.upstream.ToolCalls(); len(got) != 0 {
		t.Fatalf("nothing may reach the upstream: %v", got)
	}
}

// E. 服务缓存失效通知（控制面每次同步都会写 mcp_servers 触发它）不能一律踢掉会话，
// 否则定时重同步会让所有桥接会话每小时中断；路由指纹未变时会话必须继续可用。
func TestAdvReviewE_ServerChangedNotificationDoesNotKillHealthySessions(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	sid := bridgeSession(t, env)
	env.handler.handleMCPServerChanged("tenant_test\x1fmcp_srv1")
	// 缓存被失效；模拟下一次请求从库里重新读到同一份路由（指纹未变）。
	env.handler.serverCache.set("tenant_test\x1fmcp_srv1", &mcpServerRoute{
		ID: "mcp_srv1", TenantID: "tenant_test", Name: "demo", ServerURL: env.upstream.Cases[0].URL, Status: "active",
		Transport: "sse", AllowPrivateEgress: true, RouteHash: strings.Repeat("a", 64), Capabilities: map[string]interface{}{},
	})
	w := env.do(t, http.MethodPost, rpcBody(8, "tools/list", ""), map[string]string{"Mcp-Session-Id": sid})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"echo"`) {
		t.Fatalf("an unchanged route must keep its session across cache invalidation: %d %s", w.Code, w.Body.String())
	}
	if env.handler.sseBridge.openSessions() != 1 {
		t.Fatal("session must still be registered")
	}
}
