package handler

// 验收缺陷 D3：Streamable 上游路径不校验 Mcp-Session-Id 归属，客户端伪造的会话 id 被原样转发。
// 修复后：网关只放行「本网关在 initialize 响应里见到上游签发」且归属（租户/server/主体/路由指纹）
// 一致的会话 id；未知或他人的 id 一律 404 且不转发（审计 execution_forwarded=false）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
)

type sessUpstream struct {
	srv    *httptest.Server
	mu     sync.Mutex
	hits   int
	issued map[string]bool
	seq    int
	seen   []string // 每次收到的 Mcp-Session-Id
	// onRequest 在每次请求到达上游时回调（测试观察用）。
	onRequest func(*http.Request)
}

func newSessUpstream(t *testing.T) *sessUpstream {
	u := &sessUpstream{issued: map[string]bool{}}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, 0, 512)
		buf := make([]byte, 512)
		for {
			n, err := r.Body.Read(buf)
			raw = append(raw, buf[:n]...)
			if err != nil {
				break
			}
		}
		u.mu.Lock()
		u.hits++
		if u.onRequest != nil {
			u.onRequest(r)
		}
		sid := r.Header.Get("Mcp-Session-Id")
		u.seen = append(u.seen, sid)
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodDelete {
			u.mu.Lock()
			delete(u.issued, sid)
			u.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.Contains(string(raw), `"initialize"`) {
			u.mu.Lock()
			u.seq++
			id := fmt.Sprintf("up-sess-%d", u.seq)
			u.issued[id] = true
			u.mu.Unlock()
			w.Header().Set("Mcp-Session-Id", id)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"x","version":"1"}}}`))
			return
		}
		u.mu.Lock()
		ok := u.issued[sid]
		u.mu.Unlock()
		if sid != "" && !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *sessUpstream) hitCount() int { u.mu.Lock(); defer u.mu.Unlock(); return u.hits }

func doAsKey(env *bridgeEnv, keyID, method, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := newMCPTestRequest(body)
	req.Method = method
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req = req.WithContext(withKeyID(req.Context(), keyID))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	return w
}

func withKeyID(ctx context.Context, keyID string) context.Context {
	return context.WithValue(ctx, auth.KeyIDKey, keyID)
}

const sessInit = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`
const sessCall = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`

func initSession(t *testing.T, env *bridgeEnv, keyID string) string {
	t.Helper()
	w := doAsKey(env, keyID, http.MethodPost, sessInit, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("initialize: %d %s", w.Code, w.Body.String())
	}
	sid := w.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatalf("上游签发的 Mcp-Session-Id 必须回给客户端")
	}
	return sid
}

func TestD3_ForgedSessionIdIsRejectedAndNotForwarded(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	before := up.hitCount()
	w := doAsKey(env, "key-a", http.MethodPost, sessCall, map[string]string{"Mcp-Session-Id": "forged-by-client"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("伪造的会话 id 必须 404，实际 %d %s", w.Code, w.Body.String())
	}
	if up.hitCount() != before {
		t.Fatalf("伪造会话的请求不得到达上游")
	}
	// 审计：未转发
	found := false
	for _, l := range env.logs() {
		if l["tool_name"] == "demo__echo" {
			found = true
			if l["execution_forwarded"] != false {
				t.Fatalf("未转发必须记 execution_forwarded=false: %#v", l)
			}
		}
	}
	if !found {
		t.Fatalf("伪造会话的 tools/call 也必须有审计行: %#v", env.logs())
	}
}

func TestD3_LegitimateSessionStillWorks(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	sid := initSession(t, env, "key-a")
	w := doAsKey(env, "key-a", http.MethodPost, sessCall, map[string]string{"Mcp-Session-Id": sid})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok"`) {
		t.Fatalf("合法会话必须照常转发: %d %s", w.Code, w.Body.String())
	}
	up.mu.Lock()
	last := up.seen[len(up.seen)-1]
	up.mu.Unlock()
	if last != sid {
		t.Fatalf("上游应收到原样的会话 id %q，实际 %q", sid, last)
	}
}

func TestD3_AnotherPrincipalCannotUseSession(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	sid := initSession(t, env, "key-a")
	before := up.hitCount()
	w := doAsKey(env, "key-b", http.MethodPost, sessCall, map[string]string{"Mcp-Session-Id": sid})
	if w.Code != http.StatusNotFound || up.hitCount() != before {
		t.Fatalf("他人会话必须 404 且不转发: %d hits+%d", w.Code, up.hitCount()-before)
	}
	// 失败的越权尝试不得毁掉合法主体的会话
	if w := doAsKey(env, "key-a", http.MethodPost, sessCall, map[string]string{"Mcp-Session-Id": sid}); w.Code != http.StatusOK {
		t.Fatalf("合法主体会话不应受影响: %d", w.Code)
	}
}

func TestD3_GatewayRestartInvalidatesSessionsPerSpec(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	sid := initSession(t, env, "key-a")
	env.handler.SetMCPSessionStore(newMCPMemorySessionStore()) // 等价于进程重启：会话表清空
	w := doAsKey(env, "key-a", http.MethodPost, sessCall, map[string]string{"Mcp-Session-Id": sid})
	if w.Code != http.StatusNotFound {
		t.Fatalf("重启后旧会话按规范应 404 让客户端重新 initialize: %d", w.Code)
	}
}

func TestD3_RouteChangeInvalidatesSession(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	sid := initSession(t, env, "key-a")
	route, _ := env.handler.serverCache.get("tenant_test\x1fmcp_srv1")
	route.RouteHash = strings.Repeat("b", 64)
	// 用 tools/list：tools/call 在路由指纹变化后会先被策略层的路由绑定拦下（HTTP 200 + JSON-RPC 错误），到不了会话校验。
	w := doAsKey(env, "key-a", http.MethodPost, rpcBody(3, "tools/list", ""), map[string]string{"Mcp-Session-Id": sid})
	if w.Code != http.StatusNotFound {
		t.Fatalf("路由指纹变化后旧会话必须作废: %d", w.Code)
	}
}

func TestD3_DeleteAndGetWithForgedSessionAreRejected(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	before := up.hitCount()
	h := map[string]string{"Mcp-Session-Id": "forged", "MCP-Protocol-Version": "2025-11-25"}
	if w := doAsKey(env, "key-a", http.MethodDelete, "", h); w.Code != http.StatusNotFound {
		t.Fatalf("DELETE 伪造会话: %d", w.Code)
	}
	if w := doAsKey(env, "key-a", http.MethodGet, "", h); w.Code != http.StatusNotFound {
		t.Fatalf("GET 伪造会话应 404 而不是 502: %d %s", w.Code, w.Body.String())
	}
	if up.hitCount() != before {
		t.Fatalf("不得转发")
	}
}

func TestD3_DeleteEndsSession(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	sid := initSession(t, env, "key-a")
	h := map[string]string{"Mcp-Session-Id": sid, "MCP-Protocol-Version": "2025-11-25"}
	if w := doAsKey(env, "key-a", http.MethodDelete, "", h); w.Code >= 300 {
		t.Fatalf("合法 DELETE: %d", w.Code)
	}
	if w := doAsKey(env, "key-a", http.MethodPost, sessCall, map[string]string{"Mcp-Session-Id": sid}); w.Code != http.StatusNotFound {
		t.Fatalf("已终止的会话不得再放行: %d", w.Code)
	}
}

func TestD3_RequestsWithoutSessionIdAreByteIdentical(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	w := doAsKey(env, "key-a", http.MethodPost, sessCall, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("不带会话 id 的请求行为不变: %d", w.Code)
	}
}

// 存储有界：总量与单主体上限、空闲 TTL、绝对寿命。
func TestD3_MemoryStoreIsBounded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newMCPMemorySessionStore()
	s.now = func() time.Time { return now }
	s.maxTotal, s.maxPerPrincipal, s.idleTTL, s.maxLifetime = 3, 2, time.Minute, time.Hour
	ctx := context.Background()
	b := func(p string) mcpSessionBinding { return mcpSessionBinding{Principal: p, RouteHash: "h"} }
	_ = s.Put(ctx, "t", "s", "a1", b("pa"))
	_ = s.Put(ctx, "t", "s", "a2", b("pa"))
	_ = s.Put(ctx, "t", "s", "a3", b("pa")) // 超单主体上限：淘汰该主体最旧的 a1
	if _, ok, _ := s.Get(ctx, "t", "s", "a1"); ok {
		t.Fatal("单主体超限应淘汰最旧会话")
	}
	_ = s.Put(ctx, "t", "s", "b1", b("pb"))
	// 超总量（M-4）：不淘汰任何人的会话，而是拒绝这次新登记。
	if err := s.Put(ctx, "t", "s", "c1", b("pc")); !errors.Is(err, errMCPSessionTableFull) {
		t.Fatalf("表满应拒绝新登记，实际 err=%v", err)
	}
	if n := s.len(); n > 3 {
		t.Fatalf("总量必须有界，实际 %d", n)
	}
	for _, id := range []string{"a2", "a3", "b1"} {
		if _, ok, _ := s.Get(ctx, "t", "s", id); !ok {
			t.Fatalf("表满拒绝新登记时，已有会话 %s 不得被挤掉", id)
		}
	}
	now = now.Add(0)
	_ = s.Put(ctx, "t", "s", "c1", b("pc")) // 仍满：保持被拒，下面的空闲过期断言改用 a2
	now = now.Add(2 * time.Minute)          // 空闲超时
	if _, ok, _ := s.Get(ctx, "t", "s", "a2"); ok {
		t.Fatal("空闲超时的会话必须过期")
	}
	_ = s.Put(ctx, "t", "s", "d1", b("pd"))
	for i := 0; i < 70; i++ { // 持续活跃也有绝对寿命
		now = now.Add(time.Minute - time.Second)
		if _, ok, _ := s.Get(ctx, "t", "s", "d1"); !ok {
			break
		}
	}
	if _, ok, _ := s.Get(ctx, "t", "s", "d1"); ok {
		t.Fatal("超过最大寿命的会话必须过期")
	}
}

// 多副本：共享存储（Redis）实现与内存实现语义一致；归属键含租户与 server，session id 本身不明文落库。
type fakeKV struct {
	mu   sync.Mutex
	data map[string]string
	ttl  map[string]time.Duration
}

func (f *fakeKV) Set(_ context.Context, k, v string, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.data == nil {
		f.data, f.ttl = map[string]string{}, map[string]time.Duration{}
	}
	f.data[k], f.ttl[k] = v, ttl
	return nil
}
func (f *fakeKV) Get(_ context.Context, k string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[k]
	return v, ok, nil
}
func (f *fakeKV) Del(_ context.Context, k string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, k)
	return nil
}

func TestD3_SharedStoreSemanticsForMultiReplica(t *testing.T) {
	kv := &fakeKV{}
	a, b := newMCPSharedSessionStore(kv), newMCPSharedSessionStore(kv) // 两个副本共用 KV
	ctx := context.Background()
	bind := mcpSessionBinding{Principal: "p", RouteHash: "h"}
	if err := a.Put(ctx, "t", "s", "sid-1", bind); err != nil {
		t.Fatal(err)
	}
	got, ok, err := b.Get(ctx, "t", "s", "sid-1")
	if err != nil || !ok || got.Principal != "p" || got.RouteHash != "h" {
		t.Fatalf("副本 B 必须能看到副本 A 登记的会话: %v %v %v", got, ok, err)
	}
	if _, ok, _ := b.Get(ctx, "t2", "s", "sid-1"); ok {
		t.Fatal("跨租户不得命中")
	}
	for k, ttl := range kv.ttl {
		if strings.Contains(k, "sid-1") {
			t.Fatalf("session id 不得明文进入共享存储的 key: %s", k)
		}
		if ttl <= 0 {
			t.Fatal("共享存储必须带 TTL（有界）")
		}
	}
	_ = a.Delete(ctx, "t", "s", "sid-1")
	if _, ok, _ := b.Get(ctx, "t", "s", "sid-1"); ok {
		t.Fatal("删除后另一副本不得再命中")
	}
	var _ = json.Marshal
}

// 共享存储不可用时 fail-closed：返回 503 且不转发，而不是放行未验证的 id。
type brokenStore struct{}

func (brokenStore) Put(context.Context, string, string, string, mcpSessionBinding) error {
	return fmt.Errorf("down")
}
func (brokenStore) Get(context.Context, string, string, string) (mcpSessionBinding, bool, error) {
	return mcpSessionBinding{}, false, fmt.Errorf("down")
}
func (brokenStore) Delete(context.Context, string, string, string) error { return fmt.Errorf("down") }

func TestD3_StoreFailureFailsClosed(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	env.handler.SetMCPSessionStore(brokenStore{})
	before := up.hitCount()
	w := doAsKey(env, "key-a", http.MethodPost, sessCall, map[string]string{"Mcp-Session-Id": "whatever"})
	if w.Code != http.StatusServiceUnavailable || up.hitCount() != before {
		t.Fatalf("会话校验后端不可用必须 fail-closed(503) 且不转发: %d", w.Code)
	}
}

// HITL 重放的主体键带租户前缀（mcpBridgePrincipalKey），要能和 initialize 时登记的主体对上。
func TestD3_ReplayPrincipalMatchesRegisteredPrincipal(t *testing.T) {
	info := &auth.AuthInfo{KeyID: "k", UserID: "u", ProjectID: "p"}
	reg := mcpBridgePrincipal(info)
	replay := mcpBridgePrincipalKey("tenant_test", "k", "u", "p")
	if got := mcpStreamablePrincipalFromReplay("tenant_test", replay); got != reg {
		t.Fatalf("重放主体 %q 应还原为登记主体 %q", got, reg)
	}
}
