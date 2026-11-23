package handler

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
)

// --- 步骤0: flag helper 表驱动 ---

func TestKeepAliveMITMEnabled(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{" true ", true},
		{" 1 ", true},
		{"", false},
		{"false", false},
		{"0", false},
		{"yes", false},
		{"  ", false},
		{"truthy", false},
	}
	for _, c := range cases {
		t.Run("val="+c.in, func(t *testing.T) {
			t.Setenv("PROXY_MITM_KEEPALIVE", c.in)
			if got := keepAliveMITMEnabled(); got != c.want {
				t.Fatalf("keepAliveMITMEnabled(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestKeepAliveMITMEnabledDefaultUnset(t *testing.T) {
	os.Unsetenv("PROXY_MITM_KEEPALIVE")
	if keepAliveMITMEnabled() {
		t.Fatalf("keepAliveMITMEnabled() with unset env must default false")
	}
}

func TestMITMIdleTimeout(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 90 * time.Second},     // 空 → 默认 90s
		{"90", 90 * time.Second},   // 自定义=默认值
		{"30", 30 * time.Second},   // 自定义
		{"120", 120 * time.Second}, // 自定义
		{" 45 ", 45 * time.Second}, // 带空白
		{"abc", 90 * time.Second},  // 非法 → 回退
		{"-5", 90 * time.Second},   // 负数 → 回退(非法)
		{"0", 90 * time.Second},    // 0 → 回退(非法,不允许0死等)
		{"9.5", 90 * time.Second},  // 非整数 → 回退
	}
	for _, c := range cases {
		t.Run("val="+c.in, func(t *testing.T) {
			t.Setenv("PROXY_MITM_IDLE_TIMEOUT", c.in)
			if got := mitmIdleTimeout(); got != c.want {
				t.Fatalf("mitmIdleTimeout(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestMITMIdleTimeoutDefaultUnset(t *testing.T) {
	os.Unsetenv("PROXY_MITM_IDLE_TIMEOUT")
	if got := mitmIdleTimeout(); got != 90*time.Second {
		t.Fatalf("mitmIdleTimeout() unset = %v, want 90s", got)
	}
}

// --- 步骤6: removeHopByHopHeaders ---

func TestRemoveHopByHopHeadersFixedSet(t *testing.T) {
	h := http.Header{}
	fixed := []string{
		"Connection", "Proxy-Connection", "Keep-Alive",
		"Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade",
	}
	for _, k := range fixed {
		h.Set(k, "x")
	}
	h.Set("Content-Type", "application/json")
	h.Set("Authorization", "Bearer keep-me")
	h.Set("X-Custom", "keep")

	removeHopByHopHeaders(h)

	for _, k := range fixed {
		if h.Get(k) != "" {
			t.Fatalf("hop-by-hop header %q should be removed, still present", k)
		}
	}
	if h.Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type should be preserved")
	}
	if h.Get("Authorization") != "Bearer keep-me" {
		t.Fatalf("Authorization should be preserved")
	}
	if h.Get("X-Custom") != "keep" {
		t.Fatalf("X-Custom should be preserved")
	}
}

func TestRemoveHopByHopHeadersConnectionListed(t *testing.T) {
	h := http.Header{}
	// Connection 头逐条列出要删的字段(RFC 7230 §6.1)
	h.Set("Connection", "X-Hop-One, X-Hop-Two")
	h.Set("X-Hop-One", "drop")
	h.Set("X-Hop-Two", "drop")
	h.Set("X-Survivor", "keep")

	removeHopByHopHeaders(h)

	if h.Get("X-Hop-One") != "" {
		t.Fatalf("X-Hop-One listed in Connection should be removed")
	}
	if h.Get("X-Hop-Two") != "" {
		t.Fatalf("X-Hop-Two listed in Connection should be removed")
	}
	if h.Get("X-Survivor") != "keep" {
		t.Fatalf("X-Survivor not listed should survive")
	}
	if h.Get("Connection") != "" {
		t.Fatalf("Connection itself should be removed")
	}
}

// --- 步骤3: outReq 构造 ---

func TestBuildUpstreamRequestForRoundTrip(t *testing.T) {
	body := []byte(`{"prompt":"hello"}`)
	clientReq, err := http.NewRequest(http.MethodPost, "https://placeholder/v1/chat", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	clientReq.Header.Set("Content-Type", "application/json")
	clientReq.Header.Set("Connection", "keep-alive")
	clientReq.RequestURI = "/v1/chat" // ReadRequest 会设置 RequestURI

	targetHost := "api.deepseek.com:443"
	outReq := buildUpstreamRequest(clientReq, targetHost, body)

	if outReq.RequestURI != "" {
		t.Fatalf("RequestURI must be cleared for client RoundTrip, got %q", outReq.RequestURI)
	}
	if outReq.URL.Scheme != "https" {
		t.Fatalf("scheme = %q, want https", outReq.URL.Scheme)
	}
	if outReq.URL.Host != targetHost {
		t.Fatalf("host = %q, want %q", outReq.URL.Host, targetHost)
	}
	if outReq.Header.Get("Connection") != "" {
		t.Fatalf("hop-by-hop Connection must be stripped from outReq")
	}
	if outReq.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type should survive")
	}
	// Body 必须可重读且等于 requestBody
	got, err := io.ReadAll(outReq.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("outReq body = %q, want %q", got, body)
	}
	// GetBody 必须存在,使 Transport 在池里 stale 连接上能安全重发已知 body 的 POST。
	if outReq.GetBody == nil {
		t.Fatalf("outReq.GetBody must be set for safe retransmit on stale pooled conn")
	}
	rc, err := outReq.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	regot, _ := io.ReadAll(rc)
	if !bytes.Equal(regot, body) {
		t.Fatalf("GetBody() body = %q, want %q", regot, body)
	}
	// Clone 会把 clientReq.Close 复制过来;上游复用应与客户端隧道复用解耦 → 必须显式 false。
	if outReq.Close {
		t.Fatalf("outReq.Close must be false (decouple upstream reuse from client Connection:close)")
	}
}

func TestBuildUpstreamRequestDecouplesClientClose(t *testing.T) {
	body := []byte(`{}`)
	clientReq, _ := http.NewRequest(http.MethodPost, "https://placeholder/x", bytes.NewReader(body))
	clientReq.Close = true // 客户端要求关隧道
	outReq := buildUpstreamRequest(clientReq, "api.deepseek.com:443", body)
	if outReq.Close {
		t.Fatalf("client Connection:close must NOT force upstream conn close (lost reuse)")
	}
}

// --- 步骤5: keepAlive 返回判定 ---

func TestKeepAliveDecisionForResponse(t *testing.T) {
	cases := []struct {
		name         string
		useKeepAlive bool
		clientClose  bool
		respClose    bool
		want         bool
	}{
		{"keepalive on, both want keep", true, false, false, true},
		{"keepalive on, client Connection:close", true, true, false, false},
		{"keepalive on, upstream Connection:close", true, false, true, false},
		{"keepalive on, both close", true, true, true, false},
		{"keepalive off (default path)", false, false, false, false},
		{"keepalive off, client close", false, true, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := keepAliveDecision(c.useKeepAlive, c.clientClose, c.respClose); got != c.want {
				t.Fatalf("keepAliveDecision(%v,%v,%v) = %v, want %v", c.useKeepAlive, c.clientClose, c.respClose, got, c.want)
			}
		})
	}
}

// --- 步骤7: h1 transport 缓存复用(防"每请求新 transport") ---

func TestMITMKeepAliveTransportCachedAndH1(t *testing.T) {
	h := NewProxyHandler(nil, nil, nil, nil, nil)
	t1 := h.mitmKeepAliveTransport()
	t2 := h.mitmKeepAliveTransport()
	if t1 == nil {
		t.Fatalf("mitmKeepAliveTransport returned nil")
	}
	if t1 != t2 {
		t.Fatalf("mitmKeepAliveTransport must cache & reuse a single transport (got two distinct instances)")
	}
	tr, ok := t1.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", t1)
	}
	if tr.ForceAttemptHTTP2 {
		t.Fatalf("ForceAttemptHTTP2 must be false (force HTTP/1.1)")
	}
	if tr.TLSClientConfig == nil || len(tr.TLSClientConfig.NextProtos) != 1 || tr.TLSClientConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("TLSClientConfig.NextProtos must be [http/1.1], got %#v", tr.TLSClientConfig)
	}
	if tr.DialContext == nil {
		t.Fatalf("DialContext must be set (guarded for SSRF)")
	}
	// [blocker] DisableCompression:防 Go Transport 对无 Accept-Encoding 请求自动注入 gzip 并透明
	// 解压(剥 CE 头/Uncompressed/改 CL),使回写字节与手拨 ReadResponse 路径漂移、流式 gzip 无定界挂起。
	if !tr.DisableCompression {
		t.Fatalf("DisableCompression must be true (透传原始压缩字节,与手拨路径字节一致)")
	}
	// [should-fix] ResponseHeaderTimeout:上游建连后迟迟不回响应头时给上界,别无界阻塞。
	if tr.ResponseHeaderTimeout != 60*time.Second {
		t.Fatalf("ResponseHeaderTimeout must be 60s, got %v", tr.ResponseHeaderTimeout)
	}
}

// --- 核心防退化: 逐请求审计不退化 ---
// SecurityClient/AuditWriter 为具体类型(非接口)且 CheckInput 走真实 HTTP,
// 无法在不起真实上游+真实 security-engine 的情况下对 serveOneMITMRequest 全链路单测。
// 但「每轮新建 auditRecord 且 RequestID 各异」是承重不变量,可直接对 NewProxyAuditRecord
// 的逐请求调用做断言: 模拟同隧道连发 N 请求 → N 条 RequestID 各异的审计记录。
func TestPerRequestAuditRecordIDsAreDistinct(t *testing.T) {
	const n = 5
	seen := map[string]bool{}
	req, _ := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat", nil)
	match := detectLLMProvider("api.deepseek.com:443", "/v1/chat")
	for i := 0; i < n; i++ {
		// 复刻 serveOneMITMRequest 内每轮的 auditRecord 构造(空 RequestID → uuid)
		rec, err := NewProxyAuditRecord("", "tenant_default", "api.deepseek.com:443", req, match, true)
		if err != nil {
			t.Fatal(err)
		}
		if rec.RequestID == "" {
			t.Fatalf("round %d: RequestID must be auto-generated when empty", i)
		}
		if seen[rec.RequestID] {
			t.Fatalf("round %d: duplicate RequestID %q — per-request audit identity collapsed", i, rec.RequestID)
		}
		seen[rec.RequestID] = true
	}
	if len(seen) != n {
		t.Fatalf("expected %d distinct RequestIDs, got %d", n, len(seen))
	}
}

// 兜底: 确保默认关 env 下 handler 构造不 panic 且 transport 字段(h2 共享版)仍可用,
// 与改造前一致(默认关字节等价的最低保证之一)。
func TestDefaultPathTransportUntouched(t *testing.T) {
	h := NewProxyHandler(nil, nil, nil, nil, nil)
	if h.currentTransport() == nil {
		t.Fatalf("shared transport (h2, used by handleHTTP) must remain available")
	}
	// keepalive 专用 transport 与共享 transport 必须是不同实例(决策:不动共享 transport)
	shared := h.currentTransport()
	keepalive := h.mitmKeepAliveTransport()
	sharedTr, sok := shared.(*http.Transport)
	keepaliveTr, kok := keepalive.(*http.Transport)
	if sok && kok && sharedTr == keepaliveTr {
		t.Fatalf("keepalive transport must NOT be the shared transport instance")
	}
}

func TestProxyMITMHeaderConflictPersistsToRealCentral(t *testing.T) {
	central := os.Getenv("HEADER_CONTRACT_CENTRAL_URL")
	if central == "" {
		t.Skip("real central fixture is not configured")
	}
	cert := genTestCert(t)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	serverTLS, clientTLS, srvRaw, cliRaw := newMITMTunnel(t, cert, pool)
	h := NewProxyHandler(nil, nil, nil, nil, headeraudit.NewClient(central, "secret"))
	done := make(chan bool, 1)
	go func() {
		defer srvRaw.Close()
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			done <- false
			return
		}
		outer := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
		outer.RemoteAddr = "203.0.113.10:443"
		done <- h.serveOneMITMRequest(serverTLS, bufio.NewReader(serverTLS), outer, "api.deepseek.com:443", "tenant_default", true, true)
	}()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", strings.NewReader(`{"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Request-Id", "r2-proxy-mitm")
	req.Header["X-JJDGuard-Agent-Type"] = []string{"proxy-mitm-new-canary"}
	req.Header["X-NewAPI-Agent-Type"] = []string{"proxy-mitm-old-canary"}
	if err := req.Write(clientTLS); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	_ = cliRaw.Close()
	if resp.StatusCode != http.StatusBadRequest || strings.Contains(strings.ToLower(string(body)), "canary") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if keepAlive := <-done; keepAlive {
		t.Fatal("conflicted MITM request must close the tunnel")
	}
}
