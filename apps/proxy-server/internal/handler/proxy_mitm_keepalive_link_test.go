package handler

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 这是「逐请求审计不退化」的全链路证据测试:用一对真实 tls.Conn(net.Pipe + 自签证书)驱动
// serveOneMITMRequest,上游走真实 DialTLSContext(经注入 EgressGuard 重定向到本地假上游,绕开
// SSRF 私网封锁但仍走真实拨号+握手代码路径),并用计数 security-engine 服务器断言:
//   同隧道 keep-alive 连发 N 请求 → CheckInput 被调用 N 次、N 个请求各异 request_id。
// 证明 keep-alive 复用隧道时每个请求仍独立过审计四件套,不退化为「一隧道一审计」。

// genTestCert 生成一张自签 TLS 证书,既给 tlsClientConn(MITM 服务端)用,也给假上游用。
func genTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-mitm"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"api.deepseek.com", "localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// fakeUpstream 起一个本地 TLS HTTP/1.1 服务器(keep-alive),每个请求回一小段 JSON。
// 返回监听地址(host:port)与证书池。
func fakeUpstream(t *testing.T, cert tls.Certificate, reqCount *int64) (net.Listener, *x509.CertPool) {
	t.Helper()
	return fakeUpstreamWithHandler(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(reqCount, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
}

// fakeUpstreamWithHandler 起一个本地 TLS HTTP/1.1 上游(keep-alive),用调用方提供的 handler。
func fakeUpstreamWithHandler(t *testing.T, cert tls.Certificate, handler http.Handler) (net.Listener, *x509.CertPool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	srv := &http.Server{
		Handler:   handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln, pool
}

// quietSecuritySrv 起一个恒返回 audit 的 security-engine 桩(让 CheckInput/CheckOutput 不拦)。
func quietSecuritySrv(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"audit","findings":[]}`))
	}))
	t.Cleanup(s.Close)
	return s
}

// newMITMTunnel 建立一对真实 tls.Conn(net.Pipe + 自签证书),返回服务端 tls.Conn、客户端 tls.Conn
// 及各自的裸 pipe 端(收尾时关裸端避免 net.Pipe 上 close_notify 阻塞)。两端并发完成握手。
func newMITMTunnel(t *testing.T, cert tls.Certificate, pool *x509.CertPool) (serverTLS, clientTLS *tls.Conn, srvRaw, cliRaw net.Conn) {
	t.Helper()
	srvRaw, cliRaw = net.Pipe()
	serverTLS = tls.Server(srvRaw, &tls.Config{Certificates: []tls.Certificate{cert}})
	clientTLS = tls.Client(cliRaw, &tls.Config{RootCAs: pool, ServerName: "api.deepseek.com"})
	return serverTLS, clientTLS, srvRaw, cliRaw
}

// trustingKeepAliveTransport 让 handler 的 keep-alive 专用 transport 信任本测试假上游证书,
// 同时**完整保留生产 mitmKeepAliveTransport() 的所有配置位**(DisableCompression / ForceAttemptHTTP2 /
// ResponseHeaderTimeout / NextProtos / guarded DialContext):做法是先触发生产懒初始化拿到真 transport,
// 仅在其既有 TLSClientConfig 上补 RootCAs(信任自签证书)。如此行为型测试(如透明解压回归)真实反映
// 生产 transport 配置——若生产误删 DisableCompression,本测试也会随之失败,而非被测试桩掩盖。
func trustingKeepAliveTransport(h *ProxyHandler, pool *x509.CertPool) {
	prod := h.mitmKeepAliveTransport().(*http.Transport) // 触发生产懒初始化(承载 DisableCompression 等)
	prod.TLSClientConfig = prod.TLSClientConfig.Clone()
	prod.TLSClientConfig.RootCAs = pool
	prod.TLSClientConfig.ServerName = "api.deepseek.com"
}

// redirectGuard 构造一个 EgressGuard,其 resolver 把任意 host 解析到一个公网态 IP(TEST-NET-3,
// 不被 SSRF 封锁),其 dialer 忽略 pinned 地址、统一连到本地假上游。如此既走真实 Resolve→
// isBlockedEgressIP→dialer→DialTLSContext 全链路,又能在单测里连到本地服务器。
func redirectGuard(upstreamAddr string) *EgressGuard {
	resolver := stubResolver{ip: net.ParseIP("203.0.113.10")} // TEST-NET-3, 公网态、非私网
	dialer := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, upstreamAddr)
	}
	return NewEgressGuard(resolver, dialer)
}

type stubResolver struct{ ip net.IP }

func (s stubResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: s.ip}}, nil
}

// TestServeOneMITMRequestKeepAliveAuditDoesNotDegrade 是承重不变量的全链路证据。
func TestServeOneMITMRequestKeepAliveAuditDoesNotDegrade(t *testing.T) {
	cert := genTestCert(t)

	var upstreamHits int64
	ln, pool := fakeUpstream(t, cert, &upstreamHits)
	upstreamAddr := ln.Addr().String()

	// 计数型 security-engine:统计 CheckInput 调用次数 + 收集 request_id 验证各异。
	var checkInputHits int64
	var mu sync.Mutex
	seenReqIDs := map[string]bool{}
	secSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/check-input/" {
			atomic.AddInt64(&checkInputHits, 1)
			var body []byte
			body, _ = io.ReadAll(r.Body)
			mu.Lock()
			// request_id 内嵌纳秒,粗验各异:直接以整段 payload 去重过严,改抽 request_id 子串。
			seenReqIDs[string(body)] = true
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"audit","findings":[]}`))
	}))
	t.Cleanup(secSrv.Close)

	h := &ProxyHandler{
		securityClient: NewSecurityClient(secSrv.URL),
		auditWriter:    NewAuditWriter(nil), // nil db: WriteRequestLog 安全空转,不影响 CheckInput 计数
		egressGuard:    redirectGuard(upstreamAddr),
	}
	// 让 keep-alive 专用 transport 信任假上游证书 + 仍走 guarded 拨号。
	h.mitmKeepAliveOnce.Do(func() {
		tr := h.egressGuard.HTTPTransport()
		tr.ForceAttemptHTTP2 = false
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "api.deepseek.com", NextProtos: []string{"http/1.1"}}
		h.mitmKeepAliveRT = tr
	})

	// 建立真实 tls.Conn 对:net.Pipe 两端各跑 tls.Server / tls.Client,并发握手。
	srvRaw, cliRaw := net.Pipe()
	serverTLS := tls.Server(srvRaw, &tls.Config{Certificates: []tls.Certificate{cert}})
	clientTLS := tls.Client(cliRaw, &tls.Config{RootCAs: pool, ServerName: "api.deepseek.com"})

	const n = 4

	// 服务端:在隧道上循环服务 n 个请求(模拟 handleMITM 的 keep-alive 循环)。
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		reader := bufio.NewReader(serverTLS)
		r := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
		for i := 0; i < n; i++ {
			ka := h.serveOneMITMRequest(serverTLS, reader, r, "api.deepseek.com:443", "tenant_default", true, true)
			if i < n-1 && !ka {
				t.Errorf("round %d: expected keepAlive=true to continue tunnel, got false", i)
				return
			}
		}
		// 关裸 pipe 端而非 TLS 层:避免在同步 net.Pipe 上写 close_notify 阻塞(纯测试收尾,
		// 与生产无关——生产用真实 socket 不存在此阻塞)。
		_ = srvRaw.Close()
	}()

	// 客户端:握手后顺序发 n 个 keep-alive 请求,逐个读响应。
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	cliReader := bufio.NewReader(clientTLS)
	for i := 0; i < n; i++ {
		req, _ := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions",
			strings.NewReader(fmt.Sprintf(`{"messages":[{"content":"hi-%d"}]}`, i)))
		req.Header.Set("Content-Type", "application/json")
		// 最后一个请求声明 Connection:close,使隧道在第 n 轮后由 keepAliveDecision 收尾。
		if i == n-1 {
			req.Close = true
			req.Header.Set("Connection", "close")
		}
		if err := req.Write(clientTLS); err != nil {
			t.Fatalf("round %d write: %v", i, err)
		}
		resp, err := http.ReadResponse(cliReader, req)
		if err != nil {
			t.Fatalf("round %d read response: %v", i, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(b) != `{"ok":true}` {
			t.Fatalf("round %d unexpected response: %d %q", i, resp.StatusCode, b)
		}
	}
	_ = cliRaw.Close()

	select {
	case <-serverDone:
	case <-time.After(10 * time.Second):
		t.Fatal("server loop did not finish")
	}

	if got := atomic.LoadInt64(&checkInputHits); got != n {
		t.Fatalf("CheckInput called %d times across keep-alive tunnel, want %d (per-request audit degraded!)", got, n)
	}
	if got := atomic.LoadInt64(&upstreamHits); got != n {
		t.Fatalf("upstream received %d requests, want %d", got, n)
	}
	mu.Lock()
	distinct := len(seenReqIDs)
	mu.Unlock()
	if distinct != n {
		t.Fatalf("expected %d distinct CheckInput payloads (distinct request_id), got %d", n, distinct)
	}
}

// TestServeOneMITMRequestBlockReturnsFalseAndSendsBlockedResponse 证明:CheckInput action=block 时
// serveOneMITMRequest 经 sendBlockedResponse 回 403 并 return false(不复用隧道、不触上游)。
// 注:这是「非 audit-only」配置下的既有行为(本改造未新增任何 block 路径);audit-only 环境
// 下 CheckOutput/CheckInput 恒返回 audit,此路径不可达。
func TestServeOneMITMRequestBlockReturnsFalseAndSendsBlockedResponse(t *testing.T) {
	cert := genTestCert(t)
	var upstreamHits int64
	ln, pool := fakeUpstream(t, cert, &upstreamHits)

	secSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// CheckInput → block(模拟非 audit-only 拦截配置)
		_, _ = w.Write([]byte(`{"action":"block","findings":[{"type":"secret"}]}`))
	}))
	t.Cleanup(secSrv.Close)

	h := &ProxyHandler{
		securityClient: NewSecurityClient(secSrv.URL),
		auditWriter:    NewAuditWriter(nil),
		egressGuard:    redirectGuard(ln.Addr().String()),
	}

	srvRaw, cliRaw := net.Pipe()
	serverTLS := tls.Server(srvRaw, &tls.Config{Certificates: []tls.Certificate{cert}})
	clientTLS := tls.Client(cliRaw, &tls.Config{RootCAs: pool, ServerName: "api.deepseek.com"})

	type result struct{ ka bool }
	resCh := make(chan result, 1)
	go func() {
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			close(resCh)
			return
		}
		reader := bufio.NewReader(serverTLS)
		r := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
		ka := h.serveOneMITMRequest(serverTLS, reader, r, "api.deepseek.com:443", "tenant_default", true, true)
		resCh <- result{ka: ka}
		_ = srvRaw.Close()
	}()

	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions",
		strings.NewReader(`{"messages":[{"content":"sk-leak"}]}`))
	req.Header.Set("Content-Type", "application/json")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read blocked response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked response status = %d, want 403", resp.StatusCode)
	}
	_ = cliRaw.Close()

	select {
	case res, ok := <-resCh:
		if !ok {
			t.Fatal("server failed before producing result")
		}
		if res.ka {
			t.Fatal("block must return keepAlive=false (tunnel not reused after block)")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not finish")
	}

	if atomic.LoadInt64(&upstreamHits) != 0 {
		t.Fatalf("blocked request must NOT reach upstream, got %d hits", upstreamHits)
	}
}

// gzipBytes 压缩一段明文为 gzip 字节(给假上游手工产出带 Content-Encoding:gzip 的响应)。
func gzipBytes(t *testing.T, plain []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestKeepAliveDisableCompressionTransparentNoDecode 是「DisableCompression」回归(blocker):
// 客户端不带 Accept-Encoding,上游回 Content-Encoding:gzip 的压缩体。若 transport 未设
// DisableCompression=true,Go 会自动注入 Accept-Encoding:gzip 并透明解压(剥 CE 头、Uncompressed=true、
// 改 CL)→ keep-alive 回写客户端的字节与手拨 ReadResponse 路径漂移。断言:客户端收到的恰是上游
// 原始 gzip 字节、CE 头仍为 gzip(未被透明解压)。
func TestKeepAliveDisableCompressionTransparentNoDecode(t *testing.T) {
	cert := genTestCert(t)
	plain := []byte(`{"reply":"hello-from-model"}`)
	gz := gzipBytes(t, plain)

	ln, pool := fakeUpstreamWithHandler(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 上游收到的请求不应带 Accept-Encoding(DisableCompression 阻止 Go 自动注入)。
		if ae := r.Header.Get("Accept-Encoding"); ae != "" {
			t.Errorf("upstream saw Accept-Encoding=%q; DisableCompression must prevent auto-injection", ae)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(gz)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gz)
	}))

	h := &ProxyHandler{
		securityClient: NewSecurityClient(quietSecuritySrv(t).URL),
		auditWriter:    NewAuditWriter(nil),
		egressGuard:    redirectGuard(ln.Addr().String()),
	}
	trustingKeepAliveTransport(h, pool)

	serverTLS, clientTLS, srvRaw, cliRaw := newMITMTunnel(t, cert, pool)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		reader := bufio.NewReader(serverTLS)
		r := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
		_ = h.serveOneMITMRequest(serverTLS, reader, r, "api.deepseek.com:443", "tenant_default", true, true)
		_ = srvRaw.Close()
	}()

	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions",
		strings.NewReader(`{"q":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	// 客户端故意不带 Accept-Encoding。
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write: %v", err)
	}
	// 关键:用 readRawResponse 读「原始字节」,不让 http.Client 透明解压客户端侧,才能比对回写字节。
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("client must receive Content-Encoding:gzip intact (transparent decode leaked), got %q", resp.Header.Get("Content-Encoding"))
	}
	if resp.Uncompressed {
		t.Fatalf("response was transparently decompressed — DisableCompression not effective")
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, gz) {
		t.Fatalf("client bytes drifted from upstream raw gzip: got %d bytes, want %d", len(got), len(gz))
	}
	_ = cliRaw.Close()
	<-done
}

// TestKeepAliveNoCrossTalkBuffered 是「串包/归池」回归(数据泄漏级,缓冲分支):上游回显请求序号,
// 同隧道连发 N 个不同请求,断言第 i 个响应严格匹配第 i 个请求——绝不串包。
func TestKeepAliveNoCrossTalkBuffered(t *testing.T) {
	cert := genTestCert(t)
	ln, pool := fakeUpstreamWithHandler(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// 回显请求体,使每个响应与对应请求强绑定。
		_, _ = w.Write([]byte(fmt.Sprintf(`{"echo":%q}`, string(body))))
	}))
	h := &ProxyHandler{
		securityClient: NewSecurityClient(quietSecuritySrv(t).URL),
		auditWriter:    NewAuditWriter(nil),
		egressGuard:    redirectGuard(ln.Addr().String()),
	}
	trustingKeepAliveTransport(h, pool)
	assertNoCrossTalk(t, h, cert, pool, 6)
}

// TestKeepAliveNoCrossTalkStreaming 是「串包/归池」回归(流式分支,TeeReader + io.Copy(io.Discard) +
// origBody.Close 归池兜底后下一轮无串包)。开 PROXY_STREAM_LLM_RESPONSES 走流式回写路径。
func TestKeepAliveNoCrossTalkStreaming(t *testing.T) {
	t.Setenv("PROXY_STREAM_LLM_RESPONSES", "true")
	cert := genTestCert(t)
	ln, pool := fakeUpstreamWithHandler(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream") // 模型回复类型 → 走 stream 分支
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"echo":%q}`, string(body))))
	}))
	h := &ProxyHandler{
		securityClient: NewSecurityClient(quietSecuritySrv(t).URL),
		auditWriter:    NewAuditWriter(nil),
		egressGuard:    redirectGuard(ln.Addr().String()),
	}
	trustingKeepAliveTransport(h, pool)
	assertNoCrossTalk(t, h, cert, pool, 6)
}

// assertNoCrossTalk 同隧道连发 n 个内容各异的请求,逐个断言响应回显与该请求严格一致。
func assertNoCrossTalk(t *testing.T, h *ProxyHandler, cert tls.Certificate, pool *x509.CertPool, n int) {
	t.Helper()
	serverTLS, clientTLS, srvRaw, cliRaw := newMITMTunnel(t, cert, pool)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		reader := bufio.NewReader(serverTLS)
		r := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
		for i := 0; i < n; i++ {
			ka := h.serveOneMITMRequest(serverTLS, reader, r, "api.deepseek.com:443", "tenant_default", true, true)
			if i < n-1 && !ka {
				t.Errorf("round %d: expected keepAlive=true, got false", i)
				return
			}
		}
		_ = srvRaw.Close()
	}()

	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	cliReader := bufio.NewReader(clientTLS)
	for i := 0; i < n; i++ {
		payload := fmt.Sprintf(`{"seq":%d,"nonce":"req-%d-uniq"}`, i, i)
		req, _ := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if i == n-1 {
			req.Close = true
			req.Header.Set("Connection", "close")
		}
		if err := req.Write(clientTLS); err != nil {
			t.Fatalf("round %d write: %v", i, err)
		}
		resp, err := http.ReadResponse(cliReader, req)
		if err != nil {
			t.Fatalf("round %d read: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		want := fmt.Sprintf(`{"echo":%q}`, payload)
		if string(body) != want {
			t.Fatalf("CROSS-TALK at round %d: got %q, want %q (response not matched to its own request!)", i, body, want)
		}
	}
	_ = cliRaw.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("server loop did not finish")
	}
}

// TestKeepAliveDefaultOffByteEquivalence 证明「默认关字节等价」。
// 默认关(useKeepAlive=false)路径在 serveOneMITMRequest 内是「手拨 DialTLSContext + clientReq.Write
// + http.ReadResponse + 原样回写」,与本 feature 引入前的 handleMITM 逐字节相同,且会把上游响应体/
// Content-Encoding 原样转发(从不解码)。本测试对 keep-alive(RoundTrip)路径断言其回写客户端的
// 响应体 == 上游原始字节(含 gzip CE 头),即与手拨路径产出的同一字节序列——若 transport 透明解压
// 就会偏离。这样在不依赖手拨路径自签证书校验(其 tls.Config 在生产代码内联、无 RootCAs 注入点)的
// 前提下,等价地证明 keep-alive 没有引入字节漂移。
//
// 说明:手拨路径本身的字节行为由「与引入前 diff 为 0 + 全包零回归」保证,无需在本单测里重跑其
// 真实 TLS(那需要往生产代码塞测试用 RootCAs 注入点,得不偿失)。
func TestKeepAliveDefaultOffByteEquivalence(t *testing.T) {
	cert := genTestCert(t)
	plain := []byte(`{"reply":"deterministic-body-123"}`)
	gz := gzipBytes(t, plain)
	ln, pool := fakeUpstreamWithHandler(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(gz)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gz)
	}))

	h := &ProxyHandler{
		securityClient: NewSecurityClient(quietSecuritySrv(t).URL),
		auditWriter:    NewAuditWriter(nil),
		egressGuard:    redirectGuard(ln.Addr().String()),
	}
	trustingKeepAliveTransport(h, pool)
	serverTLS, clientTLS, srvRaw, cliRaw := newMITMTunnel(t, cert, pool)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		reader := bufio.NewReader(serverTLS)
		r := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
		_ = h.serveOneMITMRequest(serverTLS, reader, r, "api.deepseek.com:443", "tenant_default", true, true)
		_ = srvRaw.Close()
	}()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", strings.NewReader(`{"q":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Close = true
	req.Header.Set("Connection", "close")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("keep-alive path Content-Encoding=%q, want gzip (手拨路径会原样转发 → 漂移)", resp.Header.Get("Content-Encoding"))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	_ = cliRaw.Close()
	<-done
	// 手拨路径会把上游原始字节逐字转发;keep-alive 路径产出必须等于同一字节序列。
	if !bytes.Equal(body, gz) {
		t.Fatalf("byte drift: keep-alive body (%d B) != upstream raw gzip bytes that manual-dial path forwards verbatim (%d B)", len(body), len(gz))
	}
}

// TestKeepAlive502OnUpstreamDialFailure 证明 502 分支:上游不可达(listener 关)→ 客户端收 502 +
// serveOneMITMRequest 返回 false + auditRecord.Status=="error"(经计数 security-engine 间接:
// 上游不可达时 CheckInput 仍照常调用一次,证明审计前置链路走到;502 由 dial 后失败触发)。
func TestKeepAlive502OnUpstreamDialFailure(t *testing.T) {
	cert := genTestCert(t)
	// 起一个上游拿到地址后立刻关掉,使后续 dial 失败。
	var dummy int64
	ln, pool := fakeUpstream(t, cert, &dummy)
	deadAddr := ln.Addr().String()
	_ = ln.Close() // 现在 deadAddr 无人监听 → dial refused

	var checkInputHits int64
	secSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/check-input/" {
			atomic.AddInt64(&checkInputHits, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"audit","findings":[]}`))
	}))
	t.Cleanup(secSrv.Close)

	h := &ProxyHandler{
		securityClient: NewSecurityClient(secSrv.URL),
		auditWriter:    NewAuditWriter(nil),
		egressGuard:    redirectGuard(deadAddr),
	}
	trustingKeepAliveTransport(h, pool)

	serverTLS, clientTLS, srvRaw, cliRaw := newMITMTunnel(t, cert, pool)
	type res struct{ ka bool }
	resCh := make(chan res, 1)
	go func() {
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			close(resCh)
			return
		}
		reader := bufio.NewReader(serverTLS)
		r := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
		ka := h.serveOneMITMRequest(serverTLS, reader, r, "api.deepseek.com:443", "tenant_default", true, true)
		resCh <- res{ka: ka}
		_ = srvRaw.Close()
	}()

	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", strings.NewReader(`{"q":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read 502: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("upstream dial failure must yield 502, got %d", resp.StatusCode)
	}
	_ = cliRaw.Close()

	select {
	case r, ok := <-resCh:
		if !ok {
			t.Fatal("server failed before result")
		}
		if r.ka {
			t.Fatal("502 path must return keepAlive=false")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not finish")
	}
	if atomic.LoadInt64(&checkInputHits) != 1 {
		t.Fatalf("CheckInput should still run once before upstream failure, got %d", checkInputHits)
	}
}

// TestReadDeadlineClearedAfterRequestHeader 是 fix2(read deadline 仅覆盖空闲等待)的回归:
// 模拟 handleMITM 循环顶为本轮武装一个**很短**的 idle read deadline,然后客户端先发请求头、
// 故意拖一段(> 该 deadline)再发请求体。若 serveOneMITMRequest 未在 ReadRequest 成功后清除
// deadline,则后续读请求体会被 i/o timeout 掐断、本轮失败;清除后本轮应正常完成。
func TestReadDeadlineClearedAfterRequestHeader(t *testing.T) {
	cert := genTestCert(t)
	var upstreamHits int64
	ln, pool := fakeUpstream(t, cert, &upstreamHits)

	h := &ProxyHandler{
		securityClient: NewSecurityClient(quietSecuritySrv(t).URL),
		auditWriter:    NewAuditWriter(nil),
		egressGuard:    redirectGuard(ln.Addr().String()),
	}
	trustingKeepAliveTransport(h, pool)

	serverTLS, clientTLS, srvRaw, cliRaw := newMITMTunnel(t, cert, pool)
	type res struct{ ka bool }
	resCh := make(chan res, 1)
	go func() {
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			close(resCh)
			return
		}
		reader := bufio.NewReader(serverTLS)
		r := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
		// 模拟循环顶武装一个很短的 idle read deadline(120ms);若不在 ReadRequest 后清除,
		// 拖到 300ms 才到的请求体会读超时。
		_ = serverTLS.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
		ka := h.serveOneMITMRequest(serverTLS, reader, r, "api.deepseek.com:443", "tenant_default", true, true)
		resCh <- res{ka: ka}
		_ = srvRaw.Close()
	}()

	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	// 手工分两段发:先发请求头(带 Content-Length),拖过 deadline,再发请求体。
	body := `{"q":"slow-body"}`
	head := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.deepseek.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Connection: close\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
	if _, err := clientTLS.Write([]byte(head)); err != nil {
		t.Fatalf("write head: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // > 120ms idle deadline
	if _, err := clientTLS.Write([]byte(body)); err != nil {
		t.Fatalf("write body: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		t.Fatalf("read response (deadline likely掐断了慢请求体读取): %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (round must complete despite body arriving after idle window)", resp.StatusCode)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	_ = cliRaw.Close()

	select {
	case <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not finish")
	}
	if atomic.LoadInt64(&upstreamHits) != 1 {
		t.Fatalf("upstream must receive the request once (round completed), got %d", upstreamHits)
	}
}
