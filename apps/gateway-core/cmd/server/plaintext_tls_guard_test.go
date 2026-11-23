package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 现场 P3-9：客户端把地址写成 https://主机:8080/v1，而 8080 是明文 HTTP 端口。
// 这些测试锁定：能识别 TLS ClientHello、立即给出明确结果和服务端日志，
// 且完全不影响正常 HTTP 流量（不阻塞 Accept、不改写任何普通请求的字节）。

type guardLogRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *guardLogRecorder) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *guardLogRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

// 最小但结构合法的 TLS 记录头 + ClientHello 握手头（足够被识别，不需要可握手）。
var tlsClientHelloFixture = []byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x03}

func TestLooksLikeTLSClientHello(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"TLS 1.0 记录头", []byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x01}, true},
		{"TLS 1.2 记录头", []byte{0x16, 0x03, 0x03, 0x02, 0x00, 0x01}, true},
		{"SSL 3.0 记录头", []byte{0x16, 0x03, 0x00, 0x00, 0x2f, 0x01}, true},
		{"只有前三个字节也足够判断", []byte{0x16, 0x03, 0x01}, true},
		{"握手类型不是 ClientHello", []byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x02}, false},
		{"次版本号超出范围", []byte{0x16, 0x03, 0x05, 0x00, 0x2f, 0x01}, false},
		{"主版本号不是 3", []byte{0x16, 0x02, 0x01, 0x00, 0x2f, 0x01}, false},
		{"记录类型不是握手", []byte{0x17, 0x03, 0x03, 0x00, 0x2f, 0x01}, false},
		{"普通 HTTP 请求", []byte("POST /v1/messages HTTP/1.1\r\n"), false},
		{"HTTP/2 前言", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), false},
		{"不足三个字节无法判断", []byte{0x16, 0x03}, false},
		{"空数据", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeTLSClientHello(tc.data); got != tc.want {
				t.Fatalf("looksLikeTLSClientHello(% x) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}

func startGuardedServer(t *testing.T, handler http.Handler, guard *plaintextTLSGuard) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(guard.Wrap(listener)) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

func TestPlaintextTLSGuardRepliesImmediatelyAndLogsOnce(t *testing.T) {
	logs := &guardLogRecorder{}
	var handlerCalls atomic.Int32
	addr := startGuardedServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalls.Add(1)
	}), newPlaintextTLSGuard(logs.logf))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	started := time.Now()
	if _, err := conn.Write(tlsClientHelloFixture); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("应当立即得到完整回应并被服务端关闭连接，而不是超时: %v (已读 %q)", err, reply)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("回应耗时 %s，应当立即返回而不是等待读头超时", elapsed)
	}
	text := string(reply)
	if !strings.HasPrefix(text, "HTTP/1.1 400 Bad Request\r\n") || !strings.Contains(text, "Connection: close") {
		t.Fatalf("回应不是预期的 400: %q", text)
	}
	if !strings.Contains(text, "明文 HTTP 端口") || !strings.Contains(text, "http://") {
		t.Fatalf("回应缺少中文改法提示: %q", text)
	}
	if handlerCalls.Load() != 0 {
		t.Fatal("TLS 握手数据不应进入 HTTP 处理器")
	}

	lines := logs.snapshot()
	if len(lines) != 1 {
		t.Fatalf("应记录 1 条服务端提示，实际 %d: %q", len(lines), lines)
	}
	_, port, _ := net.SplitHostPort(addr)
	for _, want := range []string{"[client-hint]", "TLS 握手", "明文 HTTP 端口", ":" + port, "127.0.0.1"} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("日志缺少 %q: %s", want, lines[0])
		}
	}
	if strings.Contains(lines[0], string(tlsClientHelloFixture)) {
		t.Fatal("日志不应包含握手字节")
	}
}

func TestPlaintextTLSGuardMakesHTTPSClientsFailFastWithReadableError(t *testing.T) {
	logs := &guardLogRecorder{}
	addr := startGuardedServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("HTTPS 客户端的请求不应到达处理器")
	}), newPlaintextTLSGuard(logs.logf))

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	started := time.Now()
	_, err := client.Get("https://" + addr + "/v1/models")
	if err == nil {
		t.Fatal("https:// 访问明文端口必须失败")
	}
	// Go 客户端识别到 HTTP 回应后给出可读错误；其他语言的 TLS 库只会看到版本或记录层错误，
	// 因此服务端日志才是排查依据。
	if !strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") {
		t.Fatalf("错误信息不符合预期: %v", err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("客户端应快速失败")
	}
	if got := len(logs.snapshot()); got != 1 {
		t.Fatalf("服务端日志条数=%d, want 1", got)
	}
}

func TestPlaintextTLSGuardLeavesNormalHTTPUntouched(t *testing.T) {
	logs := &guardLogRecorder{}
	var bodies []string
	var mu sync.Mutex
	addr := startGuardedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, r.Method+" "+r.URL.Path+" "+string(data))
		mu.Unlock()
		w.Header().Set("X-Seen", "1")
		_, _ = io.WriteString(w, "pong")
	}), newPlaintextTLSGuard(logs.logf))

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: false}}
	for i := 0; i < 3; i++ { // 同一连接上的多次请求都不受影响
		resp, err := client.Post("http://"+addr+"/v1/chat/completions", "application/json", bytes.NewReader([]byte(`{"n":1}`)))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "pong" || resp.Header.Get("X-Seen") != "1" {
			t.Fatalf("正常请求被改变: status=%d body=%q", resp.StatusCode, body)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 3 || bodies[0] != `POST /v1/chat/completions {"n":1}` {
		t.Fatalf("处理器收到的请求被改写: %q", bodies)
	}
	if len(logs.snapshot()) != 0 {
		t.Fatalf("正常 HTTP 不应产生提示日志: %q", logs.snapshot())
	}
}

func TestPlaintextTLSGuardDoesNotBlockAcceptOnSilentConnections(t *testing.T) {
	logs := &guardLogRecorder{}
	addr := startGuardedServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}), newPlaintextTLSGuard(logs.logf))

	silent, err := net.Dial("tcp", addr) // 连上但一个字节都不发
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("沉默连接不应拖住后续连接: %v", err)
	}
	resp.Body.Close()
}

func TestPlaintextTLSGuardRateLimitsLogLinesAndReportsSuppressed(t *testing.T) {
	logs := &guardLogRecorder{}
	now := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	var clockMu sync.Mutex
	guard := newPlaintextTLSGuard(logs.logf)
	guard.interval = time.Minute
	guard.now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	addr := startGuardedServer(t, http.NotFoundHandler(), guard)

	attempt := func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = conn.Write(tlsClientHelloFixture)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.ReadAll(conn)
	}
	for i := 0; i < 5; i++ {
		attempt()
	}
	if got := len(logs.snapshot()); got != 1 {
		t.Fatalf("同一窗口内应只记 1 条，实际 %d", got)
	}
	clockMu.Lock()
	now = now.Add(2 * time.Minute)
	clockMu.Unlock()
	attempt()
	lines := logs.snapshot()
	if len(lines) != 2 || !strings.Contains(lines[1], "已抑制同类提示 4 次") {
		t.Fatalf("窗口结束后应再记 1 条并说明抑制次数: %q", lines)
	}
}

func TestListenGatewayWrapsTheProductionListener(t *testing.T) {
	listener, err := listenGateway("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write(tlsClientHelloFixture)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := io.ReadAll(conn)
	if err != nil || !strings.HasPrefix(string(reply), "HTTP/1.1 400 Bad Request") {
		t.Fatalf("生产监听器应带有 TLS 识别: err=%v reply=%q", err, reply)
	}

	resp, err := http.Get("http://" + listener.Addr().String() + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("普通请求 status=%d", resp.StatusCode)
	}
}
