package handler

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 正向代理 HTTPS（MITM）：上游连不上、读响应体失败时，serveOneMITMRequest 以前直接 return，
// request_logs 停在开头写的 in_progress。上游失败是请求的终态，审计要写 error/502，
// 客户端也要收到 502，和 keep-alive RoundTrip 失败分支同一口径。
// MITM 的上游请求不随客户端断开取消（ctx 派生自 Background），这里的失败都是真实上游失败。
func TestServeOneMITMRequestUpstreamFailureFinalizesAudit(t *testing.T) {
	cert := genTestCert(t)
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	cases := []struct {
		name      string
		keepAlive bool
		upstream  func(t *testing.T) string
	}{
		{"dial_refused/oneshot", false, closedAddr},
		{"dial_refused/keepalive", true, closedAddr},
		{"header_hangup/keepalive", true, func(t *testing.T) string { return hangupUpstream(t, cert, false) }},
		{"body_hangup/keepalive", true, func(t *testing.T) string { return hangupUpstream(t, cert, true) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := &pfgDB{}
			writer := NewAuditWriter(nil)
			writer.db = db
			h := &ProxyHandler{
				securityClient: NewSecurityClient(quietSecuritySrv(t).URL),
				auditWriter:    writer,
				egressGuard:    redirectGuard(tc.upstream(t)),
			}
			if tc.keepAlive {
				trustingKeepAliveTransport(h, pool)
			}
			code := runOneMITMExchange(t, h, cert, pool, tc.keepAlive)

			status, auditCode := db.lastRequestLog(t)
			if status != "error" || auditCode != http.StatusBadGateway {
				t.Errorf("审计=%q/%d, want error/502（不能停在 in_progress）", status, auditCode)
			}
			if code != http.StatusBadGateway {
				t.Errorf("客户端收到 %d, want 502", code)
			}
			db.requireDetachedWrites(t)
		})
	}
}

// runOneMITMExchange 在一条 MITM 隧道上发一个请求，返回客户端读到的状态码（读不到时为 0）。
func runOneMITMExchange(t *testing.T, h *ProxyHandler, cert tls.Certificate, pool *x509.CertPool, keepAlive bool) int {
	t.Helper()
	serverTLS, clientTLS, srvRaw, cliRaw := newMITMTunnel(t, cert, pool)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		r := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
		h.serveOneMITMRequest(serverTLS, bufio.NewReader(serverTLS), r, "api.deepseek.com:443", "tenant_default", true, keepAlive)
		_ = srvRaw.Close()
	}()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", strings.NewReader(`{"messages":[{"content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write: %v", err)
	}
	code := 0
	if resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req); err == nil {
		code = resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	_ = cliRaw.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not finish")
	}
	return code
}

// closedAddr 返回一个已关闭监听的本地地址：拨号必然被拒。
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// hangupUpstream 起一个 TLS 上游，读完请求后断开：afterHeader=false 时一个字节都不回（读响应头失败）；
// afterHeader=true 时先回声明了长度的响应头和半截正文（读响应体失败）。
func hangupUpstream(t *testing.T, cert tls.Certificate, afterHeader bool) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				if afterHeader {
					_, _ = fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"id\":")
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}
