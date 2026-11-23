package handler

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func runMITMExchange(t *testing.T, h *ProxyHandler, host, rawRequest string, upstream http.Handler) int {
	t.Helper()
	cert := genTestCertFor(t, host)
	ln, pool := fakeUpstreamWithHandler(t, cert, upstream)
	h.egressGuard = redirectGuard(ln.Addr().String())
	if h.securityClient == nil {
		h.securityClient = NewSecurityClient(quietSecuritySrv(t).URL)
	}
	// keep-alive 模式走 RoundTrip，可注入信任假上游证书的 transport（与现有 MITM 链路测试同法）。
	h.mitmKeepAliveOnce.Do(func() {
		tr := h.egressGuard.HTTPTransport()
		tr.ForceAttemptHTTP2 = false
		tr.DisableCompression = true
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: host, NextProtos: []string{"http/1.1"}}
		h.mitmKeepAliveRT = tr
	})
	srvRaw, cliRaw := net.Pipe()
	serverTLS := tls.Server(srvRaw, &tls.Config{Certificates: []tls.Certificate{cert}})
	clientTLS := tls.Client(cliRaw, &tls.Config{RootCAs: pool, ServerName: host})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serverTLS.Handshake(); err != nil {
			return
		}
		r := httptest.NewRequest(http.MethodConnect, "https://"+host+":443", nil)
		r.RemoteAddr = "192.0.2.77:51000"
		h.serveOneMITMRequest(serverTLS, bufio.NewReader(serverTLS), r, host+":443", "tenant_default", true, true)
		_ = srvRaw.Close()
	}()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	_ = clientTLS.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientTLS.Write([]byte(rawRequest)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	_ = cliRaw.Close()
	<-done
	return resp.StatusCode
}

func TestForwardProxyPricedTrafficHasSecurityOnlySemantics(t *testing.T) {
	h := &ProxyHandler{auditWriter: NewAuditWriter(nil)}
	hits := 0
	body := `{"model":"priced-model"}`
	request := "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: 24\r\nAuthorization: Bearer client-owned-upstream-key\r\n\r\n" + body
	status := runMITMExchange(t, h, "api.openai.com", request, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("Authorization") != "Bearer client-owned-upstream-key" {
			t.Error("upstream credential not preserved")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":2,"completion_tokens":3}}`))
	}))
	if status != 200 || hits != 1 {
		t.Fatalf("security-only proxy status=%d upstream=%d", status, hits)
	}
}

func genTestCertFor(t *testing.T, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{host, "localhost"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
