package handler

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type capacityStreamModeReader struct{ audit *atomic.Bool }

func (r capacityStreamModeReader) Enabled(context.Context) bool { return r.audit.Load() }

func TestCapacityStreamEnvironmentCannotBypassProtectOutput(t *testing.T) {
	for _, startsInRecord := range []bool{false, true} {
		t.Run(map[bool]string{false: "protect", true: "runtime-switch-to-protect"}[startsInRecord], func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", "false")
			t.Setenv("PROXY_STREAM_LLM_RESPONSES", "true")
			var record atomic.Bool
			record.Store(startsInRecord)
			cert := genTestCert(t)
			upstream, pool := fakeUpstreamWithHandler(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				record.Store(false)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"protected output"}}]}`))
			}))
			engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/check-output/" {
					_, _ = w.Write([]byte(`{"action":"block","findings":[{"type":"dlp","rule_id":"configured-output","category":"data_exfiltration","action":"block"}]}`))
					return
				}
				_, _ = w.Write([]byte(`{"action":"allow","findings":[]}`))
			}))
			defer engine.Close()
			h := &ProxyHandler{
				securityClient: NewSecurityClient(engine.URL).WithSecurityAuditOnlySettingReader(capacityStreamModeReader{audit: &record}),
				auditWriter:    NewAuditWriter(nil), egressGuard: redirectGuard(upstream.Addr().String()),
			}
			trustingKeepAliveTransport(h, pool)
			serverTLS, clientTLS, serverRaw, clientRaw := newMITMTunnel(t, cert, pool)
			defer serverRaw.Close()
			defer clientRaw.Close()
			_ = serverRaw.SetDeadline(time.Now().Add(5 * time.Second))
			_ = clientRaw.SetDeadline(time.Now().Add(5 * time.Second))
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer serverRaw.Close()
				if err := serverTLS.Handshake(); err != nil {
					t.Errorf("server handshake: %v", err)
					return
				}
				connect := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
				h.serveOneMITMRequest(serverTLS, bufio.NewReader(serverTLS), connect, "api.deepseek.com:443", "tenant_default", true, true)
			}()
			if err := clientTLS.Handshake(); err != nil {
				t.Fatal(err)
			}
			request, _ := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"hello"}]}`))
			request.Header.Set("Content-Type", "application/json")
			request.Close = true
			if err := request.Write(clientTLS); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			<-done
			if response.StatusCode != http.StatusForbidden || strings.Contains(string(body), "protected output") {
				t.Fatalf("Protect must withhold configured output even with stream env: status=%d body=%s", response.StatusCode, body)
			}
		})
	}
}
