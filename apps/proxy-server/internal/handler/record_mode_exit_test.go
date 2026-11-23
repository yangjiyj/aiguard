package handler

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// P0-3 invariant R: in record mode no security reason may interrupt a
// request. Detection that cannot run (queue full) is forwarded in every mode.

func TestRecordModeNeverEnforces_ForwardProxyInputBlockingActions(t *testing.T) {
	for _, action := range []string{"block", "reply", "deny", "quarantine"} {
		t.Run(action, func(t *testing.T) {
			runMITMUnknownJSONFileUploadTest(t, "application/json", action, mitmFileDLPExpectation{auditOnly: true})
		})
	}
}

func TestRecordModeNeverEnforces_ForwardProxyHTTPInputBlock(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"block","findings":[{"type":"file","category":"phone_cn","action":"block"}]}`)
	}))
	defer securityServer.Close()
	var upstreamCalls atomic.Int32
	h := NewProxyHandler(successfulEmptyWhitelistChecker(), nil, NewSecurityClient(securityServer.URL), nil, nil)
	h.transport = fileDLPTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("upstream reached")), Request: r}, nil
	})
	req := httptest.NewRequest(http.MethodPost, "http://files.example.test/upload/report.pdf", bytes.NewReader([]byte("%PDF-1.4\nphone\n")))
	req.Header.Set("Content-Type", "application/pdf")
	recorder := httptest.NewRecorder()

	h.handleHTTP(recorder, req)

	if recorder.Code != http.StatusOK || upstreamCalls.Load() != 1 {
		t.Fatalf("record mode must forward a blocked file: status=%d upstream=%d body=%s", recorder.Code, upstreamCalls.Load(), recorder.Body.String())
	}
}

// runMITMOutputBlockTest sends a clean input through the MITM path and has the
// security engine answer "block" for the model output.
func runMITMOutputBlockTest(t *testing.T, auditOnly string) (int, string) {
	t.Helper()
	t.Setenv("SECURITY_AUDIT_ONLY", auditOnly)
	cert := genTestCert(t)
	upstreamReply := `{"choices":[{"message":{"role":"assistant","content":"model reply"}}]}`
	ln, pool := fakeUpstreamWithHandler(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(upstreamReply))
	}))
	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/check-output/" {
			_, _ = w.Write([]byte(`{"action":"block","findings":[{"type":"pii","action":"block"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"action":"audit","findings":[]}`))
	}))
	t.Cleanup(securityServer.Close)
	h := &ProxyHandler{securityClient: NewSecurityClient(securityServer.URL), auditWriter: NewAuditWriter(nil), egressGuard: redirectGuard(ln.Addr().String())}
	h.mitmKeepAliveOnce.Do(func() {
		tr := h.egressGuard.HTTPTransport()
		tr.ForceAttemptHTTP2 = false
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "localhost", NextProtos: []string{"http/1.1"}}
		h.mitmKeepAliveRT = tr
	})
	serverTLS, clientTLS, srvRaw, cliRaw := newMITMTunnel(t, cert, pool)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		outer := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
		h.serveOneMITMRequest(serverTLS, bufio.NewReader(serverTLS), outer, "api.deepseek.com:443", "tenant_default", true, true)
		_ = srvRaw.Close()
	}()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", strings.NewReader(`{"model":"deepseek-chat","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "close")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = cliRaw.Close()
	select {
	case <-serverDone:
	case <-time.After(10 * time.Second):
		t.Fatal("MITM server did not finish")
	}
	return resp.StatusCode, string(body)
}

// runMITMInputActionTest sends a plain (non-file) chat request through the
// MITM path and has the security engine answer inputAction for the input.
func runMITMInputActionTest(t *testing.T, auditOnly, inputAction string) (int, string, int32) {
	t.Helper()
	t.Setenv("SECURITY_AUDIT_ONLY", auditOnly)
	cert := genTestCert(t)
	var upstreamCalls atomic.Int32
	ln, pool := fakeUpstreamWithHandler(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"model reply"}}]}`))
	}))
	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/check-input/" {
			_, _ = w.Write([]byte(`{"action":"` + inputAction + `","findings":[{"type":"pii","action":"` + inputAction + `"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"action":"audit","findings":[]}`))
	}))
	t.Cleanup(securityServer.Close)
	h := &ProxyHandler{securityClient: NewSecurityClient(securityServer.URL), auditWriter: NewAuditWriter(nil), egressGuard: redirectGuard(ln.Addr().String())}
	h.mitmKeepAliveOnce.Do(func() {
		tr := h.egressGuard.HTTPTransport()
		tr.ForceAttemptHTTP2 = false
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "localhost", NextProtos: []string{"http/1.1"}}
		h.mitmKeepAliveRT = tr
	})
	serverTLS, clientTLS, srvRaw, cliRaw := newMITMTunnel(t, cert, pool)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		outer := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
		h.serveOneMITMRequest(serverTLS, bufio.NewReader(serverTLS), outer, "api.deepseek.com:443", "tenant_default", true, true)
		_ = srvRaw.Close()
	}()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	_ = cliRaw.SetDeadline(time.Now().Add(15 * time.Second))
	req, _ := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", strings.NewReader(`{"model":"deepseek-chat","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "close")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = cliRaw.Close()
	select {
	case <-serverDone:
	case <-time.After(10 * time.Second):
		t.Fatal("MITM server did not finish")
	}
	return resp.StatusCode, string(body), upstreamCalls.Load()
}

func TestRecordModeNeverEnforces_ForwardProxyNonFileInput(t *testing.T) {
	for _, action := range []string{"block", "reply", "deny", "quarantine"} {
		t.Run(action, func(t *testing.T) {
			status, body, upstream := runMITMInputActionTest(t, "true", action)
			if status != http.StatusOK || upstream != 1 || !strings.Contains(body, "model reply") {
				t.Fatalf("record mode must forward: status=%d upstream=%d body=%s", status, upstream, body)
			}
		})
	}
}

func TestProtectModeBlocksForwardProxyNonFileInputBlockingSet(t *testing.T) {
	for _, action := range []string{"block", "reply", "deny", "quarantine"} {
		t.Run(action, func(t *testing.T) {
			status, body, upstream := runMITMInputActionTest(t, "false", action)
			if upstream != 0 || strings.Contains(body, "model reply") {
				t.Fatalf("protect mode must stop %s input: status=%d upstream=%d body=%s", action, status, upstream, body)
			}
		})
	}
	t.Run("mask_is_not_blocking", func(t *testing.T) {
		_, _, upstream := runMITMInputActionTest(t, "false", "mask")
		if upstream != 1 {
			t.Fatalf("mask must not block, upstream=%d", upstream)
		}
	})
}

func TestRecordModeNeverEnforces_ForwardProxyBufferedOutput(t *testing.T) {
	status, body := runMITMOutputBlockTest(t, "true")
	if status != http.StatusOK || !strings.Contains(body, "model reply") {
		t.Fatalf("record mode must return the original model output, got %d body=%s", status, body)
	}
}

func TestProtectModeBlocksForwardProxyBufferedOutput(t *testing.T) {
	status, body := runMITMOutputBlockTest(t, "false")
	if status != http.StatusForbidden || strings.Contains(body, "model reply") {
		t.Fatalf("protect mode must replace a blocked model output, got %d body=%s", status, body)
	}
}

// A full inspection queue is a capacity gap, not a verdict: the large request
// is forwarded unbuffered in both modes and the security engine is not asked
// about the input.
func TestForwardProxyQueueFullForwardsAsCoverageGap(t *testing.T) {
	for _, mode := range []string{"true", "false"} {
		t.Run("SECURITY_AUDIT_ONLY="+mode, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", mode)
			previousWait := inspectionAdmissionWait
			inspectionAdmissionWait = 20 * time.Millisecond
			t.Cleanup(func() { inspectionAdmissionWait = previousWait })

			cert := genTestCert(t)
			var upstreamHits int64
			var upstreamBody atomic.Value
			ln, pool := fakeUpstreamWithHandler(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt64(&upstreamHits, 1)
				body, _ := io.ReadAll(r.Body)
				upstreamBody.Store(string(body))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			var inputChecks int64
			securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/check-input/" {
					atomic.AddInt64(&inputChecks, 1)
					_, _ = w.Write([]byte(`{"action":"block","findings":[{"type":"pii","action":"block"}]}`))
					return
				}
				_, _ = w.Write([]byte(`{"action":"audit","findings":[]}`))
			}))
			t.Cleanup(securityServer.Close)

			client := NewSecurityClient(securityServer.URL)
			client.inspectionQueue = &InspectionQueue{slots: make(chan struct{}, 1)}
			client.inspectionQueue.slots <- struct{}{} // queue is full
			h := &ProxyHandler{securityClient: client, auditWriter: NewAuditWriter(nil), egressGuard: redirectGuard(ln.Addr().String())}
			h.mitmKeepAliveOnce.Do(func() {
				tr := h.egressGuard.HTTPTransport()
				tr.ForceAttemptHTTP2 = false
				tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "localhost", NextProtos: []string{"http/1.1"}}
				h.mitmKeepAliveRT = tr
			})

			serverTLS, clientTLS, srvRaw, cliRaw := newMITMTunnel(t, cert, pool)
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				if err := serverTLS.Handshake(); err != nil {
					t.Errorf("server handshake: %v", err)
					return
				}
				outer := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
				h.serveOneMITMRequest(serverTLS, bufio.NewReader(serverTLS), outer, "api.deepseek.com:443", "tenant_default", true, true)
				_ = srvRaw.Close()
			}()
			if err := clientTLS.Handshake(); err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			// net.Pipe is synchronous: an implementation that answers without
			// reading the body would deadlock the test. Fail fast instead.
			_ = cliRaw.SetDeadline(time.Now().Add(15 * time.Second))
			payload := `{"model":"deepseek-chat","messages":[{"role":"user","content":"hello"}]}`
			// io.MultiReader hides the length, so the request is sent chunked
			// (ContentLength -1), which is what takes the admission path.
			req, err := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/chat/completions", io.MultiReader(strings.NewReader(payload)))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Connection", "close")
			if err := req.Write(clientTLS); err != nil {
				t.Fatalf("write request: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			respBody, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			_ = cliRaw.Close()
			select {
			case <-serverDone:
			case <-time.After(10 * time.Second):
				t.Fatal("MITM server did not finish")
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("queue full must forward as a coverage gap, got %d body=%s", resp.StatusCode, respBody)
			}
			if got := atomic.LoadInt64(&upstreamHits); got != 1 {
				t.Fatalf("upstream hits=%d want 1", got)
			}
			if got, _ := upstreamBody.Load().(string); got != payload {
				t.Fatalf("upstream received %q, want the original body", got)
			}
			if got := atomic.LoadInt64(&inputChecks); got != 0 {
				t.Fatalf("a request without an inspection slot must not be inspected, got %d input checks", got)
			}
		})
	}
}
