package handler

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type mitmFileDLPExpectation struct {
	auditOnly   bool
	auditReader FileDLPSettingReader
	// forwarded: the action is not a configured block (e.g. an unmaskable
	// mask), so the original request reaches the upstream and is alerted.
	forwarded bool
}

func TestServeOneMITMRequestBlocksUnknownJSONFileUpload(t *testing.T) {
	runMITMUnknownJSONFileUploadTest(t, "application/json", "block", mitmFileDLPExpectation{})
}

func TestServeOneMITMRequestBlocksUnknownJSONFileUploadWithoutContentType(t *testing.T) {
	runMITMUnknownJSONFileUploadTest(t, "", "block", mitmFileDLPExpectation{})
}

// The proxy cannot mask a file; the configured action is "mask", not
// "block", so the file is forwarded and the gap is alerted.
func TestServeOneMITMRequestForwardsUnknownJSONFileUploadMask(t *testing.T) {
	runMITMUnknownJSONFileUploadTest(t, "application/json", "mask", mitmFileDLPExpectation{forwarded: true})
}

func TestServeOneMITMRequestAuditOnlyAllowsUnknownJSONFileUploadWhenDatabaseIsFalse(t *testing.T) {
	runMITMUnknownJSONFileUploadTest(t, "application/json", "block", mitmFileDLPExpectation{
		auditOnly:   true,
		auditReader: &countingFileDLPSettingReader{value: false},
	})
}

func runMITMUnknownJSONFileUploadTest(t *testing.T, contentType, action string, expectation mitmFileDLPExpectation) {
	t.Helper()
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	if expectation.auditOnly {
		t.Setenv("SECURITY_AUDIT_ONLY", "true")
	} else {
		t.Setenv("SECURITY_AUDIT_ONLY", "false")
	}

	cert := genTestCert(t)
	var upstreamHits int64
	ln, pool := fakeUpstream(t, cert, &upstreamHits)

	var securityHits int64
	var receivedInput map[string]interface{}
	var receivedTextInput map[string]interface{}
	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&securityHits, 1)
		defer r.Body.Close()
		received := map[string]interface{}{}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode security request: %v", err)
		}
		if r.URL.Path == "/check-input/" {
			context, _ := received["context"].(map[string]interface{})
			attachments, _ := context["attachments"].([]interface{})
			if len(attachments) > 0 {
				receivedInput = received
			} else {
				receivedTextInput = received
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"`+action+`","findings":[{"type":"file","action":"`+action+`"}]}`)
	}))
	t.Cleanup(securityServer.Close)

	securityClient := NewSecurityClient(securityServer.URL)
	if expectation.auditReader != nil {
		securityClient.WithSecurityAuditOnlySettingReader(expectation.auditReader)
	}
	h := &ProxyHandler{
		securityClient: securityClient,
		auditWriter:    NewAuditWriter(nil),
		egressGuard:    redirectGuard(ln.Addr().String()),
	}
	h.mitmKeepAliveOnce.Do(func() {
		tr := h.egressGuard.HTTPTransport()
		tr.ForceAttemptHTTP2 = false
		tr.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
			ServerName: "localhost",
			NextProtos: []string{"http/1.1"},
		}
		h.mitmKeepAliveRT = tr
	})

	srvRaw, cliRaw := net.Pipe()
	serverTLS := tls.Server(srvRaw, &tls.Config{Certificates: []tls.Certificate{cert}})
	clientTLS := tls.Client(cliRaw, &tls.Config{RootCAs: pool, ServerName: "api.deepseek.com"})
	serverDone := make(chan bool, 1)
	go func() {
		defer close(serverDone)
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		outer := httptest.NewRequest(http.MethodConnect, "https://api.deepseek.com:443", nil)
		serverDone <- h.serveOneMITMRequest(serverTLS, bufio.NewReader(serverTLS), outer, "api.deepseek.com:443", "tenant_default", true, true)
		_ = srvRaw.Close()
	}()

	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	body := `{"model":"gpt-test","input":[{"role":"user","content":[{"type":"input_text","text":"summarize this file"},{"type":"input_file","filename":"report.pdf","file_data":"JVBERi0xLjQ="}]}]}`
	req, err := http.NewRequest(http.MethodPost, "https://api.deepseek.com/v1/responses", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Connection", "close")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	_ = cliRaw.Close()

	wantStatus := http.StatusForbidden
	// User text and attachment bytes have separate source and authorization.
	wantSecurityHits := int64(2)
	wantUpstreamHits := int64(0)
	if expectation.auditOnly || expectation.forwarded {
		wantStatus = http.StatusOK
		wantSecurityHits = 3 // Two input sources and one non-streaming output.
		wantUpstreamHits = 1
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("unknown JSON file upload status=%d, want %d", resp.StatusCode, wantStatus)
	}
	select {
	case <-serverDone:
	case <-time.After(10 * time.Second):
		t.Fatal("MITM server did not finish")
	}
	if got := atomic.LoadInt64(&securityHits); got != wantSecurityHits {
		t.Fatalf("security-engine calls=%d, want %d", got, wantSecurityHits)
	}
	if got := atomic.LoadInt64(&upstreamHits); got != wantUpstreamHits {
		t.Fatalf("unknown JSON file reached upstream %d time(s), want %d", got, wantUpstreamHits)
	}
	context, ok := receivedInput["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("input security context missing: %#v", receivedInput)
	}
	attachments, ok := context["attachments"].([]interface{})
	if !ok || len(attachments) != 1 {
		t.Fatalf("unknown JSON attachment missing from security request: %#v", context["attachments"])
	}
	if receivedInput["content"] != "" || context["user_task"] != "summarize this file" || context["user_task_complete"] != true {
		t.Fatalf("file source inherited unrelated text or incomplete authorization: %#v", receivedInput)
	}
	if receivedTextInput["content"] != "summarize this file" {
		t.Fatalf("user instruction was not inspected independently: %#v", receivedTextInput)
	}
}
