package handler

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCapacityAdmissionDoesNotWaitWhenInspectionIsDisabled(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", "true")
	originalWait := inspectionAdmissionWait
	inspectionAdmissionWait = 2 * time.Second
	t.Cleanup(func() { inspectionAdmissionWait = originalWait })
	cert := genTestCert(t)
	upstream, pool := fakeUpstreamWithHandler(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "disabled inspection forwarded")
	}))
	h := &ProxyHandler{
		securityClient: &SecurityClient{inspectionQueue: &InspectionQueue{}},
		auditWriter:    NewAuditWriter(nil), egressGuard: redirectGuard(upstream.Addr().String()),
	}
	trustingKeepAliveTransport(h, pool)
	serverTLS, clientTLS, serverRaw, clientRaw := newMITMTunnel(t, cert, pool)
	t.Cleanup(func() { _ = serverRaw.Close(); _ = clientRaw.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverRaw.Close()
		if err := serverTLS.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		connect := httptest.NewRequest(http.MethodConnect, "https://example.test:443", nil)
		h.serveOneMITMRequest(serverTLS, bufio.NewReader(serverTLS), connect, "example.test:443", "tenant_default", false, true)
	}()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	_ = clientRaw.SetDeadline(time.Now().Add(time.Second))
	request, err := http.NewRequest(http.MethodPost, "https://example.test/upload", io.NopCloser(strings.NewReader("safe request")))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength, request.Close = -1, true
	var response *http.Response
	responseErr := request.Write(clientTLS)
	if responseErr == nil {
		response, responseErr = http.ReadResponse(bufio.NewReader(clientTLS), request)
	}
	var body []byte
	if responseErr == nil {
		body, responseErr = io.ReadAll(response.Body)
		_ = response.Body.Close()
	}
	_ = clientRaw.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = serverRaw.Close()
		t.Fatal("MITM server did not finish")
	}
	if responseErr != nil || response == nil || response.StatusCode != http.StatusOK || string(body) != "disabled inspection forwarded" {
		t.Fatalf("disabled inspection must not wait on detector slots: response=%v err=%v body=%s", response, responseErr, body)
	}
}
