package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
)

func TestProxyHeaderConflictAuditsBeforeAnyDownstream(t *testing.T) {
	const aCanary, bCanary = "proxy-agent-new-canary", "proxy-agent-old-canary"
	auditCalls := 0
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auditCalls++
		body, _ := io.ReadAll(r.Body)
		captured = string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	h := NewProxyHandler(nil, nil, nil, nil, headeraudit.NewClient(srv.URL, "secret"))
	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	req.Header["X-JJDGuard-Agent-Type"] = []string{aCanary}
	req.Header["X-NewAPI-Agent-Type"] = []string{bCanary}
	w := httptest.NewRecorder()
	h.Handle(w, req)
	if w.Code != http.StatusBadRequest || auditCalls != 1 {
		t.Fatalf("status=%d audits=%d body=%s", w.Code, auditCalls, w.Body.String())
	}
	for _, output := range []string{w.Body.String(), captured} {
		if strings.Contains(output, aCanary) || strings.Contains(output, bCanary) {
			t.Fatal("canary leaked")
		}
	}
}

func TestProxyHeaderConflictAuditUnavailableIs503(t *testing.T) {
	h := NewProxyHandler(nil, nil, nil, nil, headeraudit.NewClient("", ""))
	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	req.Header["X-JJDGuard-Agent-Type"] = []string{"proxy-new-canary"}
	req.Header["X-NewAPI-Agent-Type"] = []string{"proxy-old-canary"}
	w := httptest.NewRecorder()
	h.Handle(w, req)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "header_conflict_audit_unavailable") || strings.Contains(w.Body.String(), "canary") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestProxyHTTPHeaderConflictPersistsToRealCentral(t *testing.T) {
	central := os.Getenv("HEADER_CONTRACT_CENTRAL_URL")
	if central == "" {
		t.Skip("real central fixture is not configured")
	}
	h := NewProxyHandler(nil, nil, nil, nil, headeraudit.NewClient(central, "secret"))
	req := httptest.NewRequest(http.MethodGet, "http://example.invalid/path", nil)
	req.Header.Set("X-Request-Id", "r2-proxy-http")
	req.Header["X-JJDGuard-Agent-Type"] = []string{"proxy-http-new-canary"}
	req.Header["X-NewAPI-Agent-Type"] = []string{"proxy-http-old-canary"}
	w := httptest.NewRecorder()
	h.Handle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "canary") {
		t.Fatalf("conflict values leaked: %s", w.Body.String())
	}
}
