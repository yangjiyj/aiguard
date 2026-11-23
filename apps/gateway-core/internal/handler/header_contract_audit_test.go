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

type headerContractRoundTrip func(*http.Request) (*http.Response, error)

func (f headerContractRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReverseProxyHeaderConflictAuditsBeforeRoundTrip(t *testing.T) {
	const aCanary, bCanary = "agent-new-canary", "agent-old-canary"
	auditCalls := 0
	var captured string
	auditServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auditCalls++
		body, _ := io.ReadAll(r.Body)
		captured = string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer auditServer.Close()
	roundTrips := 0
	h := &ReverseProxyHandler{
		routes:      []ReverseProxyRoute{{PathPrefix: "/", TargetURL: "http://example.invalid", Status: "active"}},
		headerAudit: headeraudit.NewClient(auditServer.URL, "secret"),
		client: &http.Client{Transport: headerContractRoundTrip(func(*http.Request) (*http.Response, error) {
			roundTrips++
			return nil, nil
		})},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header["X-JJDGuard-Agent-Type"] = []string{aCanary}
	req.Header["X-NewAPI-Agent-Type"] = []string{bCanary}
	w := httptest.NewRecorder()
	if !h.ServeHTTP(w, req) {
		t.Fatal("route not handled")
	}
	if w.Code != http.StatusBadRequest || auditCalls != 1 || roundTrips != 0 {
		t.Fatalf("status=%d audit=%d roundtrip=%d body=%s", w.Code, auditCalls, roundTrips, w.Body.String())
	}
	for _, output := range []string{w.Body.String(), captured} {
		if strings.Contains(output, aCanary) || strings.Contains(output, bCanary) {
			t.Fatal("canary leaked")
		}
	}
}

func TestReverseProxyHeaderConflictAuditUnavailableIs503(t *testing.T) {
	h := &ReverseProxyHandler{
		routes:      []ReverseProxyRoute{{PathPrefix: "/", TargetURL: "http://example.invalid", Status: "active"}},
		headerAudit: headeraudit.NewClient("", ""),
		client:      &http.Client{Transport: headerContractRoundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("roundtrip called"); return nil, nil })},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header["X-JJDGuard-Session-Id"] = []string{"session-new-canary"}
	req.Header["X-NewAPI-Session-Id"] = []string{"session-old-canary"}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "header_conflict_audit_unavailable") || strings.Contains(w.Body.String(), "canary") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestReverseProxyHeaderConflictPersistsToRealCentral(t *testing.T) {
	central := os.Getenv("HEADER_CONTRACT_CENTRAL_URL")
	if central == "" {
		t.Skip("real central fixture is not configured")
	}
	roundTrips := 0
	h := &ReverseProxyHandler{
		routes:      []ReverseProxyRoute{{PathPrefix: "/", TargetURL: "http://example.invalid", Status: "active"}},
		headerAudit: headeraudit.NewClient(central, "secret"),
		client: &http.Client{Transport: headerContractRoundTrip(func(*http.Request) (*http.Response, error) {
			roundTrips++
			return nil, nil
		})},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Request-Id", "r2-gateway-reverse")
	req.Header["X-JJDGuard-Agent-Type"] = []string{"reverse-new-canary"}
	req.Header["X-NewAPI-Agent-Type"] = []string{"reverse-old-canary"}
	w := httptest.NewRecorder()
	if !h.ServeHTTP(w, req) || w.Code != http.StatusBadRequest || roundTrips != 0 {
		t.Fatalf("handled/status/roundtrips=true/%d/%d body=%s", w.Code, roundTrips, w.Body.String())
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "canary") {
		t.Fatalf("conflict values leaked: %s", w.Body.String())
	}
}
