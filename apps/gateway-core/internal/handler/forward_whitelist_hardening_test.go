package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestForwardWhitelistHardeningDeploymentModes(t *testing.T) {
	t.Setenv("PROXY_WHITELIST_FAIL_MODE", "closed")
	for _, tc := range []struct {
		name, mode, audit string
		enforce, gap      bool
	}{
		{"deny_unlisted", "deny_unlisted", "false", true, false},
		{"tunnel_audit", "tunnel_audit", "false", false, true},
		{"audit_only", "deny_unlisted", "true", false, false},
		{"failure_closed", "deny_unlisted", "false", true, true},
		{"failure_audit_only", "deny_unlisted", "true", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", tc.audit)
			h := &ForwardProxyHandler{lastReload: time.Now(), forwardProxyMode: tc.mode}
			if strings.HasPrefix(tc.name, "failure") {
				h.reloadWhitelist()
			}
			outcome, _ := h.whitelistOutcome(context.Background(), "unlisted.example", 443)
			if outcome.Enforce != tc.enforce || outcome.Gap != tc.gap {
				t.Fatalf("outcome=%+v", outcome)
			}
		})
	}
}

func TestForwardWhitelistHardeningMatchesHostAndPort(t *testing.T) {
	h := &ForwardProxyHandler{lastReload: time.Now(), whitelist: []whitelistEntry{
		{pattern: "*.openai.com", port: 443},
		{pattern: "api.example.com", port: 8443},
		{pattern: "invalid.example", port: 0},
	}}
	for _, tc := range []struct {
		host    string
		port    int
		allowed bool
	}{
		{"api.openai.com", 443, true}, {"openai.com", 443, true},
		{"evilopenai.com", 443, false}, {"api.openai.com", 80, false},
		{"API.EXAMPLE.COM.", 8443, true}, {"api.example.com", 443, false},
		{"unlisted.example", 443, false},
		{"invalid.example", 443, false},
	} {
		if got := h.isHostAllowed(tc.host, tc.port); got != tc.allowed {
			t.Errorf("%s:%d allowed=%v want=%v", tc.host, tc.port, got, tc.allowed)
		}
	}
	if (&ForwardProxyHandler{}).isHostAllowed("unlisted.example", 443) {
		t.Fatal("gateway empty whitelist must deny unlisted targets")
	}
}

func TestForwardWhitelistHardeningStoreFailureSwitch(t *testing.T) {
	t.Setenv("GATEWAY_FORWARD_PROXY_MODE", "deny_unlisted")
	for _, auditOnly := range []string{"false", "true"} {
		for _, failMode := range []string{"closed", "open"} {
			t.Run(auditOnly+"/"+failMode, func(t *testing.T) {
				t.Setenv("SECURITY_AUDIT_ONLY", auditOnly)
				t.Setenv("PROXY_WHITELIST_FAIL_MODE", failMode)
				h := NewForwardProxyHandler(nil, "tenant_default", "")
				outcome, reason := h.whitelistOutcome(context.Background(), "public.example", 443)
				wantEnforce := auditOnly == "false" && failMode == "closed"
				if outcome.Enforce != wantEnforce || !outcome.Gap || reason != "proxy_whitelist_unavailable" {
					t.Fatalf("failMode=%s auditOnly=%s outcome=%+v reason=%s", failMode, auditOnly, outcome, reason)
				}
			})
		}
	}
}

func TestForwardWhitelistHardeningRejectsBeforeEgress(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	t.Setenv("GATEWAY_FORWARD_PROXY_MODE", "deny_unlisted")
	for _, method := range []string{http.MethodConnect, http.MethodGet} {
		h := &ForwardProxyHandler{tenantID: "tenant_default", lastReload: time.Now()}
		r := httptest.NewRequest(method, "http://unlisted.invalid/path", nil)
		if method == http.MethodConnect {
			r.Host = "unlisted.invalid:443"
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "whitelist") {
			t.Fatalf("%s whitelist must reject before DNS: status=%d body=%s", method, w.Code, w.Body.String())
		}
	}
}
