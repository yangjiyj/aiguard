package handler

import (
	"context"
	"errors"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWhitelistHardeningAuditOnlyAndCoverageGaps(t *testing.T) {
	for _, tc := range []struct {
		name    string
		checker *WhitelistChecker
		reason  string
	}{
		{"missing", nil, "proxy_whitelist_unavailable"},
		{"empty", successfulEmptyWhitelistChecker(), "proxy_whitelist_empty"},
	} {
		d := tc.checker.decide(context.Background(), "public.example", 443, securityexit.Record)
		if d.Outcome.Enforce || !d.Outcome.Gap || d.Reason != tc.reason {
			t.Fatalf("%s decision=%+v", tc.name, d)
		}
	}
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	checker := newCheckerWithRules([]WhitelistRule{{HostPattern: "listed.example", Port: 80, TenantID: "tenant_x"}})
	h := NewProxyHandler(checker, nil, nil, nil, nil)
	calls := 0
	h.transport = fileDLPTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("upstream"))}, nil
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://unlisted.example/path", nil)
	r.Header.Set("X-Tenant-ID", "tenant_foreign")
	h.handleHTTP(w, r)
	if calls != 1 || w.Code != http.StatusOK {
		t.Fatalf("audit-only status=%d upstreamCalls=%d", w.Code, calls)
	}
}

func TestWhitelistHardeningFailureModes(t *testing.T) {
	for _, failure := range []string{"nil", "query"} {
		for _, mode := range []string{"closed", "open"} {
			t.Run(failure+"/"+mode, func(t *testing.T) {
				t.Setenv("PROXY_WHITELIST_FAIL_MODE", mode)
				w := NewWhitelistChecker(nil, "")
				if failure == "query" {
					w.store = &fakeWhitelistStore{err: errors.New("database unavailable")}
				}
				allowed, _, _ := w.Check("api.example.com:443")
				if allowed != (mode == "open") {
					t.Fatalf("failure=%s mode=%s allowed=%v", failure, mode, allowed)
				}
			})
		}
	}
}

func TestWhitelistHardeningTenantBoundaryAndPort(t *testing.T) {
	w := newCheckerWithRules([]WhitelistRule{
		{HostPattern: "*.openai.com", Port: 443, TenantID: "tenant_default", AuditEnabled: true},
		{HostPattern: "foreign.example", Port: 443, TenantID: "tenant_foreign", AuditEnabled: true},
		{HostPattern: "invalid.example", Port: 0, TenantID: "tenant_default", AuditEnabled: true},
	})
	w.tenantID = "tenant_default"
	for _, tc := range []struct {
		host    string
		allowed bool
	}{
		{"api.openai.com:443", true}, {"API.OPENAI.COM.:443", true},
		{"evilopenai.com:443", false}, {"api.openai.com:80", false}, {"foreign.example:443", false},
		{"invalid.example:443", false},
	} {
		allowed, _, tenant := w.Check(tc.host)
		if allowed != tc.allowed || tenant != "tenant_default" {
			t.Errorf("%s allowed=%v tenant=%s", tc.host, allowed, tenant)
		}
	}
}

func TestWhitelistHardeningHTTPRejectsBeforeTransport(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	checker := newCheckerWithRules([]WhitelistRule{{HostPattern: "listed.example", Port: 80, TenantID: "tenant_default"}})
	checker.tenantID = "tenant_default"
	calls := 0
	h := NewProxyHandler(checker, nil, nil, nil, nil)
	h.transport = fileDLPTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("upstream"))}, nil
	})
	w := httptest.NewRecorder()
	h.handleHTTP(w, httptest.NewRequest(http.MethodGet, "http://unlisted.example/path", nil))
	if w.Code != http.StatusForbidden || calls != 0 {
		t.Fatalf("status=%d upstreamCalls=%d", w.Code, calls)
	}
}
