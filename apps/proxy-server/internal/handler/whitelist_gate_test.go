package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeWhitelistStore injects whitelist rules without a real DB (阶段二 2.5).
type fakeWhitelistStore struct {
	rules []WhitelistRule
	err   error
}

func (f *fakeWhitelistStore) ListRules(ctx context.Context) ([]WhitelistRule, error) {
	return f.rules, f.err
}

func newCheckerWithRules(rules []WhitelistRule) *WhitelistChecker {
	tenantID := "tenant_default"
	if len(rules) > 0 {
		tenantID = rules[0].TenantID
	}
	return &WhitelistChecker{
		store:       &fakeWhitelistStore{rules: rules},
		cacheExpiry: time.Minute,
		tenantID:    tenantID,
	}
}

func successfulEmptyWhitelistChecker() *WhitelistChecker {
	checker := newCheckerWithRules(nil)
	checker.tenantID = "tenant_default"
	return checker
}

// 不在白名单的目标被拒
func TestCheck_DeniesHostNotInWhitelist(t *testing.T) {
	checker := newCheckerWithRules([]WhitelistRule{
		{HostPattern: "*.openai.com", Port: 443, AuditEnabled: true, TenantID: "tenant_x"},
	})

	allowed, _, _ := checker.Check("evil.example.com:443")
	if allowed {
		t.Errorf("Expected evil.example.com to be denied when not in whitelist")
	}

	allowed, audit, tenant := checker.Check("api.openai.com:443")
	if !allowed {
		t.Errorf("Expected api.openai.com to be allowed (matches *.openai.com)")
	}
	if !audit {
		t.Errorf("Expected audit enabled for matched rule")
	}
	if tenant != "tenant_x" {
		t.Errorf("Expected tenant 'tenant_x', got '%s'", tenant)
	}
}

// 零规则时放行（灰度 opt-in，保持既有放行语义）
func TestCheck_EmptyRulesAllowAll(t *testing.T) {
	checker := newCheckerWithRules([]WhitelistRule{})
	allowed, _, _ := checker.Check("anything.example.com:443")
	if !allowed {
		t.Errorf("Expected allow-all when whitelist has zero rules")
	}
}

// CONNECT 到不在白名单的目标 -> 403
func TestHandleConnect_ForbidsUnlistedHost(t *testing.T) {
	checker := newCheckerWithRules([]WhitelistRule{
		{HostPattern: "*.openai.com", Port: 443, AuditEnabled: true, TenantID: "tenant_x"},
	})
	h := &ProxyHandler{whitelistChecker: checker}

	r := &http.Request{
		Method: http.MethodConnect,
		Host:   "evil.example.com:443",
		Header: make(http.Header),
	}
	w := httptest.NewRecorder()

	h.handleConnect(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for unlisted CONNECT host, got %d", w.Code)
	}
}
