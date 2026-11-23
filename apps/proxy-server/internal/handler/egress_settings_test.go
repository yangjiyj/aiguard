package handler

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
)

func guardWithSettings(ips map[string][]net.IPAddr, settings egresspolicy.Settings) *EgressGuard {
	guard := NewEgressGuard(fakeResolver{ips: ips}, nil)
	guard.SetSettingsSource(func(context.Context) egresspolicy.Settings { return settings })
	return guard
}

func TestEgressGuardSettingsDefaultStillDenies(t *testing.T) {
	guard := guardWithSettings(map[string][]net.IPAddr{"intranet.example": {{IP: net.ParseIP("10.0.0.7")}}}, egresspolicy.Settings{})
	if _, err := guard.Resolve(context.Background(), "intranet.example:443"); err == nil {
		t.Fatal("private target allowed with default settings")
	}
}

func TestEgressGuardSwitchesAllowTheirClass(t *testing.T) {
	for _, tc := range []struct {
		name, address string
		ips           map[string][]net.IPAddr
		settings      egresspolicy.Settings
	}{
		{"private", "intranet.example:443", map[string][]net.IPAddr{"intranet.example": {{IP: net.ParseIP("10.0.0.7")}}}, egresspolicy.Settings{AllowPrivate: true}},
		{"tailscale", "100.64.0.21:8081", nil, egresspolicy.Settings{AllowPrivate: true}},
		{"loopback literal", "127.0.0.1:80", nil, egresspolicy.Settings{AllowLoopback: true}},
		{"metadata hostname", "metadata.google.internal:80", map[string][]net.IPAddr{"metadata.google.internal": {{IP: net.ParseIP("169.254.169.254")}}}, egresspolicy.Settings{AllowMetadata: true}},
		{"cidr", "intranet.example:443", map[string][]net.IPAddr{"intranet.example": {{IP: net.ParseIP("10.0.0.7")}}}, egresspolicy.Settings{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.7/32")}}},
	} {
		target, err := guardWithSettings(tc.ips, tc.settings).Resolve(context.Background(), tc.address)
		if err != nil || !target.ViaSetting {
			t.Errorf("%s: target=%+v err=%v", tc.name, target, err)
		}
	}
	// 只开内网不放开阿里云元数据（它落在 CGNAT 段里）。
	if _, err := guardWithSettings(nil, egresspolicy.Settings{AllowPrivate: true}).Resolve(context.Background(), "100.100.100.200:80"); err == nil {
		t.Fatal("allow_private must not open the Alibaba Cloud metadata address")
	}
}

func TestEgressGuardHostListDoesNotSurviveDNSRebind(t *testing.T) {
	settings := egresspolicy.Settings{AllowedHosts: []string{"metadata.google.internal"}}
	guard := guardWithSettings(map[string][]net.IPAddr{"metadata.google.internal": {{IP: net.ParseIP("169.254.169.254")}}}, settings)
	if _, err := guard.Resolve(context.Background(), "metadata.google.internal:80"); err == nil || !strings.Contains(err.Error(), "blocked egress target") {
		t.Fatalf("listed hostname resolving to metadata must stay denied, got %v", err)
	}
}

func TestWhitelistDecisionReadsConsoleSettingsBeforeEnvironment(t *testing.T) {
	t.Setenv("PROXY_WHITELIST_FAIL_MODE", "open")
	checker := newCheckerWithRules([]WhitelistRule{{HostPattern: "*.openai.com", Port: 443, TenantID: "tenant_default"}})
	checker.settingsValues = func(context.Context) map[string]string {
		return map[string]string{egresspolicy.KeyUnlistedAction: "allow_audit"}
	}
	if d := checker.decide(context.Background(), "unlisted.example", 443, 1); d.Outcome.Enforce || d.Reason != "proxy_whitelist_unlisted" {
		t.Fatalf("allow_audit decision = %+v", d)
	}
	failing := &WhitelistChecker{store: &fakeWhitelistStore{err: fmt.Errorf("db down")}, tenantID: "tenant_default"}
	failing.settingsValues = func(context.Context) map[string]string {
		return map[string]string{egresspolicy.KeyWhitelistFailMode: "closed"}
	}
	if d := failing.decide(context.Background(), "x.example", 443, 1); !d.Outcome.Enforce {
		t.Fatalf("stored closed must beat env open: %+v", d)
	}
	failing.settingsValues = func(context.Context) map[string]string { return map[string]string{} }
	if d := failing.decide(context.Background(), "x.example", 443, 1); d.Outcome.Enforce {
		t.Fatalf("without a stored key the env initial value (open) applies: %+v", d)
	}
}

func TestProxyConnectDeniedInternalTargetRecordsSecurityEvent(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	db := &pfgDB{}
	checker := newCheckerWithRules([]WhitelistRule{{HostPattern: "intranet.example", Port: 443, TenantID: "tenant_default", AuditEnabled: true}})
	h := NewProxyHandler(checker, nil, nil, &AuditWriter{db: db}, nil)
	h.egressGuard = guardWithSettings(map[string][]net.IPAddr{"intranet.example": {{IP: net.ParseIP("10.0.0.7")}}}, egresspolicy.Settings{})
	r := httptest.NewRequest(http.MethodConnect, "http://intranet.example:443", nil)
	r.Host = "intranet.example:443"
	w := httptest.NewRecorder()
	h.handleConnect(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	found := false
	for _, exec := range db.snapshot() {
		if !strings.Contains(exec.sql, "security_events") {
			continue
		}
		for _, arg := range exec.args {
			text := fmt.Sprint(arg)
			if raw, ok := arg.([]byte); ok {
				text = string(raw)
			}
			if strings.Contains(text, egresspolicy.ReasonInternalEgressDenied) {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("no security event with %s", egresspolicy.ReasonInternalEgressDenied)
	}
}
