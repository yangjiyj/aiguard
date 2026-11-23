package handler

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
)

func TestForwardEgressDefaultDeniesInternalTargets(t *testing.T) {
	for _, tc := range []struct{ host, ip string }{
		{"intranet.example", "10.0.0.7"},
		{"loop.example", "127.0.0.1"},
		{"meta.example", "169.254.169.254"},
		{"aliyun-meta.example", "100.100.100.200"},
		{"localhost", "127.0.0.1"},
		{"metadata.google.internal", "169.254.169.254"},
		{"10.0.0.7", "10.0.0.7"},
	} {
		_, viaSetting, err := resolveForwardEgressTarget(context.Background(), tc.host, 443, egresspolicy.Settings{}, lookupIPs(tc.ip))
		if err == nil || viaSetting {
			t.Errorf("%s -> %s allowed by default (err=%v)", tc.host, tc.ip, err)
		}
	}
	target, viaSetting, err := resolveForwardEgressTarget(context.Background(), "api.example.com", 443, egresspolicy.Settings{}, lookupIPs("203.0.113.10"))
	if err != nil || viaSetting || target.DialAddress != "203.0.113.10:443" {
		t.Fatalf("public target = %+v via=%v err=%v", target, viaSetting, err)
	}
}

func TestForwardEgressSwitchesAllowTheirClassAndPin(t *testing.T) {
	for _, tc := range []struct {
		name     string
		host, ip string
		settings egresspolicy.Settings
	}{
		{"private", "intranet.example", "10.0.0.7", egresspolicy.Settings{AllowPrivate: true}},
		{"loopback", "loop.example", "127.0.0.1", egresspolicy.Settings{AllowLoopback: true}},
		{"metadata", "meta.example", "169.254.169.254", egresspolicy.Settings{AllowMetadata: true}},
		{"cidr", "intranet.example", "10.0.0.7", egresspolicy.Settings{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.7/32")}}},
	} {
		target, viaSetting, err := resolveForwardEgressTarget(context.Background(), tc.host, 8443, tc.settings, lookupIPs(tc.ip))
		if err != nil || !viaSetting || target.DialAddress != net.JoinHostPort(tc.ip, "8443") {
			t.Errorf("%s: target=%+v via=%v err=%v", tc.name, target, viaSetting, err)
		}
	}
	// 只开内网不放开元数据和回环。
	if _, _, err := resolveForwardEgressTarget(context.Background(), "x.example", 443, egresspolicy.Settings{AllowPrivate: true}, lookupIPs("100.100.100.200")); err == nil {
		t.Fatal("allow_private must not open the Alibaba Cloud metadata address")
	}
}

func TestForwardEgressHostListIsExactAndStillChecksResolvedAddress(t *testing.T) {
	settings := egresspolicy.Settings{AllowedHosts: []string{"svc.internal"}}
	// 主机名在名单里、解析到公网：放行。
	if _, via, err := resolveForwardEgressTarget(context.Background(), "svc.internal", 443, settings, lookupIPs("203.0.113.10")); err != nil || !via {
		t.Fatalf("listed internal hostname resolving public: via=%v err=%v", via, err)
	}
	// 名单精确匹配：子域、相似名照拒。
	if _, _, err := resolveForwardEgressTarget(context.Background(), "a.svc.internal", 443, settings, lookupIPs("203.0.113.10")); err == nil {
		t.Fatal("subdomain of an exact host entry must stay denied")
	}
	// DNS 重绑定到私网：主机名在名单里也照拒（名单按解析后的地址判）。
	if _, _, err := resolveForwardEgressTarget(context.Background(), "svc.internal", 443, settings, lookupIPs("10.0.0.7")); err == nil {
		t.Fatal("listed hostname rebinding to a private address must stay denied")
	}
	// 混合应答里只要有一个未放行的内网地址就整体拒绝。
	if _, _, err := resolveForwardEgressTarget(context.Background(), "api.example.com", 443, egresspolicy.Settings{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.7/32")}}, lookupIPs("10.0.0.7", "10.0.0.8")); err == nil {
		t.Fatal("mixed answer with an unlisted private address must fail closed")
	}
}

func forwardProxyWithRuntime(values map[string]string, recorder *fakeReverseProxyAuditRecorder, lookup lookupIPAddrFunc) *ForwardProxyHandler {
	return &ForwardProxyHandler{
		tenantID:      "tenant_default",
		lastReload:    time.Now(),
		auditRecorder: recorder,
		lookupIP:      lookup,
		runtimeValues: func(context.Context) (map[string]string, bool) { return values, values != nil },
	}
}

func securityEventReasons(recorder *fakeReverseProxyAuditRecorder) []string {
	var reasons []string
	for _, event := range recorder.securityEvents {
		reasons = append(reasons, event.record.InputSemanticReason)
	}
	return reasons
}

func TestForwardProxyDeniedInternalTargetRecordsSecurityEventEvenInRecordMode(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	recorder := &fakeReverseProxyAuditRecorder{}
	h := forwardProxyWithRuntime(map[string]string{}, recorder, lookupIPs("10.0.0.7"))
	h.whitelist = []whitelistEntry{{pattern: "intranet.example", port: 443}}
	r := httptest.NewRequest(http.MethodConnect, "http://intranet.example:443", nil)
	r.Host = "intranet.example:443"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := securityEventReasons(recorder); len(got) != 1 || got[0] != egresspolicy.ReasonInternalEgressDenied {
		t.Fatalf("security events = %v", got)
	}
	if recorder.securityEvents[0].actionTaken != "block" {
		t.Fatalf("action = %q", recorder.securityEvents[0].actionTaken)
	}
}

func TestForwardProxyAllowedInternalTargetForwardsAndRecordsEvent(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("internal-ok"))
	}))
	defer upstream.Close()
	port := upstream.Listener.Addr().(*net.TCPAddr).Port
	recorder := &fakeReverseProxyAuditRecorder{}
	h := forwardProxyWithRuntime(map[string]string{egresspolicy.KeyAllowLoopback: "true"}, recorder, lookupIPs("127.0.0.1"))
	h.whitelist = []whitelistEntry{{pattern: "intranet.example", port: port}}
	r := httptest.NewRequest(http.MethodGet, "http://intranet.example:"+strconv.Itoa(port)+"/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "internal-ok") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	found := false
	for _, reason := range securityEventReasons(recorder) {
		if reason == egresspolicy.ReasonInternalEgressAllowed {
			found = true
		}
	}
	if !found {
		t.Fatalf("security events = %v, want %s", securityEventReasons(recorder), egresspolicy.ReasonInternalEgressAllowed)
	}
}

func TestForwardWhitelistOutcomeReadsConsoleSettingsBeforeEnvironment(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	t.Setenv("GATEWAY_FORWARD_PROXY_MODE", "tunnel_audit")
	t.Setenv("PROXY_WHITELIST_FAIL_MODE", "open")
	// 库里没有键：环境变量作初值（与 2.9.21 一致）。
	h := forwardProxyWithRuntime(map[string]string{}, &fakeReverseProxyAuditRecorder{}, nil)
	h.forwardProxyMode = ""
	if outcome, _ := h.whitelistOutcome(context.Background(), "unlisted.example", 443); outcome.Enforce {
		t.Fatalf("env tunnel_audit without stored key must not enforce: %+v", outcome)
	}
	// 库里存了 deny：压过环境变量。
	h = forwardProxyWithRuntime(map[string]string{egresspolicy.KeyUnlistedAction: "deny"}, &fakeReverseProxyAuditRecorder{}, nil)
	if outcome, reason := h.whitelistOutcome(context.Background(), "unlisted.example", 443); !outcome.Enforce || reason != "proxy_whitelist_unlisted" {
		t.Fatalf("stored deny: outcome=%+v reason=%s", outcome, reason)
	}
	// 未登记目标设为放行审计：不拦，记缺口。
	t.Setenv("GATEWAY_FORWARD_PROXY_MODE", "deny_unlisted")
	h = forwardProxyWithRuntime(map[string]string{egresspolicy.KeyUnlistedAction: "allow_audit"}, &fakeReverseProxyAuditRecorder{}, nil)
	if outcome, _ := h.whitelistOutcome(context.Background(), "unlisted.example", 443); outcome.Enforce || !outcome.Gap {
		t.Fatalf("stored allow_audit: outcome=%+v", outcome)
	}
	// 白名单读取失败：库里 closed 压过环境变量 open。
	h = forwardProxyWithRuntime(map[string]string{egresspolicy.KeyWhitelistFailMode: "closed"}, &fakeReverseProxyAuditRecorder{}, nil)
	h.lastReload = time.Time{}
	h.reloadWhitelist()
	if outcome, reason := h.whitelistOutcome(context.Background(), "public.example", 443); !outcome.Enforce || reason != "proxy_whitelist_unavailable" {
		t.Fatalf("stored closed: outcome=%+v reason=%s", outcome, reason)
	}
	h = forwardProxyWithRuntime(map[string]string{egresspolicy.KeyWhitelistFailMode: "open"}, &fakeReverseProxyAuditRecorder{}, nil)
	h.reloadWhitelist()
	if outcome, _ := h.whitelistOutcome(context.Background(), "public.example", 443); outcome.Enforce {
		t.Fatalf("stored open: outcome=%+v", outcome)
	}
}

func TestGatewayConfigCarriesSignedForwardProxySettings(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
	payload[egresspolicy.KeyAllowPrivate] = true
	payload[egresspolicy.KeyAllowedCIDRs] = `["10.0.0.0/8"]`
	payload[egresspolicy.KeyUnlistedAction] = "allow_audit"
	resignGatewayPayload(t, payload)
	config, err := fetchGatewayPayload(t, payload)
	if err != nil {
		t.Fatalf("signed forward proxy settings rejected: %v", err)
	}
	if config.ForwardProxy[egresspolicy.KeyAllowPrivate] != "true" || config.ForwardProxy[egresspolicy.KeyAllowedCIDRs] != `["10.0.0.0/8"]` || config.ForwardProxy[egresspolicy.KeyUnlistedAction] != "allow_audit" {
		t.Fatalf("forward proxy values = %v", config.ForwardProxy)
	}
	if _, ok := config.ForwardProxy[egresspolicy.KeyWhitelistFailMode]; ok {
		t.Fatal("a key the control plane did not send must stay absent so the environment initial value applies")
	}
	tampered := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
	tampered[egresspolicy.KeyAllowMetadata] = true
	if _, err := fetchGatewayPayload(t, tampered); err == nil {
		t.Fatal("unsigned egress switch was accepted")
	}
}

func TestForwardProxyEgressKeepsGatewayLegacyCGNATAndMetadataSet(t *testing.T) {
	h := forwardProxyWithRuntime(map[string]string{}, &fakeReverseProxyAuditRecorder{}, nil)
	settings := h.egressSettings(context.Background())
	// 2.9.21 网关正向代理放行 100.64.0.0/10（阿里云元数据除外）和 168.63.129.16，升级后不变严。
	for _, ip := range []string{"100.64.0.21", "168.63.129.16"} {
		if _, via, err := resolveForwardEgressTarget(context.Background(), "x.example", 443, settings, lookupIPs(ip)); err != nil || via {
			t.Errorf("%s: via=%v err=%v", ip, via, err)
		}
	}
	if _, _, err := resolveForwardEgressTarget(context.Background(), "x.example", 443, settings, lookupIPs("100.100.100.200")); err == nil {
		t.Fatal("Alibaba Cloud metadata must stay denied")
	}
}
