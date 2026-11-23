package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

func TestReverseProxyRouteOverridesAllowOnlyTheirClass(t *testing.T) {
	for _, tc := range []struct {
		name, host, ip string
		overrides      safetarget.EgressOverrides
	}{
		{"loopback", "llm.example", "127.0.0.1", safetarget.EgressOverrides{AllowLoopback: true}},
		{"link local", "llm.example", "169.254.20.1", safetarget.EgressOverrides{AllowLinkLocal: true}},
		{"metadata", "llm.example", "169.254.169.254", safetarget.EgressOverrides{AllowMetadata: true}},
		{"internal hostname", "llm.corp.internal", "203.0.113.10", safetarget.EgressOverrides{AllowInternalHostnames: true}},
	} {
		if _, err := resolveSafeEgressTargetForRoute(context.Background(), tc.host, 443, false, nil, lookupIPs(tc.ip)); err == nil {
			t.Errorf("%s: allowed without override", tc.name)
		}
		target, err := resolveSafeEgressTargetForRouteWithOverrides(context.Background(), tc.host, 443, false, nil, tc.overrides, lookupIPs(tc.ip))
		if err != nil || !strings.HasPrefix(target.DialAddress, tc.ip) {
			t.Errorf("%s: target=%+v err=%v", tc.name, target, err)
		}
	}
	// 开关互不放大：链路本地不放开元数据；内部主机名不放开它解析出的内网地址。
	if _, err := resolveSafeEgressTargetForRouteWithOverrides(context.Background(), "llm.example", 443, false, nil, safetarget.EgressOverrides{AllowLinkLocal: true}, lookupIPs("169.254.169.254")); err == nil {
		t.Fatal("link-local override opened the metadata address")
	}
	if _, err := resolveSafeEgressTargetForRouteWithOverrides(context.Background(), "llm.corp.internal", 443, false, nil, safetarget.EgressOverrides{AllowInternalHostnames: true}, lookupIPs("10.0.0.7")); err == nil {
		t.Fatal("internal hostname override opened an unlisted private address")
	}
	// 内部主机名 + 私网授权网段：两者都满足才放行。
	if _, err := resolveSafeEgressTargetForRouteWithOverrides(context.Background(), "llm.corp.internal", 443, true, []string{"10.0.0.7/32"}, safetarget.EgressOverrides{AllowInternalHostnames: true}, lookupIPs("10.0.0.7")); err != nil {
		t.Fatalf("internal hostname with authorized private CIDR: %v", err)
	}
}

func TestReverseProxyDeniedTargetRecordsSecurityEvent(t *testing.T) {
	recorder := &fakeReverseProxyAuditRecorder{}
	h := &ReverseProxyHandler{
		tenantID:      "tenant_default",
		client:        &http.Client{Timeout: time.Second},
		auditRecorder: recorder,
		routes: []ReverseProxyRoute{{
			ID: "rpr_loop", PathPrefix: "/loop", TargetURL: "http://127.0.0.1:9", Status: "active",
		}},
	}
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/loop/v1/models", nil)
	w := httptest.NewRecorder()
	if !h.ServeHTTP(w, req) || w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	found := false
	for _, event := range recorder.securityEvents {
		if event.record.InputSemanticReason == reverseProxyEgressDeniedReason && event.actionTaken == "block" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no %s security event among %d", reverseProxyEgressDeniedReason, len(recorder.securityEvents))
	}
}

func TestReverseProxyRouteLoopbackOverrideReachesUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer upstream.Close()
	h := &ReverseProxyHandler{
		tenantID:      "tenant_default",
		client:        upstream.Client(),
		auditRecorder: &fakeReverseProxyAuditRecorder{},
		routes: []ReverseProxyRoute{{
			ID: "rpr_loop", PathPrefix: "/loop", TargetURL: upstream.URL, Status: "active",
			EgressOverrides: safetarget.EgressOverrides{AllowLoopback: true},
		}},
	}
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/loop/v1/models", nil)
	w := httptest.NewRecorder()
	if !h.ServeHTTP(w, req) || w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
