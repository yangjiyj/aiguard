package handler

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// 行为矩阵 8.2（防跳板出站，不在防护项注册表里）：独立代理的正向代理出站默认拒绝；对应开关打开
// 只放开它那一类；全局观察留痕下白名单这类检测放行，防跳板照拒（设计 D5、D6）。
func TestAntiPivotStandaloneProxyEgressMatrix(t *testing.T) {
	intranet := map[string][]net.IPAddr{"intranet.example": {{IP: net.ParseIP("10.0.0.7")}}}
	for _, tc := range []struct {
		class, address string
		ips            map[string][]net.IPAddr
		open           egresspolicy.Settings
	}{
		{"private", "intranet.example:80", intranet, egresspolicy.Settings{AllowPrivate: true}},
		{"private cidr", "intranet.example:80", intranet, egresspolicy.Settings{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.7/32")}}},
		{"loopback", "127.0.0.1:80", nil, egresspolicy.Settings{AllowLoopback: true}},
		{"metadata", "169.254.169.254:80", nil, egresspolicy.Settings{AllowMetadata: true}},
		{"alibaba metadata", "100.100.100.200:80", nil, egresspolicy.Settings{AllowMetadata: true}},
		{"metadata hostname", "metadata.google.internal:80", map[string][]net.IPAddr{"metadata.google.internal": {{IP: net.ParseIP("169.254.169.254")}}}, egresspolicy.Settings{AllowMetadata: true}},
	} {
		t.Run(tc.class, func(t *testing.T) {
			if _, err := guardWithSettings(tc.ips, egresspolicy.Settings{}).Resolve(context.Background(), tc.address); err == nil || !isBlockedEgress(err) {
				t.Fatalf("default must deny: %v", err)
			}
			if target, err := guardWithSettings(tc.ips, tc.open).Resolve(context.Background(), tc.address); err != nil || !target.ViaSetting {
				t.Fatalf("switch must allow: target=%+v err=%v", target, err)
			}
			for _, auditOnly := range []string{"false", "true"} {
				t.Setenv("SECURITY_AUDIT_ONLY", auditOnly)
				h := NewProxyHandler(successfulEmptyWhitelistChecker(), nil, nil, nil, nil)
				h.egressGuard = guardWithSettings(tc.ips, egresspolicy.Settings{})
				h.transport = h.egressGuard.HTTPTransport()
				w := httptest.NewRecorder()
				h.handleHTTP(w, httptest.NewRequest(http.MethodGet, "http://"+tc.address+"/", nil))
				if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "egress target not allowed") {
					t.Fatalf("SECURITY_AUDIT_ONLY=%s: anti-pivot must deny: status=%d body=%q", auditOnly, w.Code, w.Body.String())
				}
				// 对照：这个代理确实处在对应的全局执行模式下。
				if got := h.exitMode() == securityexit.Record; got != (auditOnly == "true") {
					t.Fatalf("fixture: SECURITY_AUDIT_ONLY=%s record=%v", auditOnly, got)
				}
			}
		})
	}
}
