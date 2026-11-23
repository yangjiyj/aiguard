package identity

import (
	"net"
	"testing"
)

// 行为矩阵 8.2（防跳板出站，不在防护项注册表里）：平台自身出站之身份源。回环、元数据一律拒绝；
// 私网按“拦截私网”开关和放行网段；全局观察留痕不影响（设计 D5、D6）。默认是否拦私网沿用
// JJD_IDP_BLOCK_PRIVATE 的升级前语义（未设置时不拦），见合流回报的待决项。
func TestAntiPivotIdentityEgressMatrix(t *testing.T) {
	guard := func(t *testing.T, blockPrivate, allowCIDRs string) *SSRFGuard {
		t.Helper()
		t.Setenv("JJD_IDP_BLOCK_PRIVATE", blockPrivate)
		t.Setenv("JJD_IDP_ALLOW_CIDRS", allowCIDRs)
		g := NewSSRFGuard()
		g.lookupIP = func(host string) ([]net.IP, error) {
			return map[string][]net.IP{"idp.corp": {net.ParseIP("10.0.0.7")}, "meta.corp": {net.ParseIP("169.254.169.254")}}[host], nil
		}
		return g
	}
	for _, auditOnly := range []string{"false", "true"} {
		t.Setenv("SECURITY_AUDIT_ONLY", auditOnly)
		for _, url := range []string{"https://127.0.0.1/", "https://169.254.169.254/", "https://metadata.google.internal/", "https://meta.corp/"} {
			if _, _, err := guard(t, "false", "169.254.0.0/16,127.0.0.0/8").CheckURL(url); err == nil {
				t.Errorf("SECURITY_AUDIT_ONLY=%s: %s must always be denied", auditOnly, url)
			}
		}
		if _, _, err := guard(t, "true", "").CheckURL("https://idp.corp/"); err == nil {
			t.Errorf("SECURITY_AUDIT_ONLY=%s: block-private must deny a private IdP", auditOnly)
		}
		if _, _, err := guard(t, "true", "10.0.0.0/24").CheckURL("https://idp.corp/"); err != nil {
			t.Errorf("SECURITY_AUDIT_ONLY=%s: an allowed CIDR must open the private IdP: %v", auditOnly, err)
		}
	}
}
