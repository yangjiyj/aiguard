package identity

import (
	"net"
	"os"
	"testing"
)

func TestSSRFRejectLoopback(t *testing.T) {
	g := NewSSRFGuard()
	_, _, err := g.CheckURL("http://127.0.0.1/")
	if err == nil {
		t.Fatal("should reject loopback")
	}
	if !contains(err.Error(), "禁止") {
		t.Fatalf("error should mention blocked, got: %v", err)
	}
}

func TestSSRFRejectCloudMetadata(t *testing.T) {
	g := NewSSRFGuard()
	_, _, err := g.CheckURL("http://169.254.169.254/")
	if err == nil {
		t.Fatal("should reject cloud metadata")
	}
}

func TestSSRFBlockPrivateWhenExplicitlyRequested(t *testing.T) {
	t.Setenv("JJD_IDP_BLOCK_PRIVATE", "true")
	g := NewSSRFGuard()
	_, _, err := g.CheckURL("http://10.0.0.1/")
	if err == nil {
		t.Fatal("should reject private IP")
	}
}

func TestSSRFAllowPrivateWithAllowList(t *testing.T) {
	os.Setenv("JJD_IDP_ALLOW_CIDRS", "10.0.0.0/8")
	defer os.Unsetenv("JJD_IDP_ALLOW_CIDRS")
	g := NewSSRFGuard()
	_, _, err := g.CheckURL("http://10.0.0.1/")
	if err != nil {
		t.Fatalf("should allow private IP with allowlist: %v", err)
	}
}

func TestSSRFRejectNonHTTP(t *testing.T) {
	g := NewSSRFGuard()
	_, _, err := g.CheckURL("file:///etc/passwd")
	if err == nil {
		t.Fatal("should reject non-http scheme")
	}
}

func TestSSRFRejectInvalidURL(t *testing.T) {
	g := NewSSRFGuard()
	_, _, err := g.CheckURL("://not-a-url")
	if err == nil {
		t.Fatal("should reject invalid URL")
	}
}

func TestSSRFRejectLoopbackIPv6(t *testing.T) {
	g := NewSSRFGuard()
	_, _, err := g.CheckURL("http://[::1]/")
	if err == nil {
		t.Fatal("should reject IPv6 loopback")
	}
}

func TestSSRFRejectIPv6UnspecifiedEvenWhenAllowlisted(t *testing.T) {
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "::/0")
	g := NewSSRFGuard()
	if _, _, err := g.CheckURL("http://[::]/"); err == nil {
		t.Fatal("allowlist must not permit IPv6 unspecified address")
	}
}

func TestSSRFRejectsHostWhenAnyResolvedAddressIsBlocked(t *testing.T) {
	g := NewSSRFGuard()
	g.lookupIP = func(string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("203.0.113.10"),
			net.ParseIP("127.0.0.1"),
		}, nil
	}

	if _, _, err := g.CheckURL("https://idp.example.com"); err == nil {
		t.Fatal("should reject a hostname when any DNS answer is blocked")
	}
}

func TestSSRFAllowListCannotOverrideAlwaysBlockedRanges(t *testing.T) {
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "0.0.0.0/0")
	g := NewSSRFGuard()
	for _, target := range []string{"http://127.0.0.1", "http://169.254.169.254"} {
		if _, _, err := g.CheckURL(target); err == nil {
			t.Fatalf("allowlist must not override permanently blocked target %s", target)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestSSRFPrivateDefaultAndStrictMode(t *testing.T) {
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "")
	for _, strict := range []string{"", "true"} {
		t.Setenv("JJD_IDP_BLOCK_PRIVATE", strict)
		g := NewSSRFGuard()
		for _, host := range []string{"10.8.184.6", "172.16.1.1", "192.168.20.246", "100.64.0.36", "[fd00::1]"} {
			_, _, err := g.CheckURL("https://" + host + "/oidc")
			if (err != nil) != (strict == "true") {
				t.Fatalf("strict=%q host=%s err=%v", strict, host, err)
			}
		}
	}
}
func TestSSRFPrivateAndLoopbackMixedDNSRejected(t *testing.T) {
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "")
	t.Setenv("JJD_IDP_BLOCK_PRIVATE", "")
	g := NewSSRFGuard()
	g.lookupIP = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.8.184.6"), net.ParseIP("127.0.0.1")}, nil
	}
	if _, _, err := g.CheckURL("https://auth-testapi2.example.cn/oidc"); err == nil {
		t.Fatal("mixed DNS must fail closed")
	}
}
func TestSSRFAlwaysBlockedAcrossIPFamilies(t *testing.T) {
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "0.0.0.0/0,::/0")
	t.Setenv("JJD_IDP_BLOCK_PRIVATE", "")
	g := NewSSRFGuard()
	for _, host := range []string{"127.0.0.1", "0.0.0.0", "0.1.2.3", "169.254.169.254", "224.0.0.1", "[::]", "[::1]", "[fe80::1]", "[ff02::1]", "[::ffff:127.0.0.1]"} {
		if _, _, err := g.CheckURL("https://" + host); err == nil {
			t.Fatalf("must reject %s", host)
		}
	}
}
