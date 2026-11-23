package identity

import (
	"net"
	"testing"
)

// 身份源常拦云元数据地址与元数据主机名（egresspolicy 的唯一清单）：默认不拦私网时也拒，放行网段盖住也不放。
func TestSSRFAlwaysRejectsMetadataAddressesAndHostnames(t *testing.T) {
	t.Setenv("JJD_IDP_BLOCK_PRIVATE", "")
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "100.64.0.0/10,fd00::/8,168.63.0.0/16")
	g := NewSSRFGuard()
	for _, target := range []string{"https://100.100.100.200/", "https://[fd00:ec2::254]/", "https://[fd20:ce::254]/",
		"https://169.254.169.254/", "https://168.63.129.16/"} {
		if _, _, err := g.CheckURL(target); err == nil {
			t.Errorf("metadata address %s must be rejected", target)
		}
	}
	g.lookupIP = func(host string) ([]net.IP, error) {
		t.Errorf("metadata hostname %s must be rejected before resolving", host)
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	}
	for _, host := range []string{"metadata.google.internal", "Metadata.Goog.", "metadata", "instance-data.ec2.internal"} {
		if _, _, err := g.CheckURL("https://" + host + "/"); err == nil {
			t.Errorf("metadata hostname %s must be rejected", host)
		}
	}
	// 放行网段里的普通地址照常放行。
	if _, _, err := g.CheckURL("https://100.64.0.1/"); err != nil {
		t.Fatalf("allow-listed CGNAT address must stay allowed: %v", err)
	}
	if _, _, err := g.CheckURL("https://[fd00::10]/"); err != nil {
		t.Fatalf("allow-listed ULA address must stay allowed: %v", err)
	}
}
