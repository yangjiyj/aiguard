package directoryldap

import (
	"net/netip"
	"testing"
)

// 元数据地址与主机名清单只有一份（egresspolicy）。
func TestDirectoryUsesSharedMetadataLists(t *testing.T) {
	for _, host := range []string{"metadata", "instance-data.ec2.internal", "metadata.goog", "localhost", "a.localhost"} {
		if !isBlockedDirectoryHostname(host) {
			t.Errorf("%s must be blocked", host)
		}
	}
	for _, raw := range []string{"169.254.169.254", "168.63.129.16", "fd00:ec2::254", "fd20:ce::254", "100.100.100.200", "169.254.170.2"} {
		if !isMetadataAddress(netip.MustParseAddr(raw)) {
			t.Errorf("%s must be metadata", raw)
		}
	}
}
