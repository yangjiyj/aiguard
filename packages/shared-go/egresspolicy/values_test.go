package egresspolicy

import (
	"net/netip"
	"strings"
	"testing"
)

// IPv4 映射写法的网段换算成 IPv4 网段；换算不了（前缀短于 96 位）的拒绝，不再存成无效网段。
func TestParseCIDRListMapsOrRejectsIPv4MappedPrefixes(t *testing.T) {
	got, err := ParseCIDRList(`["::ffff:10.0.0.0/104","::ffff:192.168.1.1/128"]`)
	if err != nil || len(got) != 2 || got[0] != netip.MustParsePrefix("10.0.0.0/8") || got[1] != netip.MustParsePrefix("192.168.1.1/32") {
		t.Fatalf("mapped prefixes = %v err=%v", got, err)
	}
	for _, bad := range []string{`["::ffff:0:0/95"]`, `["::ffff:10.0.0.0/90"]`} {
		if _, err := ParseCIDRList(bad); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
	update := map[string]string{KeyAllowedCIDRs: `["::ffff:10.0.0.0/104"]`}
	if err := NormalizeUpdate(update); err != nil || update[KeyAllowedCIDRs] != `["10.0.0.0/8"]` {
		t.Fatalf("normalized = %q err=%v", update[KeyAllowedCIDRs], err)
	}
}

// 某一个键的值坏了只丢这个键，其余照常生效，并报出坏的键。
func TestFromValuesDropsOnlyTheBadKey(t *testing.T) {
	settings, err := FromValues(map[string]string{
		KeyAllowPrivate:  "true",
		KeyAllowedCIDRs:  "not json",
		KeyAllowedHosts:  `["a.example"]`,
		KeyAllowMetadata: "true",
	})
	if err == nil || !strings.Contains(err.Error(), KeyAllowedCIDRs) {
		t.Fatalf("bad key must be reported, got %v", err)
	}
	if !settings.AllowPrivate || !settings.AllowMetadata || len(settings.AllowedHosts) != 1 || len(settings.AllowedCIDRs) != 0 {
		t.Fatalf("good keys must survive: %+v", settings)
	}
	settings, err = FromValues(map[string]string{KeyAllowLoopback: "true", KeyAllowedHosts: `["bad host!"]`, KeyAllowedCIDRs: `["10.0.0.0/8"]`})
	if err == nil || !settings.AllowLoopback || len(settings.AllowedCIDRs) != 1 || len(settings.AllowedHosts) != 0 {
		t.Fatalf("bad host list: %+v err=%v", settings, err)
	}
}
