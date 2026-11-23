package egresspolicy

import (
	"net/netip"
	"testing"
)

func TestDefaultsDenyEveryInternalClass(t *testing.T) {
	var s Settings
	for _, raw := range []string{"10.0.0.7", "172.16.1.1", "192.168.1.1", "fd00::1", "100.64.0.1",
		"127.0.0.1", "::1", "169.254.20.1", "fe80::1", "169.254.169.254", "100.100.100.200", "fd00:ec2::254",
		"0.0.0.0", "224.0.0.1"} {
		if v := s.CheckAddr(netip.MustParseAddr(raw)); v.Allowed {
			t.Errorf("%s allowed by default: %+v", raw, v)
		}
	}
	if v := s.CheckAddr(netip.MustParseAddr("203.0.113.10")); !v.Allowed || v.ViaSetting {
		t.Fatalf("public address = %+v, want allowed without setting", v)
	}
}

func TestSwitchesAllowOnlyTheirOwnClass(t *testing.T) {
	cases := []struct {
		name     string
		settings Settings
		allow    []string
		deny     []string
	}{
		{"private", Settings{AllowPrivate: true}, []string{"10.0.0.7", "192.168.1.1", "fd00::1", "100.64.0.1"}, []string{"127.0.0.1", "169.254.169.254", "100.100.100.200", "169.254.20.1"}},
		{"loopback", Settings{AllowLoopback: true}, []string{"127.0.0.1", "::1"}, []string{"10.0.0.7", "169.254.169.254"}},
		{"metadata", Settings{AllowMetadata: true}, []string{"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}, []string{"10.0.0.7", "127.0.0.1", "169.254.20.1"}},
	}
	for _, tc := range cases {
		for _, raw := range tc.allow {
			if v := tc.settings.CheckAddr(netip.MustParseAddr(raw)); !v.Allowed || !v.ViaSetting {
				t.Errorf("%s: %s = %+v, want allowed via setting", tc.name, raw, v)
			}
		}
		for _, raw := range tc.deny {
			if v := tc.settings.CheckAddr(netip.MustParseAddr(raw)); v.Allowed {
				t.Errorf("%s: %s allowed, want denied", tc.name, raw)
			}
		}
	}
}

func TestAllowedCIDRsAreExactAndNeverCoverMetadata(t *testing.T) {
	s := Settings{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.30.40/32"), netip.MustParsePrefix("0.0.0.0/0")}}
	if v := s.CheckAddr(netip.MustParseAddr("10.20.30.40")); !v.Allowed || !v.ViaSetting {
		t.Fatalf("listed address = %+v", v)
	}
	if v := s.CheckAddr(netip.MustParseAddr("169.254.169.254")); v.Allowed {
		t.Fatal("metadata must need its own switch, not a broad CIDR")
	}
	narrow := Settings{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.30.40/32")}}
	if v := narrow.CheckAddr(netip.MustParseAddr("10.20.30.41")); v.Allowed {
		t.Fatal("neighbour address outside the CIDR must stay denied")
	}
}

func TestHostListMatchesExactOrDotSuffix(t *testing.T) {
	s := Settings{AllowedHosts: []string{"intranet.corp", ".svc.internal"}}
	for host, want := range map[string]bool{
		"intranet.corp": true, "INTRANET.CORP.": true, "a.intranet.corp": false, "evilintranet.corp": false,
		"api.svc.internal": true, "svc.internal": true, "evilsvc.internal": false,
	} {
		if got := s.HostListed(host); got != want {
			t.Errorf("%s listed=%v want %v", host, got, want)
		}
	}
}

func TestFromValuesParsesSwitchesAndLists(t *testing.T) {
	s, err := FromValues(map[string]string{
		KeyAllowPrivate: "true", KeyAllowLoopback: "false", KeyAllowMetadata: "TRUE",
		KeyAllowedCIDRs: `["10.0.0.0/8"," 192.168.1.10/32 "]`, KeyAllowedHosts: `["Intranet.Corp", ".svc"]`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !s.AllowPrivate || s.AllowLoopback || !s.AllowMetadata || len(s.AllowedCIDRs) != 2 || len(s.AllowedHosts) != 2 || s.AllowedHosts[0] != "intranet.corp" {
		t.Fatalf("settings = %+v", s)
	}
	if _, err := FromValues(map[string]string{KeyAllowedCIDRs: `["10.0.0.1"]`}); err == nil {
		t.Fatal("bare address without prefix length must be rejected")
	}
	if _, err := FromValues(map[string]string{KeyAllowedHosts: `["a b"]`}); err == nil {
		t.Fatal("invalid host must be rejected")
	}
	empty, err := FromValues(nil)
	if err != nil || empty.AllowPrivate || len(empty.AllowedCIDRs) != 0 {
		t.Fatalf("empty = %+v err=%v", empty, err)
	}
}

func TestUnlistedActionAndFailModeFallBackToEnvironmentOnlyWhenKeyMissing(t *testing.T) {
	if got := UnlistedAction(map[string]string{}, "tunnel_audit"); got != UnlistedAllowAudit {
		t.Fatalf("missing key with legacy tunnel_audit env = %q", got)
	}
	if got := UnlistedAction(map[string]string{KeyUnlistedAction: "deny"}, "tunnel_audit"); got != UnlistedDeny {
		t.Fatalf("stored deny must beat env, got %q", got)
	}
	if got := UnlistedAction(map[string]string{KeyUnlistedAction: "bogus"}, ""); got != UnlistedDeny {
		t.Fatalf("invalid stored value must fall back to deny, got %q", got)
	}
	if got := WhitelistFailMode(map[string]string{}, "open"); got != FailOpen {
		t.Fatalf("missing key with env open = %q", got)
	}
	if got := WhitelistFailMode(map[string]string{KeyWhitelistFailMode: "closed"}, "open"); got != FailClosed {
		t.Fatalf("stored closed must beat env, got %q", got)
	}
	if got := WhitelistFailMode(nil, ""); got != FailClosed {
		t.Fatalf("default = %q", got)
	}
}

func TestNormalizeUpdateRejectsBadValuesAndCanonicalizes(t *testing.T) {
	ok := map[string]string{KeyAllowPrivate: "TRUE", KeyAllowedCIDRs: `["10.1.2.3/8"]`, KeyAllowedHosts: `["A.Corp."]`, KeyUnlistedAction: "Allow_Audit", KeyWhitelistFailMode: "OPEN"}
	if err := NormalizeUpdate(ok); err != nil {
		t.Fatal(err)
	}
	if ok[KeyAllowPrivate] != "true" || ok[KeyAllowedCIDRs] != `["10.0.0.0/8"]` || ok[KeyAllowedHosts] != `["a.corp"]` || ok[KeyUnlistedAction] != "allow_audit" || ok[KeyWhitelistFailMode] != "open" {
		t.Fatalf("normalized = %+v", ok)
	}
	for _, bad := range []map[string]string{
		{KeyAllowLoopback: "yes"}, {KeyAllowedCIDRs: "10.0.0.0/8"}, {KeyUnlistedAction: "allow"}, {KeyWhitelistFailMode: "half"},
	} {
		if err := NormalizeUpdate(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestLoosenedReportsOnlyRelaxingChanges(t *testing.T) {
	before := map[string]string{KeyAllowedCIDRs: `["10.0.0.0/8"]`}
	after := map[string]string{KeyAllowPrivate: "true", KeyAllowLoopback: "false", KeyAllowedCIDRs: `["10.0.0.0/8"]`, KeyUnlistedAction: "deny"}
	if got := Loosened(before, after); len(got) != 1 || got[0] != KeyAllowPrivate {
		t.Fatalf("loosened = %v", got)
	}
	after = map[string]string{KeyAllowedCIDRs: `["10.0.0.0/8","192.168.0.0/16"]`, KeyWhitelistFailMode: "open"}
	if got := Loosened(before, after); len(got) != 2 {
		t.Fatalf("loosened = %v", got)
	}
}

// 审查 2：CGNATIsPublic 并入 Compat（各组件的 2.9.21 口径），用例改用 CompatProxyServer、CompatGatewayProxy，断言不变。
func TestCGNATFollowsComponentLegacyClassification(t *testing.T) {
	tailscale := netip.MustParseAddr("100.64.0.21")
	if v := (Settings{Compat: CompatProxyServer}).CheckAddr(tailscale); v.Allowed {
		t.Fatal("independent proxy treats CGNAT as internal")
	}
	if v := (Settings{Compat: CompatGatewayProxy}).CheckAddr(tailscale); !v.Allowed || v.ViaSetting {
		t.Fatalf("gateway legacy: CGNAT = %+v, want public", v)
	}
	if v := (Settings{Compat: CompatGatewayProxy}).CheckAddr(netip.MustParseAddr("100.100.100.200")); v.Allowed {
		t.Fatal("Alibaba Cloud metadata inside CGNAT must stay denied")
	}
}
