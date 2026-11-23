package egresspolicy

import (
	"net/netip"
	"testing"
)

// classifyTable 是全平台唯一的地址分类（与 safetarget 2.9.21 口径一致）。
var classifyTable = map[string]Class{
	"169.254.169.254": ClassMetadata, "169.254.170.2": ClassMetadata, "100.100.100.200": ClassMetadata,
	"168.63.129.16": ClassMetadata, "fd00:ec2::254": ClassMetadata, "fd20:ce::254": ClassMetadata,
	"::ffff:169.254.169.254": ClassMetadata,
	"127.0.0.1":              ClassLoopback, "::1": ClassLoopback,
	"169.254.1.1": ClassLinkLocal, "fe80::1": ClassLinkLocal,
	"0.0.0.0": ClassReserved, "::": ClassReserved, "224.0.0.1": ClassReserved, "ff02::1": ClassReserved,
	"0.1.2.3": ClassReserved, "240.0.0.1": ClassReserved, "255.255.255.255": ClassReserved, "100::1": ClassReserved,
	"10.0.0.1": ClassPrivate, "172.16.0.1": ClassPrivate, "192.168.1.1": ClassPrivate, "fc00::1": ClassPrivate,
	"fd00::1": ClassPrivate, "100.64.0.1": ClassPrivate, "198.18.0.1": ClassPrivate, "2001:2::1": ClassPrivate,
	"8.8.8.8": ClassPublic, "2606:4700::1111": ClassPublic,
}

func TestClassifyIsTheSingleTable(t *testing.T) {
	for raw, want := range classifyTable {
		if got := Classify(netip.MustParseAddr(raw)); got != want {
			t.Errorf("Classify(%s) = %s, want %s", raw, got, want)
		}
	}
}

// 各组件 2.9.21 的口径比 safetarget 窄：兼容口径只把这几类改判为公网，其余与 Classify 相同。
func TestCompatKeeps2921ComponentClassification(t *testing.T) {
	gatewayPublic := map[string]bool{"100.64.0.1": true, "168.63.129.16": true, "198.18.0.1": true, "2001:2::1": true,
		"0.1.2.3": true, "240.0.0.1": true, "100::1": true}
	proxyServerPublic := map[string]bool{"168.63.129.16": true, "198.18.0.1": true, "2001:2::1": true,
		"0.1.2.3": true, "240.0.0.1": true, "100::1": true}
	for raw, base := range classifyTable {
		addr := netip.MustParseAddr(raw)
		for name, tc := range map[string]struct {
			compat Compat
			public map[string]bool
		}{"gateway": {CompatGatewayProxy, gatewayPublic}, "proxy-server": {CompatProxyServer, proxyServerPublic}} {
			want := base
			if tc.public[raw] {
				want = ClassPublic
			}
			if got := tc.compat.Classify(addr); got != want {
				t.Errorf("%s Classify(%s) = %s, want %s", name, raw, got, want)
			}
		}
	}
}

func TestMetadataHostnamesAreOneList(t *testing.T) {
	for _, host := range []string{"metadata", "metadata.google.internal", "Metadata.Goog.", "metadata.azure.internal",
		"metadata.oraclecloud.com", "instance-data", "instance-data.ec2.internal"} {
		if !IsMetadataHostname(host) {
			t.Errorf("%s must be a metadata hostname", host)
		}
	}
	for _, host := range []string{"metadata.example.com", "localhost", "google.internal"} {
		if IsMetadataHostname(host) {
			t.Errorf("%s must not be a metadata hostname", host)
		}
	}
}
