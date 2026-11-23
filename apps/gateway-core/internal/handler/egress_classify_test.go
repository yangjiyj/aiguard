package handler

import (
	"context"
	"net"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

func staticLookup(ip string) lookupIPAddrFunc {
	return func(context.Context, string) ([]net.IPAddr, error) { return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil }
}

// 审查 2：反向代理开内网并授权 fd00::/8，不开元数据时，fd00:ec2::254（AWS IMDS IPv6）照拦。
func TestReverseProxyAuthorizedULADoesNotOpenIPv6Metadata(t *testing.T) {
	for _, metadata := range []string{"fd00:ec2::254", "fd20:ce::254"} {
		if _, err := resolveSafeEgressTargetForRouteWithOverrides(context.Background(), metadata, 443, true, []string{"fd00::/8"}, safetarget.EgressOverrides{}, nil); err == nil {
			t.Errorf("literal %s must stay denied without the metadata switch", metadata)
		}
		if _, err := resolveSafeEgressTargetForRouteWithOverrides(context.Background(), "imds.example", 443, true, []string{"fd00::/8"}, safetarget.EgressOverrides{}, staticLookup(metadata)); err == nil {
			t.Errorf("hostname resolving to %s must stay denied without the metadata switch", metadata)
		}
		if _, err := resolveSafeEgressTargetForRouteWithOverrides(context.Background(), "imds.example", 443, false, nil, safetarget.EgressOverrides{AllowMetadata: true}, staticLookup(metadata)); err != nil {
			t.Errorf("the metadata switch opens %s: %v", metadata, err)
		}
	}
	if _, err := resolveSafeEgressTargetForRouteWithOverrides(context.Background(), "app.example", 443, true, []string{"fd00::/8"}, safetarget.EgressOverrides{}, staticLookup("fd00::10")); err != nil {
		t.Fatalf("authorized ULA must still be allowed: %v", err)
	}
}

// 网关正向代理与反向代理的默认判定保持 2.9.21（收敛到 egresspolicy.Classify 之后）。
func TestGatewayProxiesKeep2921DefaultVerdicts(t *testing.T) {
	forward := (&ForwardProxyHandler{}).egressSettings(context.Background())
	for raw, allowed := range map[string]bool{
		"8.8.8.8": true, "100.64.0.1": true, "168.63.129.16": true, "198.18.0.1": true, "2001:2::1": true,
		"0.1.2.3": true, "240.0.0.1": true, "100::1": true,
		"169.254.169.254": false, "169.254.170.2": false, "100.100.100.200": false, "fd00:ec2::254": false, "fd20:ce::254": false,
		"127.0.0.1": false, "169.254.1.1": false, "10.0.0.1": false, "fd00::1": false, "0.0.0.0": false, "224.0.0.1": false,
		"255.255.255.255": false,
	} {
		_, _, err := resolveForwardEgressTarget(context.Background(), "t.example", 443, forward, staticLookup(raw))
		if (err == nil) != allowed {
			t.Errorf("forward proxy %s: allowed=%v want %v (%v)", raw, err == nil, allowed, err)
		}
		_, err = resolveSafeEgressTargetForRoute(context.Background(), "t.example", 443, false, nil, staticLookup(raw))
		if (err == nil) != allowed {
			t.Errorf("reverse proxy %s: allowed=%v want %v (%v)", raw, err == nil, allowed, err)
		}
	}
}
