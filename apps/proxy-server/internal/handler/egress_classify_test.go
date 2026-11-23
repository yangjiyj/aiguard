package handler

import (
	"context"
	"net"
	"strings"
	"testing"
)

// 独立代理的默认判定保持 2.9.21（收敛到 egresspolicy.Classify 之后）：比网关多把 CGNAT 当内网。
func TestEgressGuardKeeps2921DefaultVerdicts(t *testing.T) {
	for raw, allowed := range map[string]bool{
		"8.8.8.8": true, "168.63.129.16": true, "198.18.0.1": true, "2001:2::1": true, "0.1.2.3": true, "240.0.0.1": true, "100::1": true,
		"100.64.0.1": false, "169.254.169.254": false, "100.100.100.200": false, "fd00:ec2::254": false, "127.0.0.1": false,
		"10.0.0.1": false, "fd00::1": false, "0.0.0.0": false, "224.0.0.1": false, "255.255.255.255": false,
	} {
		guard := NewEgressGuard(fakeResolver{ips: map[string][]net.IPAddr{"t.example": {{IP: net.ParseIP(raw)}}}}, nil)
		_, err := guard.Resolve(context.Background(), "t.example:443")
		if (err == nil) != allowed {
			t.Errorf("%s: allowed=%v want %v (%v)", raw, err == nil, allowed, err)
		}
	}
}

// 元数据主机名清单只有一份（egresspolicy）：独立代理按名字拦的与 safetarget、agentguard 相同。
func TestEgressGuardUsesSharedMetadataHostnames(t *testing.T) {
	guard := NewEgressGuard(fakeResolver{ips: map[string][]net.IPAddr{}}, nil)
	for _, host := range []string{"metadata.goog", "metadata.azure.internal", "instance-data", "instance-data.ec2.internal", "metadata.oraclecloud.com"} {
		if _, err := guard.Resolve(context.Background(), host+":80"); err == nil || !strings.Contains(err.Error(), "blocked egress target") {
			t.Errorf("%s must be blocked by name, got %v", host, err)
		}
	}
}
