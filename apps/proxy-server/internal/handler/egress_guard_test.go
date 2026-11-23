package handler

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

type fakeResolver struct {
	ips map[string][]net.IPAddr
}

func (r fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if ips, ok := r.ips[host]; ok {
		return ips, nil
	}
	return nil, errors.New("unexpected lookup: " + host)
}

func TestEgressGuardRejectsLocalAndMetadataTargets(t *testing.T) {
	guard := NewEgressGuard(fakeResolver{ips: map[string][]net.IPAddr{
		"metadata.google.internal": {{IP: net.ParseIP("169.254.169.254")}},
	}}, nil)

	tests := []string{
		"127.0.0.1:80",
		"127.1:80",
		"2130706433:80",
		"0x7f000001:80",
		"[::1]:80",
		"169.254.169.254:80",
		"100.64.0.1:80",
		"100.64.0.21:8081",
		"metadata.google.internal:80",
	}

	for _, address := range tests {
		t.Run(address, func(t *testing.T) {
			_, err := guard.Resolve(context.Background(), address)
			if err == nil || !strings.Contains(err.Error(), "blocked egress target") {
				t.Fatalf("expected blocked egress target, got %v", err)
			}
		})
	}
}

func TestEgressGuardRejectsDNSRebindToPrivateAddress(t *testing.T) {
	guard := NewEgressGuard(fakeResolver{ips: map[string][]net.IPAddr{
		"rebind.example": {{IP: net.ParseIP("10.0.0.7")}},
	}}, nil)

	_, err := guard.Resolve(context.Background(), "rebind.example:443")
	if err == nil || !strings.Contains(err.Error(), "blocked egress target") {
		t.Fatalf("expected private resolved IP to be blocked, got %v", err)
	}
}

func TestEgressGuardRejectsDNSRebindToTailscaleAddress(t *testing.T) {
	guard := NewEgressGuard(fakeResolver{ips: map[string][]net.IPAddr{
		"tailscale.example": {{IP: net.ParseIP("100.64.0.21")}},
	}}, nil)

	_, err := guard.Resolve(context.Background(), "tailscale.example:8081")
	if err == nil || !strings.Contains(err.Error(), "blocked egress target") {
		t.Fatalf("expected Tailscale resolved IP to be blocked, got %v", err)
	}
}

func TestEgressGuardPinsDialToResolvedIP(t *testing.T) {
	var dialed string
	guard := NewEgressGuard(fakeResolver{ips: map[string][]net.IPAddr{
		"api.example.com": {{IP: net.ParseIP("93.184.216.34")}},
	}}, func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = address
		server, client := net.Pipe()
		go server.Close()
		return client, nil
	})

	conn, err := guard.DialContext(context.Background(), "tcp", "api.example.com:443")
	if err != nil {
		t.Fatalf("DialContext returned error: %v", err)
	}
	conn.Close()

	if dialed != "93.184.216.34:443" {
		t.Fatalf("dialed address = %q, want resolved IP pin", dialed)
	}
}

func TestProxyHandlerUsesGuardedTransportForHTTP(t *testing.T) {
	h := NewProxyHandler(nil, nil, nil, nil, nil)
	if h.egressGuard == nil {
		t.Fatal("proxy handler should initialize egress guard")
	}
	if h.transport == nil {
		t.Fatal("proxy handler should use guarded HTTP transport")
	}
}
