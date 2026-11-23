package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func lookupIPs(values ...string) lookupIPAddrFunc {
	return func(_ context.Context, _ string) ([]net.IPAddr, error) {
		result := make([]net.IPAddr, 0, len(values))
		for _, value := range values {
			result = append(result, net.IPAddr{IP: net.ParseIP(value)})
		}
		return result, nil
	}
}

func TestResolveSafeEgressTargetForRoute_DefaultPrivateAddressRejected(t *testing.T) {
	_, err := resolveSafeEgressTargetForRoute(
		context.Background(), "api.example.cn", 443, false, nil,
		lookupIPs("172.16.20.17"),
	)
	if err == nil || !strings.Contains(err.Error(), "unsafe egress target") {
		t.Fatalf("expected private address rejection, got %v", err)
	}
}

func TestResolveSafeEgressTargetForRoute_ExactPrivateCIDRAllowedAndPinned(t *testing.T) {
	target, err := resolveSafeEgressTargetForRoute(
		context.Background(), "api.example.cn", 443, true,
		[]string{"172.16.20.17/32"}, lookupIPs("172.16.20.17"),
	)
	if err != nil {
		t.Fatalf("resolve allowlisted private target: %v", err)
	}
	if target.Host != "api.example.cn" || target.Port != 443 || target.DialAddress != "172.16.20.17:443" {
		t.Fatalf("unexpected pinned target: %+v", target)
	}
}

func TestResolveSafeEgressTargetForRoute_PrivateAddressOutsideCIDRRejected(t *testing.T) {
	_, err := resolveSafeEgressTargetForRoute(
		context.Background(), "api.example.cn", 443, true,
		[]string{"172.16.20.17/32"}, lookupIPs("172.16.20.18"),
	)
	if err == nil || !strings.Contains(err.Error(), "172.16.20.18") {
		t.Fatalf("expected unauthorized private address rejection, got %v", err)
	}
}

func TestResolveSafeEgressTargetForRoute_UnauthorizedPrivateInMultiAddressAnswerFailsClosed(t *testing.T) {
	_, err := resolveSafeEgressTargetForRoute(
		context.Background(), "api.example.cn", 443, true,
		[]string{"172.16.20.17/32"}, lookupIPs("203.0.113.10", "172.16.20.18"),
	)
	if err == nil || !strings.Contains(err.Error(), "172.16.20.18") {
		t.Fatalf("expected mixed DNS answer to fail closed, got %v", err)
	}
}

func TestResolveSafeEgressTargetForRoute_PublicAddressBehaviorUnchanged(t *testing.T) {
	target, err := resolveSafeEgressTargetForRoute(
		context.Background(), "api.example.com", 443, false, nil,
		lookupIPs("203.0.113.10"),
	)
	if err != nil {
		t.Fatalf("resolve public target: %v", err)
	}
	if target.DialAddress != "203.0.113.10:443" {
		t.Fatalf("unexpected public dial address: %s", target.DialAddress)
	}
}

func TestResolveSafeEgressTargetForRoute_PermanentlyForbiddenAddressesIgnoreBroadCIDRs(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{name: "loopback", addr: "127.0.0.1"},
		{name: "ipv6 loopback", addr: "::1"},
		{name: "link local", addr: "169.254.20.1"},
		{name: "ipv6 link local", addr: "fe80::1"},
		{name: "multicast", addr: "224.0.0.1"},
		{name: "ipv6 multicast", addr: "ff02::1"},
		{name: "unspecified", addr: "0.0.0.0"},
		{name: "ipv6 unspecified", addr: "::"},
		{name: "aws metadata", addr: "169.254.169.254"},
		{name: "ecs metadata", addr: "169.254.170.2"},
		{name: "aliyun metadata", addr: "100.100.100.200"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveSafeEgressTargetForRoute(
				context.Background(), "target.internal", 443, true,
				[]string{"0.0.0.0/0", "::/0"}, lookupIPs(tc.addr),
			)
			if err == nil {
				t.Fatalf("expected %s to remain forbidden", tc.addr)
			}
		})
	}
}

func TestReverseProxyServeHTTP_DefaultPrivateTargetReturns403(t *testing.T) {
	h := &ReverseProxyHandler{
		tenantID: "tenant_default",
		client:   &http.Client{Timeout: time.Second},
		routes: []ReverseProxyRoute{{
			ID: "rpr_private", PathPrefix: "/private",
			TargetURL: "http://10.20.30.40", Status: "active",
		}},
	}
	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/private/v1/models", nil)
	w := httptest.NewRecorder()

	if !h.ServeHTTP(w, req) {
		t.Fatal("expected route to be handled")
	}
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "unsafe reverse proxy target") {
		t.Fatalf("expected private target 403, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHTTPClientForResolvedEgress_RejectsCrossHostRedirect(t *testing.T) {
	var redirectedHits atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer redirected.Close()

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, redirected.URL, http.StatusFound)
	}))
	defer first.Close()

	port := first.Listener.Addr().(*net.TCPAddr).Port
	target := resolvedEgressTarget{
		Host: "api.example.cn", Port: port,
		DialAddress: first.Listener.Addr().String(),
	}
	client := streamingHTTPClientForReverseProxy(nil, target)
	_, err := client.Get("http://api.example.cn:" + strconv.Itoa(port) + "/start")
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected cross-host redirect rejection, got %v", err)
	}
	if redirectedHits.Load() != 0 {
		t.Fatalf("cross-host redirect was followed %d times", redirectedHits.Load())
	}
}

func TestSharedResolvedEgressClientsKeepRedirectPolicyUnchanged(t *testing.T) {
	target := resolvedEgressTarget{
		Host: "api.example.com", Port: 443, DialAddress: "203.0.113.10:443",
	}
	if client := httpClientForResolvedEgress(nil, target, time.Second); client.CheckRedirect != nil {
		t.Fatal("forward proxy shared client unexpectedly received reverse proxy redirect policy")
	}
	if client := streamingHTTPClientForResolvedEgress(nil, target); client.CheckRedirect != nil {
		t.Fatal("MCP shared client unexpectedly received reverse proxy redirect policy")
	}
}

func TestStreamingHTTPClientForResolvedEgress_PreservesHostAndTLSSNIWhileDialingPinnedIP(t *testing.T) {
	cert := certificateForDNSName(t, "api.example.cn")
	var gotSNI string
	var gotHost string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			gotSNI = info.ServerName
			return nil, nil
		},
	}
	server.StartTLS()
	defer server.Close()

	port := server.Listener.Addr().(*net.TCPAddr).Port
	target := resolvedEgressTarget{
		Host: "api.example.cn", Port: port,
		DialAddress: server.Listener.Addr().String(),
	}
	client := streamingHTTPClientForReverseProxy(server.Client(), target)
	resp, err := client.Get(fmt.Sprintf("https://api.example.cn:%d/v1/models", port))
	if err != nil {
		t.Fatalf("call pinned TLS upstream: %v", err)
	}
	resp.Body.Close()

	if gotSNI != "api.example.cn" {
		t.Fatalf("TLS SNI mismatch: %q", gotSNI)
	}
	wantHost := net.JoinHostPort("api.example.cn", strconv.Itoa(port))
	if gotHost != wantHost {
		t.Fatalf("HTTP Host mismatch: got %q want %q", gotHost, wantHost)
	}
}

func certificateForDNSName(t *testing.T, dnsName string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestPrivateEgressCIDRParserRejectsInvalidAndCanonicalizes(t *testing.T) {
	prefixes, err := parsePrivateEgressCIDRs([]string{"172.16.20.17/32", "10.20.30.40/24", "10.20.30.0/24"})
	if err != nil {
		t.Fatalf("parse CIDRs: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("172.16.20.17/32"),
		netip.MustParsePrefix("10.20.30.0/24"),
	}
	if fmt.Sprint(prefixes) != fmt.Sprint(want) {
		t.Fatalf("prefix mismatch: got %v want %v", prefixes, want)
	}
	if _, err := parsePrivateEgressCIDRs([]string{"172.16.20.17"}); err == nil {
		t.Fatal("expected invalid CIDR to be rejected")
	}
}
