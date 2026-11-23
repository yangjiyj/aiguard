package handler

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type staticSemanticJudgeResolver struct {
	mu      sync.Mutex
	records map[string][]net.IPAddr
	calls   []string
	err     error
}

func (r *staticSemanticJudgeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, host)
	if r.err != nil {
		return nil, r.err
	}
	addrs := r.records[host]
	out := make([]net.IPAddr, len(addrs))
	copy(out, addrs)
	return out, nil
}

func (r *staticSemanticJudgeResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func semanticJudgeTestNetwork(resolver semanticJudgeResolver, dial func(context.Context, string, string) (net.Conn, error)) semanticJudgeNetwork {
	return semanticJudgeNetwork{resolver: resolver, dialContext: dial, testOnlyAllowInsecureHTTP: true}
}

func semanticJudgeNetworkForTestServer(t *testing.T, server *httptest.Server, hostname string) (string, semanticJudgeNetwork) {
	t.Helper()
	return semanticJudgeNetworkForTestServerAddress(t, server, hostname, "203.0.113.20")
}

func semanticJudgeNetworkForTestServerAddress(t *testing.T, server *httptest.Server, hostname, resolvedIP string) (string, semanticJudgeNetwork) {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	resolver := &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{
		hostname: {{IP: net.ParseIP(resolvedIP)}},
	}}
	network := semanticJudgeTestNetwork(resolver, func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, serverURL.Host)
	})
	return "http://" + net.JoinHostPort(hostname, serverURL.Port()), network
}

func TestPrepareSemanticJudgeEndpointRejectsInsecureHTTPExceptBundled(t *testing.T) {
	resolver := &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{
		"judge.example": {{IP: net.ParseIP("203.0.113.10")}},
	}}
	_, err := prepareSemanticJudgeEndpoint(
		context.Background(),
		"http://judge.example/v1/chat/completions",
		false,
		semanticJudgeNetwork{resolver: resolver},
	)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "https") {
		t.Fatalf("managed custom/provider judge must require HTTPS, got %v", err)
	}
	if _, err := prepareSemanticJudgeEndpoint(
		context.Background(), bundledSemanticJudgeURL, false,
		semanticJudgeNetwork{resolver: &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{
			"llm-judge": {{IP: net.ParseIP("10.0.0.9")}},
		}}},
	); err != nil {
		t.Fatalf("exact bundled HTTP endpoint must remain allowed: %v", err)
	}
}

func TestPrepareSemanticJudgeEndpointRejectsAnyUnsafeDNSAnswer(t *testing.T) {
	resolver := &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{
		"judge.example": {
			{IP: net.ParseIP("203.0.113.10")},
			{IP: net.ParseIP("10.0.0.8")},
		},
	}}
	_, err := prepareSemanticJudgeEndpoint(
		context.Background(),
		"https://judge.example/v1/chat/completions",
		false,
		semanticJudgeTestNetwork(resolver, nil),
	)
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("all DNS answers must be validated, got err=%v", err)
	}
}

func TestPrepareSemanticJudgeEndpointRejectsForbiddenClassesEvenWithPrivateOptIn(t *testing.T) {
	tests := []string{
		"http://127.0.0.1/v1/chat/completions",
		"http://[::1]/v1/chat/completions",
		"http://0.0.0.0/v1/chat/completions",
		"http://224.0.0.1/v1/chat/completions",
		"http://169.254.169.254/latest/meta-data",
		"http://100.100.100.200/latest/meta-data",
		"http://[fd00:ec2::254]/latest/meta-data",
		"http://[fd20:ce::254]/computeMetadata/v1/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://user:password@8.8.8.8/v1/chat/completions",
		"http://8.8.8.8/v1/chat/completions#fragment",
		"http://8.8.8.8:0/v1/chat/completions",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			_, err := prepareSemanticJudgeEndpoint(
				context.Background(),
				raw,
				true,
				semanticJudgeTestNetwork(&staticSemanticJudgeResolver{}, nil),
			)
			if err == nil {
				t.Fatalf("%s must remain forbidden with private egress opt-in", raw)
			}
		})
	}
}

func TestPrepareSemanticJudgeEndpointAllowsSharedAddressSpaceWithExplicitOptIn(t *testing.T) {
	if _, err := prepareSemanticJudgeEndpoint(
		context.Background(),
		"http://100.64.0.8:8080/v1/chat/completions",
		true,
		semanticJudgeTestNetwork(&staticSemanticJudgeResolver{}, nil),
	); err != nil {
		t.Fatalf("explicit private egress opt-in should allow shared address space: %v", err)
	}
}

func TestPrepareSemanticJudgeEndpointAllowsOnlyExactBundledPrivateTarget(t *testing.T) {
	resolver := &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{
		"llm-judge": {{IP: net.ParseIP("10.0.0.9")}},
	}}
	network := semanticJudgeTestNetwork(resolver, nil)
	if _, err := prepareSemanticJudgeEndpoint(context.Background(), bundledSemanticJudgeURL, false, network); err != nil {
		t.Fatalf("exact bundled target should be allowed: %v", err)
	}
	if _, err := prepareSemanticJudgeEndpoint(context.Background(), "http://llm-judge:8080/admin", false, network); err == nil {
		t.Fatalf("same private host with a different path must not inherit bundled exemption")
	}
}

func TestRunJudgeProbePinsValidatedIPAndPreservesHost(t *testing.T) {
	var gotHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"malicious\"}"}}]}`))
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)

	resolver := &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{
		"judge.example": {{IP: net.ParseIP("203.0.113.10")}},
	}}
	var dialed string
	network := semanticJudgeTestNetwork(resolver, func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = address
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, serverURL.Host)
	})
	backend := judgeBackend{
		URL:    "http://judge.example:" + serverURL.Port() + "/v1/chat/completions",
		Model:  "judge-m",
		APIKey: "secret",
	}
	got, err := runJudgeProbeWithNetwork(context.Background(), backend, 5, network)
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if got.Verdict != "malicious" {
		t.Fatalf("verdict=%q want malicious", got.Verdict)
	}
	wantDial := net.JoinHostPort("203.0.113.10", serverURL.Port())
	if dialed != wantDial {
		t.Fatalf("dialed=%q want pinned %q", dialed, wantDial)
	}
	if gotHost != "judge.example:"+serverURL.Port() {
		t.Fatalf("Host=%q want original hostname", gotHost)
	}
	if resolver.callCount() != 1 {
		t.Fatalf("resolver calls=%d want exactly one before dial", resolver.callCount())
	}
}

func TestRunJudgeProbePreservesTLSServerNameWhenDialingPinnedIP(t *testing.T) {
	var gotSNI string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"benign\"}"}}]}`))
	}))
	server.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			gotSNI = hello.ServerName
			return nil, nil
		},
	}
	server.StartTLS()
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)

	resolver := &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{
		"judge.example": {{IP: net.ParseIP("203.0.113.11")}},
	}}
	network := semanticJudgeTestNetwork(resolver, func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, serverURL.Host)
	})
	network.tlsConfig = &tls.Config{InsecureSkipVerify: true} // test fixture only

	backend := judgeBackend{URL: "https://judge.example:" + serverURL.Port() + "/v1/chat/completions", Model: "m", APIKey: "k"}
	if _, err := runJudgeProbeWithNetwork(context.Background(), backend, 5, network); err != nil {
		t.Fatalf("TLS probe failed: %v", err)
	}
	if gotSNI != "judge.example" {
		t.Fatalf("TLS ServerName=%q want judge.example", gotSNI)
	}
}

func TestRunJudgeProbeRejectsRedirectWithoutResolvingDestination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)

	resolver := &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{
		"judge.example": {{IP: net.ParseIP("203.0.113.12")}},
	}}
	network := semanticJudgeTestNetwork(resolver, func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, serverURL.Host)
	})
	backend := judgeBackend{URL: "http://judge.example:" + serverURL.Port(), Model: "m", APIKey: "k"}
	if _, err := runJudgeProbeWithNetwork(context.Background(), backend, 5, network); err == nil || !strings.Contains(strings.ToLower(err.Error()), "redirect") {
		t.Fatalf("redirect must be rejected explicitly, got %v", err)
	}
	if resolver.callCount() != 1 {
		t.Fatalf("redirect destination must not be resolved, resolver calls=%d", resolver.callCount())
	}
}

func TestRunJudgeProbeRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", semanticJudgeMaxResponseBytes+1)))
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)

	resolver := &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{
		"judge.example": {{IP: net.ParseIP("203.0.113.13")}},
	}}
	network := semanticJudgeTestNetwork(resolver, func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, serverURL.Host)
	})
	backend := judgeBackend{URL: "http://judge.example:" + serverURL.Port(), Model: "m", APIKey: "k"}
	if _, err := runJudgeProbeWithNetwork(context.Background(), backend, 5, network); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized response must be rejected, got %v", err)
	}
}

func TestPrepareSemanticJudgeEndpointFailsClosedOnDNSFailure(t *testing.T) {
	resolver := &staticSemanticJudgeResolver{err: fmt.Errorf("dns unavailable")}
	_, err := prepareSemanticJudgeEndpoint(
		context.Background(),
		"https://judge.example/v1/chat/completions",
		false,
		semanticJudgeTestNetwork(resolver, nil),
	)
	if err == nil {
		t.Fatalf("DNS failure must fail closed")
	}
}

func TestPrepareSemanticJudgeEndpointAllowsPlainHTTPForAuthorizedPrivateJudge(t *testing.T) {
	resolver := &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{
		"judge.internal": {{IP: net.ParseIP("10.0.0.8")}},
	}}
	network := semanticJudgeNetwork{resolver: resolver}
	for _, raw := range []string{
		"http://172.16.20.10:8000/v1/chat/completions",
		"http://judge.internal/v1/chat/completions",
	} {
		target, err := prepareSemanticJudgeEndpoint(context.Background(), raw, true, network)
		if err != nil {
			t.Fatalf("%s: authorized private judge should accept plain http: %v", raw, err)
		}
		if target.endpoint.Scheme != "http" {
			t.Fatalf("%s: scheme must be preserved, got %s", raw, target.endpoint.Scheme)
		}
	}
	if _, err := prepareSemanticJudgeEndpoint(
		context.Background(), "http://172.16.20.10:8000/v1/chat/completions", false, network,
	); err == nil || !strings.Contains(strings.ToLower(err.Error()), "https") {
		t.Fatalf("plain http without private opt-in must still require https, got %v", err)
	}
}

func TestPrepareSemanticJudgeEndpointRejectsPlainHTTPToPublicAddressesEvenWithOptIn(t *testing.T) {
	resolver := &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{
		"judge.example": {{IP: net.ParseIP("203.0.113.10")}},
		"judge.mixed":   {{IP: net.ParseIP("10.0.0.8")}, {IP: net.ParseIP("203.0.113.10")}},
	}}
	network := semanticJudgeNetwork{resolver: resolver}
	for _, raw := range []string{
		"http://judge.example/v1/chat/completions",
		"http://judge.mixed/v1/chat/completions",
		"http://203.0.113.10/v1/chat/completions",
	} {
		_, err := prepareSemanticJudgeEndpoint(context.Background(), raw, true, network)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "https") {
			t.Fatalf("%s: public plain http must be rejected even with private opt-in, got %v", raw, err)
		}
	}
	if _, err := prepareSemanticJudgeEndpoint(
		context.Background(), "https://judge.example/v1/chat/completions", true, network,
	); err != nil {
		t.Fatalf("public https must remain allowed: %v", err)
	}
}
