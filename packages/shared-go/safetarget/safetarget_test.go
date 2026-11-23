package safetarget

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type staticResolver struct {
	mu      sync.Mutex
	records map[string][]net.IPAddr
	err     error
	calls   []string
}

func (r *staticResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, host)
	if r.err != nil {
		return nil, r.err
	}
	answers := r.records[host]
	out := make([]net.IPAddr, len(answers))
	copy(out, answers)
	return out, nil
}

func (r *staticResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func resolverFor(host string, ips ...string) *staticResolver {
	answers := make([]net.IPAddr, 0, len(ips))
	for _, raw := range ips {
		answers = append(answers, net.IPAddr{IP: net.ParseIP(raw)})
	}
	return &staticResolver{records: map[string][]net.IPAddr{host: answers}}
}

// localServerTarget bypasses Resolve only to exercise the transport against a
// real local listener. Resolve policy tests independently prove that loopback
// addresses are always rejected, including with private egress opt-in.
func localServerTarget(t *testing.T, server *httptest.Server, hostname, path string) Target {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("parse test server IP: %v", err)
	}
	ip = ip.Unmap()
	endpoint, err := url.Parse(serverURL.Scheme + "://" + net.JoinHostPort(hostname, port) + path)
	if err != nil {
		t.Fatalf("parse pinned test endpoint: %v", err)
	}
	return Target{
		URL:         endpoint,
		Hostname:    hostname,
		Port:        port,
		IP:          ip,
		DialAddress: net.JoinHostPort(ip.String(), port),
	}
}

func TestResolveReturnsOriginalURLAndPinnedPublicAddress(t *testing.T) {
	resolver := resolverFor("judge.example", "203.0.113.10", "203.0.113.11")
	raw := "https://judge.example:8443/v1/chat/completions?mode=strict"

	target, err := Resolve(context.Background(), raw, false, resolver)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if target.URL == nil || target.URL.String() != raw {
		t.Fatalf("URL = %v, want %q", target.URL, raw)
	}
	if target.Hostname != "judge.example" {
		t.Fatalf("Hostname = %q, want judge.example", target.Hostname)
	}
	if target.Port != "8443" {
		t.Fatalf("Port = %q, want 8443", target.Port)
	}
	if target.IP != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("IP = %s, want first validated answer", target.IP)
	}
	if target.DialAddress != "203.0.113.10:8443" {
		t.Fatalf("DialAddress = %q, want 203.0.113.10:8443", target.DialAddress)
	}
	if resolver.callCount() != 1 {
		t.Fatalf("resolver calls = %d, want exactly one", resolver.callCount())
	}
}

func TestResolveRejectsInvalidURLsBeforeDNS(t *testing.T) {
	tests := map[string]string{
		"empty":              "",
		"unsupported scheme": "ftp://judge.example/model",
		"opaque URL":         "https:judge.example/model",
		"missing host":       "https:///model",
		"userinfo":           "https://user:secret@judge.example/model",
		"fragment":           "https://judge.example/model#section",
		"empty fragment":     "https://judge.example/model#",
		"literal control":    "https://judge.example/model\nnext",
		"escaped control":    "https://judge.example/model%0anext",
		"zero port":          "https://judge.example:0/model",
		"port above maximum": "https://judge.example:65536/model",
		"invalid port":       "https://judge.example:not-a-port/model",
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			resolver := resolverFor("judge.example", "203.0.113.10")
			_, err := Resolve(context.Background(), raw, true, resolver)
			if err == nil {
				t.Fatalf("Resolve(%q) unexpectedly succeeded", raw)
			}
			if resolver.callCount() != 0 {
				t.Fatalf("invalid URL reached DNS: calls = %d", resolver.callCount())
			}
		})
	}
}

func TestResolveRejectsAnyUnsafeDNSAnswer(t *testing.T) {
	resolver := resolverFor("mixed.example", "203.0.113.10", "10.0.0.8")
	_, err := Resolve(context.Background(), "https://mixed.example/model", false, resolver)
	if !errors.Is(err, ErrPrivateAddress) {
		t.Fatalf("mixed DNS error = %v, want ErrPrivateAddress", err)
	}
	if resolver.callCount() != 1 {
		t.Fatalf("resolver calls = %d, want exactly one", resolver.callCount())
	}
}

func TestResolveRejectsForbiddenAddressesEvenWithPrivateOptIn(t *testing.T) {
	tests := []string{
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"::",
		"169.254.169.254",
		"169.254.170.2",
		"100.100.100.200",
		"168.63.129.16",
		"fd00:ec2::254",
		"fd20:ce::254",
		"224.0.0.1",
		"ff02::1",
		"::ffff:127.0.0.1",
		"::ffff:169.254.169.254",
	}

	for _, rawIP := range tests {
		t.Run(rawIP, func(t *testing.T) {
			host := rawIP
			if strings.Contains(rawIP, ":") {
				host = "[" + rawIP + "]"
			}
			_, err := Resolve(context.Background(), "https://"+host+"/model", true, nil)
			if !errors.Is(err, ErrForbiddenAddress) {
				t.Fatalf("Resolve(%s) error = %v, want ErrForbiddenAddress", rawIP, err)
			}
		})
	}
}

func TestResolvePrivateClassesRequireExplicitOptInAndRemainPinned(t *testing.T) {
	tests := []string{
		"10.1.2.3",
		"172.16.2.3",
		"192.168.2.3",
		"fd12:3456::1",
		"100.64.0.8",
		"198.18.0.8",
		"2001:2::8",
	}

	for _, rawIP := range tests {
		t.Run(rawIP, func(t *testing.T) {
			host := rawIP
			if strings.Contains(rawIP, ":") {
				host = "[" + rawIP + "]"
			}
			rawURL := "http://" + host + ":8080/model"
			if _, err := Resolve(context.Background(), rawURL, false, nil); !errors.Is(err, ErrPrivateAddress) {
				t.Fatalf("without opt-in error = %v, want ErrPrivateAddress", err)
			}

			target, err := Resolve(context.Background(), rawURL, true, nil)
			if err != nil {
				t.Fatalf("with opt-in Resolve() error = %v", err)
			}
			wantIP := netip.MustParseAddr(rawIP).Unmap()
			if target.IP != wantIP {
				t.Fatalf("IP = %s, want %s", target.IP, wantIP)
			}
			wantDial := net.JoinHostPort(wantIP.String(), "8080")
			if target.DialAddress != wantDial {
				t.Fatalf("DialAddress = %q, want %q", target.DialAddress, wantDial)
			}
		})
	}
}

func TestResolveUnmapsIPv4MappedPublicAddressBeforePinning(t *testing.T) {
	resolver := &staticResolver{records: map[string][]net.IPAddr{
		"mapped.example": {{IP: net.ParseIP("::ffff:203.0.113.20")}},
	}}
	target, err := Resolve(context.Background(), "https://mapped.example/model", false, resolver)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if target.IP != netip.MustParseAddr("203.0.113.20") {
		t.Fatalf("IP = %s, want unmapped IPv4", target.IP)
	}
	if target.DialAddress != "203.0.113.20:443" {
		t.Fatalf("DialAddress = %q, want 203.0.113.20:443", target.DialAddress)
	}
}

func TestResolveFailsClosedOnDNSFailureOrEmptyAnswers(t *testing.T) {
	t.Run("resolver error", func(t *testing.T) {
		resolver := &staticResolver{err: context.DeadlineExceeded}
		_, err := Resolve(context.Background(), "https://judge.example/model", false, resolver)
		if !errors.Is(err, ErrResolution) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want wrapped ErrResolution and deadline", err)
		}
	})

	for name, resolver := range map[string]*staticResolver{
		"empty":   {records: map[string][]net.IPAddr{"judge.example": nil}},
		"invalid": {records: map[string][]net.IPAddr{"judge.example": {{IP: net.IP{}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Resolve(context.Background(), "https://judge.example/model", false, resolver)
			if !errors.Is(err, ErrResolution) {
				t.Fatalf("error = %v, want ErrResolution", err)
			}
		})
	}
}

func TestClientPinsDialAddressPreservesHostAndDisablesProxy(t *testing.T) {
	var mu sync.Mutex
	var gotHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHost = r.Host
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	target := localServerTarget(t, server, "upstream.example", "/mcp")

	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.Proxy = http.ProxyFromEnvironment
	base := &http.Client{
		Transport: baseTransport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return nil
		},
	}
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")

	client := Client(base, target, false)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport == baseTransport {
		t.Fatal("Client mutated or reused the base transport")
	}
	if transport.Proxy != nil {
		t.Fatal("safe transport must disable all proxy resolution")
	}
	if baseTransport.Proxy == nil {
		t.Fatal("base transport was mutated")
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target.URL.String(), nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	mu.Lock()
	defer mu.Unlock()
	if gotHost != target.URL.Host {
		t.Fatalf("Host = %q, want original %q", gotHost, target.URL.Host)
	}
}

func TestClientPinsPrivateOptInTarget(t *testing.T) {
	resolver := resolverFor("private.example", "10.2.3.4")
	target, err := Resolve(context.Background(), "http://private.example:8080/mcp", true, resolver)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if target.DialAddress != "10.2.3.4:8080" {
		t.Fatalf("private DialAddress = %q, want fixed private IP", target.DialAddress)
	}
	transport := Client(nil, target, true).Transport.(*http.Transport)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := transport.DialContext(ctx, "tcp", net.JoinHostPort(target.Hostname, target.Port))
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("private pinned dial error = %v, want context cancellation", err)
	}
	if resolver.callCount() != 1 {
		t.Fatalf("resolver calls = %d, want no DNS lookup during dial", resolver.callCount())
	}
}

func TestClientRejectsTargetChangeBeforeDial(t *testing.T) {
	target, err := Resolve(context.Background(), "http://203.0.113.40:8080/mcp", false, nil)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	dialCalled := false
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		dialCalled = true
		return nil, errors.New("must not dial")
	}
	client := Client(&http.Client{Transport: baseTransport}, target, false)
	_, err = client.Get("http://other.example:8080/mcp")
	if !errors.Is(err, ErrTargetChanged) {
		t.Fatalf("Get() error = %v, want ErrTargetChanged", err)
	}
	if dialCalled {
		t.Fatal("base dialer was called for a changed target")
	}
}

func TestClientRejectsRedirectWithoutFollowingDestination(t *testing.T) {
	var mu sync.Mutex
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer server.Close()
	target := localServerTarget(t, server, "redirect.example", "/start")
	base := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return nil
		},
	}
	resp, err := Client(base, target, false).Get(target.URL.String())
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("redirect error = %v, want ErrRedirectNotAllowed", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requestCount != 1 {
		t.Fatalf("request count = %d, want exactly one", requestCount)
	}
}

func TestClientPreservesTLSServerNameWhileDialingPin(t *testing.T) {
	var mu sync.Mutex
	var gotSNI string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			gotSNI = hello.ServerName
			mu.Unlock()
			return nil, nil
		},
	}
	server.StartTLS()
	defer server.Close()
	target := localServerTarget(t, server, "tls.example.com", "/judge")
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.TLSClientConfig = &tls.Config{
		RootCAs:            roots,
		InsecureSkipVerify: true, // Safe Client must override this unsafe base field.
	}
	client := Client(&http.Client{Transport: baseTransport, Timeout: 5 * time.Second}, target, false)
	resp, err := client.Get(target.URL.String())
	if err != nil {
		t.Fatalf("TLS Get() error = %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.ServerName != "tls.example.com" {
		t.Fatalf("TLS ServerName config = %#v, want tls.example.com", transport.TLSClientConfig)
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("safe TLS transport did not restore certificate verification")
	}
	mu.Lock()
	defer mu.Unlock()
	if gotSNI != "tls.example.com" {
		t.Fatalf("observed SNI = %q, want tls.example.com", gotSNI)
	}
}

func TestTransportClearsTLSDialersThatCouldBypassPin(t *testing.T) {
	target, err := Resolve(context.Background(), "https://203.0.113.43/judge", false, nil)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("custom TLS dialer")
	}
	base.DialTLS = func(string, string) (net.Conn, error) {
		return nil, errors.New("legacy custom TLS dialer")
	}

	transport := Transport(base, target)
	if transport.DialTLSContext != nil || transport.DialTLS != nil {
		t.Fatal("custom TLS dialers must be cleared so HTTPS uses pinned DialContext")
	}
	if base.DialTLSContext == nil || base.DialTLS == nil {
		t.Fatal("base transport was mutated")
	}
}

func TestClientStreamingClearsOnlyOverallTimeout(t *testing.T) {
	target, err := Resolve(context.Background(), "https://203.0.113.44/judge", false, nil)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.ResponseHeaderTimeout = 17 * time.Second
	base := &http.Client{Transport: baseTransport, Timeout: 3 * time.Second}

	normal := Client(base, target, false)
	if normal.Timeout != 3*time.Second {
		t.Fatalf("normal Timeout = %s, want base timeout", normal.Timeout)
	}
	streaming := Client(base, target, true)
	if streaming.Timeout != 0 {
		t.Fatalf("streaming Timeout = %s, want no wall-clock timeout", streaming.Timeout)
	}
	if streaming.Transport.(*http.Transport).ResponseHeaderTimeout != 17*time.Second {
		t.Fatal("streaming client did not preserve response-header timeout")
	}
	if base.Timeout != 3*time.Second || baseTransport.ResponseHeaderTimeout != 17*time.Second {
		t.Fatal("base client or transport was mutated")
	}
}

func TestClientNilBaseUsesSafeDefaults(t *testing.T) {
	target, err := Resolve(context.Background(), "https://203.0.113.45/judge", false, nil)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	client := Client(nil, target, false)
	if client == nil {
		t.Fatal("Client(nil, ...) returned nil")
	}
	if client.Timeout <= 0 {
		t.Fatalf("nil-base client Timeout = %s, want bounded default", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil || transport.DialContext == nil {
		t.Fatal("nil-base client is missing proxy disablement or pinned dialer")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.ServerName != "203.0.113.45" {
		t.Fatalf("TLS config = %#v, want original hostname", transport.TLSClientConfig)
	}
	if client.CheckRedirect == nil || !errors.Is(client.CheckRedirect(nil, nil), ErrRedirectNotAllowed) {
		t.Fatal("nil-base client must reject every redirect")
	}
}

func TestResolveRejectsMappedMetadataInMixedDNSWithPrivateOptIn(t *testing.T) {
	resolver := &staticResolver{records: map[string][]net.IPAddr{
		"mixed.example": {
			{IP: net.ParseIP("203.0.113.50")},
			{IP: net.ParseIP("::ffff:100.100.100.200")},
		},
	}}
	_, err := Resolve(context.Background(), "https://mixed.example/model", true, resolver)
	if !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("mixed mapped-metadata error = %v, want ErrForbiddenAddress", err)
	}
}

func TestClientRejectsInconsistentExportedPinBeforeBaseDial(t *testing.T) {
	target, err := Resolve(context.Background(), "https://203.0.113.51/judge", false, nil)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	target.DialAddress = "10.0.0.1:443"
	dialCalled := false
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		dialCalled = true
		return nil, errors.New("base dial should not run")
	}

	client := Client(&http.Client{Transport: baseTransport}, target, false)
	_, err = client.Get(target.URL.String())
	if !errors.Is(err, ErrTargetChanged) {
		t.Fatalf("Get() error = %v, want ErrTargetChanged", err)
	}
	if dialCalled {
		t.Fatal("inconsistent exported pin reached the base dialer")
	}
}

func TestTransportIgnoresBaseDialContext(t *testing.T) {
	target, err := Resolve(context.Background(), "https://203.0.113.52/judge", false, nil)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	maliciousDialError := errors.New("base dialer bypassed the pin")
	baseDialCalled := false
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		baseDialCalled = true
		return nil, maliciousDialError
	}

	transport := Transport(base, target)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := transport.DialContext(ctx, "tcp", net.JoinHostPort(target.Hostname, target.Port))
	if conn != nil {
		_ = conn.Close()
	}
	if baseDialCalled || errors.Is(err, maliciousDialError) {
		t.Fatalf("safe transport reused untrusted base DialContext: called=%v err=%v", baseDialCalled, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContext() error = %v, want canceled fresh net.Dialer", err)
	}
}

func TestTransportForcesCertificateVerification(t *testing.T) {
	target, err := Resolve(context.Background(), "https://203.0.113.53/judge", false, nil)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Deliberately unsafe base fixture.

	transport := Transport(base, target)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("safe transport inherited InsecureSkipVerify from base")
	}
	if base.TLSClientConfig == nil || !base.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("base TLS config was mutated")
	}
}
