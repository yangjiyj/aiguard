package handler

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
)

const (
	bundledSemanticJudgeURL       = "http://llm-judge:8080/v1/chat/completions"
	semanticJudgeMaxResponseBytes = 256 << 10
	semanticJudgeMaxRequestBytes  = 32 << 10
	semanticJudgeDNSLookupTimeout = 3 * time.Second
)

type semanticJudgeResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type semanticJudgeNetwork struct {
	resolver                  semanticJudgeResolver
	dialContext               func(context.Context, string, string) (net.Conn, error)
	tlsConfig                 *tls.Config
	testOnlyAllowInsecureHTTP bool
}

type preparedSemanticJudgeEndpoint struct {
	endpoint *url.URL
	ips      []net.IP
	port     string
	network  semanticJudgeNetwork
}

func defaultSemanticJudgeNetwork() semanticJudgeNetwork {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return semanticJudgeNetwork{
		resolver:    net.DefaultResolver,
		dialContext: dialer.DialContext,
	}
}

// prepareSemanticJudgeEndpoint is the single SSRF boundary shared by settings
// validation and the live judge probe. DNS is resolved exactly once, every
// answer is validated, and the resulting endpoint can only dial those answers.
func prepareSemanticJudgeEndpoint(
	ctx context.Context,
	raw string,
	allowPrivate bool,
	network semanticJudgeNetwork,
) (*preparedSemanticJudgeEndpoint, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > 2048 {
		return nil, fmt.Errorf("judge_url is empty or exceeds limit")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("judge_url must be an http(s) URL")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("judge_url cannot contain credentials or fragments")
	}
	// Plain HTTP is only acceptable for the bundled sidecar or, with the
	// explicit private-egress opt-in, for a judge inside the controlled private
	// network. A public HTTP judge would carry prompts in cleartext.
	plainHTTPPrivateOnly := raw != bundledSemanticJudgeURL && parsed.Scheme != "https" && !network.testOnlyAllowInsecureHTTP
	if plainHTTPPrivateOnly && !allowPrivate {
		return nil, fmt.Errorf("custom and provider judge_url must use https unless private egress is explicitly authorized")
	}

	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(parsed.Hostname())), ".")
	if host == "" {
		return nil, fmt.Errorf("judge_url host is required")
	}
	if isForbiddenSemanticJudgeHostname(host) {
		return nil, fmt.Errorf("judge_url targets a forbidden metadata endpoint")
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("judge_url contains an invalid port")
	}

	if network.resolver == nil {
		network.resolver = net.DefaultResolver
	}
	if network.dialContext == nil {
		network.dialContext = defaultSemanticJudgeNetwork().dialContext
	}

	var resolved []net.IP
	if literal := net.ParseIP(host); literal != nil {
		resolved = []net.IP{literal}
	} else {
		lookupCtx, cancel := context.WithTimeout(ctx, semanticJudgeDNSLookupTimeout)
		answers, lookupErr := network.resolver.LookupIPAddr(lookupCtx, host)
		cancel()
		if lookupErr != nil || len(answers) == 0 {
			return nil, fmt.Errorf("judge_url host resolution failed")
		}
		resolved = make([]net.IP, 0, len(answers))
		for _, answer := range answers {
			resolved = append(resolved, answer.IP)
		}
	}

	privateAllowed := allowPrivate || raw == bundledSemanticJudgeURL
	seen := make(map[string]struct{}, len(resolved))
	validated := make([]net.IP, 0, len(resolved))
	for _, ip := range resolved {
		if err := validateSemanticJudgeIP(ip, privateAllowed); err != nil {
			return nil, err
		}
		if plainHTTPPrivateOnly && !isSemanticJudgePrivateLikeIP(ip) {
			return nil, fmt.Errorf("plain http judge_url is only allowed for private addresses; public endpoints must use https")
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		validated = append(validated, append(net.IP(nil), ip...))
	}
	if len(validated) == 0 {
		return nil, fmt.Errorf("judge_url host resolved to no usable address")
	}

	return &preparedSemanticJudgeEndpoint{
		endpoint: parsed,
		ips:      validated,
		port:     port,
		network:  network,
	}, nil
}

func isForbiddenSemanticJudgeHostname(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || egresspolicy.IsMetadataHostname(host)
}

func validateSemanticJudgeIP(ip net.IP, allowPrivate bool) error {
	if ip == nil {
		return fmt.Errorf("judge_url resolved to an invalid address")
	}
	if isCloudMetadataIP(ip) {
		return fmt.Errorf("judge_url targets a forbidden metadata address")
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return fmt.Errorf("judge_url targets a forbidden address")
	}
	if isSemanticJudgePrivateLikeIP(ip) && !allowPrivate {
		return fmt.Errorf("judge_url resolved to a private address; explicit private egress opt-in is required")
	}
	return nil
}

func isSemanticJudgePrivateLikeIP(ip net.IP) bool {
	if ip.IsPrivate() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// RFC 6598 shared address space is used by CGNAT and Tailscale. It is
		// reachable inside many deployments, so it requires the same explicit
		// opt-in as RFC 1918. Benchmark networks are treated identically.
		if v4[0] == 100 && v4[1]&0xc0 == 0x40 {
			return true
		}
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return true
		}
	}
	return false
}

// isCloudMetadataIP 用全平台唯一的元数据地址集合（egresspolicy）。
func isCloudMetadataIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	return ok && egresspolicy.IsMetadataAddr(addr)
}

func (target *preparedSemanticJudgeEndpoint) httpClient(timeout time.Duration) (*http.Client, *http.Transport) {
	expectedHost := strings.TrimSuffix(strings.ToLower(target.endpoint.Hostname()), ".")
	expectedPort := target.port

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.MaxIdleConns = 0
	transport.ResponseHeaderTimeout = timeout
	transport.TLSHandshakeTimeout = timeout
	if target.network.tlsConfig != nil {
		transport.TLSClientConfig = target.network.tlsConfig.Clone()
	} else {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if target.endpoint.Scheme == "https" {
		transport.TLSClientConfig.ServerName = expectedHost
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("judge dial address is invalid")
		}
		if strings.TrimSuffix(strings.ToLower(host), ".") != expectedHost || port != expectedPort {
			return nil, fmt.Errorf("judge dial target changed after validation")
		}
		var lastErr error
		for _, ip := range target.ips {
			if network == "tcp4" && ip.To4() == nil {
				continue
			}
			if network == "tcp6" && ip.To4() != nil {
				continue
			}
			pinned := net.JoinHostPort(ip.String(), expectedPort)
			conn, dialErr := target.network.dialContext(ctx, network, pinned)
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no validated address matches network %s", network)
		}
		return nil, fmt.Errorf("failed to dial validated judge address: %w", lastErr)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("semantic judge redirects are not allowed")
		},
	}
	return client, transport
}

func readSemanticJudgeResponse(body io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(body, semanticJudgeMaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > semanticJudgeMaxResponseBytes {
		return nil, fmt.Errorf("semantic judge response is too large")
	}
	return raw, nil
}
