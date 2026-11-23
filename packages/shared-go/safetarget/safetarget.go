// Package safetarget validates outbound HTTP(S) targets and pins each accepted
// target to one IP address. It is intended to be the single SSRF boundary for
// callers that fetch administrator- or user-configured URLs.
package safetarget

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
)

var (
	// ErrInvalidURL marks URLs that cannot be used as an HTTP(S) target.
	ErrInvalidURL = errors.New("safetarget: invalid URL")
	// ErrResolution marks DNS failures, empty answers, and malformed answers.
	ErrResolution = errors.New("safetarget: name resolution failed")
	// ErrForbiddenAddress marks addresses that are never valid egress targets.
	ErrForbiddenAddress = errors.New("safetarget: forbidden address")
	// ErrPrivateAddress marks private-like addresses without explicit opt-in.
	ErrPrivateAddress = errors.New("safetarget: private address requires explicit opt-in")
	// ErrRedirectNotAllowed marks every redirect blocked by Client.
	ErrRedirectNotAllowed = errors.New("safetarget: redirects are not allowed")
	// ErrTargetChanged marks reuse of a pinned transport for another host/port.
	ErrTargetChanged = errors.New("safetarget: dial target changed after validation")
	// ErrInvalidTrustedCA marks an Options.TrustedCAPEM without any usable certificate.
	ErrInvalidTrustedCA = errors.New("safetarget: trusted CA PEM has no usable certificate")
)

// Options 是对象级的出站放行（反向代理路由、MCP 服务的 egress_overrides）。零值即默认：
// 内网、回环、链路本地、元数据、内部主机名一律拒绝，证书必须校验，重定向一律拒绝。
// 每个开关只放开自己那一类，互不放大；未指定地址、组播等不可连接的地址始终拒绝。
type Options struct {
	// AllowPrivate 放开 RFC1918/ULA/CGNAT 等内网地址（原 allowPrivate 参数）。
	AllowPrivate bool
	// AllowLoopback 放开回环地址，以及 localhost 这类回环主机名。
	AllowLoopback bool
	// AllowLinkLocal 放开链路本地地址（元数据地址除外）。
	AllowLinkLocal bool
	// AllowMetadata 放开云元数据地址，以及 metadata.google.internal 这类元数据主机名。
	AllowMetadata bool
	// AllowInternalHostnames 放过主机名层面的拦截（localhost、元数据名），解析出的地址仍按
	// 上面的开关逐个判定。
	AllowInternalHostnames bool
	// TrustedCAPEM 是额外信任的 CA（PEM），用于自签证书的上游；系统根证书仍然信任。
	TrustedCAPEM string
	// InsecureSkipVerify 跳过证书校验。
	InsecureSkipVerify bool
	// AllowSameHostRedirect 允许跟随同协议、同主机、同端口的重定向；跨主机照旧拒绝。
	AllowSameHostRedirect bool
}

const (
	defaultClientTimeout         = 30 * time.Second
	defaultResponseHeaderTimeout = 60 * time.Second
)

// Resolver is the subset of net.Resolver used by Resolve. Supplying one makes
// DNS policy deterministic in tests. A nil Resolver uses net.DefaultResolver.
type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// Target is an outbound URL whose complete DNS answer set has passed policy.
// DialAddress is always the selected, canonical IP plus Port; callers must use
// Client or Transport rather than resolving Hostname again.
type Target struct {
	URL         *url.URL
	Hostname    string
	Port        string
	IP          netip.Addr
	DialAddress string

	// opts 与 rootCAs 由 ResolveWithOptions 写入，Client/Transport 据此设置证书校验与重定向。
	opts    Options
	rootCAs *x509.CertPool
}

// maxTrustedCAPools 限制缓存的证书池个数（每份 egress_overrides 的自定义 CA 一个）。
const maxTrustedCAPools = 256

var (
	trustedCAPoolsMu sync.Mutex
	trustedCAPools   = map[[sha256.Size]byte]*x509.CertPool{}
)

// trustedCAPool 解析自定义 CA（系统根证书之外再信任它）；同一份 PEM 只解析一次，之后复用同一个证书池
// （路由与 MCP 服务的 egress_overrides 不变时每次请求都是同一份）。证书池只读，可并发使用。
func trustedCAPool(pemText string) (*x509.CertPool, error) {
	key := sha256.Sum256([]byte(pemText))
	trustedCAPoolsMu.Lock()
	pool, ok := trustedCAPools[key]
	trustedCAPoolsMu.Unlock()
	if ok {
		return pool, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(pemText)) {
		return nil, ErrInvalidTrustedCA
	}
	trustedCAPoolsMu.Lock()
	if len(trustedCAPools) >= maxTrustedCAPools {
		trustedCAPools = map[[sha256.Size]byte]*x509.CertPool{}
	}
	trustedCAPools[key] = pool
	trustedCAPoolsMu.Unlock()
	return pool, nil
}

// Resolve parses rawURL, validates every resolved address, and returns one IP
// pin. Any unsafe DNS answer rejects the whole target, preventing mixed-answer
// records from hiding a private or metadata address behind a public answer.
func Resolve(
	ctx context.Context,
	rawURL string,
	allowPrivate bool,
	resolver Resolver,
) (Target, error) {
	return ResolveWithOptions(ctx, rawURL, Options{AllowPrivate: allowPrivate}, resolver)
}

// ResolveWithOptions 与 Resolve 相同，按对象级出站放行 opts 判定地址，并把证书与重定向
// 选项带进返回的 Target（Client/Transport 会用到）。
func ResolveWithOptions(
	ctx context.Context,
	rawURL string,
	opts Options,
	resolver Resolver,
) (Target, error) {
	var rootCAs *x509.CertPool
	if strings.TrimSpace(opts.TrustedCAPEM) != "" {
		pool, err := trustedCAPool(opts.TrustedCAPEM)
		if err != nil {
			return Target{}, err
		}
		rootCAs = pool
	}
	if containsControl(rawURL) {
		return Target{}, fmt.Errorf("%w: control characters are not allowed", ErrInvalidURL)
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" || len(rawURL) > 2048 {
		return Target{}, fmt.Errorf("%w: URL is empty or exceeds 2048 bytes", ErrInvalidURL)
	}
	if strings.Contains(rawURL, "#") {
		return Target{}, fmt.Errorf("%w: fragments are not allowed", ErrInvalidURL)
	}
	decoded, err := url.PathUnescape(rawURL)
	if err != nil || containsControl(decoded) {
		return Target{}, fmt.Errorf("%w: escaped control character or invalid escape", ErrInvalidURL)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" {
		return Target{}, fmt.Errorf("%w: expected an absolute hierarchical URL", ErrInvalidURL)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return Target{}, fmt.Errorf("%w: scheme must be http or https", ErrInvalidURL)
	}
	if parsed.User != nil {
		return Target{}, fmt.Errorf("%w: userinfo is not allowed", ErrInvalidURL)
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" {
		return Target{}, fmt.Errorf("%w: fragments are not allowed", ErrInvalidURL)
	}

	hostname := normalizeHostname(parsed.Hostname())
	if hostname == "" || containsControl(hostname) || strings.ContainsAny(hostname, `/\\`) {
		return Target{}, fmt.Errorf("%w: invalid hostname", ErrInvalidURL)
	}
	if isForbiddenHostname(hostname) && !forbiddenHostnameAllowed(hostname, opts) {
		return Target{}, fmt.Errorf("%w: %s", ErrForbiddenAddress, hostname)
	}

	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return Target{}, fmt.Errorf("%w: invalid port", ErrInvalidURL)
	}

	addresses, err := resolveAddresses(ctx, hostname, resolver)
	if err != nil {
		return Target{}, err
	}
	var selected netip.Addr
	for _, address := range addresses {
		if err := validateAddress(address, opts); err != nil {
			return Target{}, err
		}
		if !selected.IsValid() {
			selected = address
		}
	}
	if !selected.IsValid() {
		return Target{}, fmt.Errorf("%w: no usable address", ErrResolution)
	}

	return Target{
		URL:         parsed,
		Hostname:    hostname,
		Port:        port,
		IP:          selected,
		DialAddress: net.JoinHostPort(selected.String(), port),
		opts:        opts,
		rootCAs:     rootCAs,
	}, nil
}

func resolveAddresses(ctx context.Context, hostname string, resolver Resolver) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(hostname); err == nil {
		if literal.Zone() != "" {
			return nil, fmt.Errorf("%w: scoped IP literals are not allowed", ErrForbiddenAddress)
		}
		return []netip.Addr{literal.Unmap()}, nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	answers, err := resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResolution, err)
	}
	if len(answers) == 0 {
		return nil, fmt.Errorf("%w: no DNS answers", ErrResolution)
	}

	addresses := make([]netip.Addr, 0, len(answers))
	for _, answer := range answers {
		if answer.Zone != "" {
			return nil, fmt.Errorf("%w: scoped DNS answers are not allowed", ErrResolution)
		}
		address, ok := netip.AddrFromSlice(answer.IP)
		if !ok {
			return nil, fmt.Errorf("%w: invalid DNS answer", ErrResolution)
		}
		addresses = append(addresses, address.Unmap())
	}
	return addresses, nil
}

// validateAddress 只把 egresspolicy.Classify 的类别映射到对象级开关（全平台唯一的地址分类）。
func validateAddress(address netip.Addr, opts Options) error {
	address = address.Unmap()
	switch egresspolicy.Classify(address) {
	case egresspolicy.ClassMetadata:
		if opts.AllowMetadata {
			return nil
		}
		return fmt.Errorf("%w: metadata endpoint %s", ErrForbiddenAddress, address)
	case egresspolicy.ClassLoopback:
		if opts.AllowLoopback {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrForbiddenAddress, address)
	case egresspolicy.ClassLinkLocal:
		if opts.AllowLinkLocal {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrForbiddenAddress, address)
	case egresspolicy.ClassReserved:
		return fmt.Errorf("%w: %s", ErrForbiddenAddress, address)
	case egresspolicy.ClassPrivate:
		if !opts.AllowPrivate {
			return fmt.Errorf("%w: %s", ErrPrivateAddress, address)
		}
	}
	return nil
}

func normalizeHostname(hostname string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
}

// forbiddenHostnameAllowed 判断被拦的主机名是否由选项放开：内部主机名开关放开全部；
// 回环开关放开 localhost 一类；元数据开关放开元数据名。解析出的地址仍逐个判定。
func forbiddenHostnameAllowed(hostname string, opts Options) bool {
	if opts.AllowInternalHostnames {
		return true
	}
	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		return opts.AllowLoopback
	}
	return opts.AllowMetadata
}

func isForbiddenHostname(hostname string) bool {
	return hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") || egresspolicy.IsMetadataHostname(hostname)
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

// sameOrigin 判断重定向目标与已校验目标是否同协议、同主机、同端口。
func sameOrigin(next *url.URL, target Target) bool {
	if next == nil || target.URL == nil || !strings.EqualFold(next.Scheme, target.URL.Scheme) {
		return false
	}
	port := next.Port()
	if port == "" {
		if strings.EqualFold(next.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	return normalizeHostname(next.Hostname()) == normalizeHostname(target.Hostname) && port == target.Port
}

// Transport clones base and binds all dials to target.DialAddress. A nil base
// clones http.DefaultTransport. Proxy lookup and every base dialing hook are
// ignored because any of them could bypass the validated IP pin.
func Transport(base *http.Transport, target Target) *http.Transport {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	transport := base.Clone()
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}

	expectedHost := normalizeHostname(target.Hostname)
	expectedPort := target.Port
	pinnedIP := target.IP.Unmap()
	pinnedAddress := ""
	if pinnedIP.IsValid() {
		pinnedAddress = net.JoinHostPort(pinnedIP.String(), expectedPort)
	}
	pinConsistent := target.DialAddress == pinnedAddress

	transport.Proxy = nil
	transport.DialTLSContext = nil
	transport.DialTLS = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || normalizeHostname(host) != expectedHost || port != expectedPort {
			return nil, fmt.Errorf("%w: got %q, want %s", ErrTargetChanged, address, net.JoinHostPort(expectedHost, expectedPort))
		}
		if !pinConsistent || pinnedAddress == "" {
			return nil, fmt.Errorf("%w: inconsistent IP pin", ErrTargetChanged)
		}
		if network == "tcp4" && !pinnedIP.Is4() {
			return nil, fmt.Errorf("%w: IPv6 pin cannot use tcp4", ErrTargetChanged)
		}
		if network == "tcp6" && !pinnedIP.Is6() {
			return nil, fmt.Errorf("%w: IPv4 pin cannot use tcp6", ErrTargetChanged)
		}
		return dialer.DialContext(ctx, network, pinnedAddress)
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.MinVersion == 0 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	// A safe target still requires authenticated TLS; an unsafe base client
	// cannot opt this transport out of certificate and hostname verification.
	// Only the target's own object-level options (egress_overrides) can.
	transport.TLSClientConfig.InsecureSkipVerify = target.opts.InsecureSkipVerify
	if target.rootCAs != nil {
		transport.TLSClientConfig.RootCAs = target.rootCAs
	}
	if target.URL != nil && strings.EqualFold(target.URL.Scheme, "https") {
		// The TCP connection uses the pin, while certificate verification and
		// SNI continue to use the original validated hostname.
		transport.TLSClientConfig.ServerName = expectedHost
	}
	return transport
}

// Client returns a copy of base that can only reach target. Redirects and
// proxies are rejected unconditionally. In streaming mode the overall client
// timeout is cleared so a long-lived response is governed by request context;
// the response-header timeout remains bounded.
func Client(base *http.Client, target Target, streaming bool) *http.Client {
	var baseTransport *http.Transport
	if base != nil {
		if transport, ok := base.Transport.(*http.Transport); ok {
			baseTransport = transport
		}
	}
	transport := Transport(baseTransport, target)
	client := &http.Client{
		Transport: transport,
		Timeout:   defaultClientTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if target.opts.AllowSameHostRedirect && len(via) < 10 && sameOrigin(req.URL, target) {
				return nil
			}
			return ErrRedirectNotAllowed
		},
	}
	if base != nil {
		client.Jar = base.Jar
		if base.Timeout > 0 {
			client.Timeout = base.Timeout
		}
	}
	if streaming {
		client.Timeout = 0
		if transport.ResponseHeaderTimeout == 0 {
			transport.ResponseHeaderTimeout = defaultResponseHeaderTimeout
		}
	}
	return client
}
