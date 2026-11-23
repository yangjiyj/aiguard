package identity

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
)

var (
	alwaysBlockedCIDRs = []string{
		"127.0.0.0/8",
		"::1/128",
		"169.254.0.0/16",
		"fe80::/10",
		"0.0.0.0/8",
	}
	defaultPrivateCIDRs = []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"fc00::/7",
	}
)

type SSRFGuard struct {
	alwaysBlocked         []netip.Prefix
	privateBlocked        []netip.Prefix
	blockPrivate          bool
	allowed               []netip.Prefix
	lookupIP              func(string) ([]net.IP, error)
	allowNonGlobalForTest bool
}

func NewSSRFGuard() *SSRFGuard {
	g := &SSRFGuard{lookupIP: net.LookupIP, blockPrivate: egressBlockPrivate(os.Getenv("JJD_IDP_BLOCK_PRIVATE"))}
	for _, cidr := range alwaysBlockedCIDRs {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			g.alwaysBlocked = append(g.alwaysBlocked, p)
		}
	}
	for _, cidr := range defaultPrivateCIDRs {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			g.privateBlocked = append(g.privateBlocked, p)
		}
	}
	for _, cidr := range egressAllowedCIDRs(os.Getenv("JJD_IDP_ALLOW_CIDRS")) {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if p, err := netip.ParsePrefix(cidr); err == nil {
			g.allowed = append(g.allowed, p)
		}
	}
	return g
}

func (g *SSRFGuard) isAllowed(addr netip.Addr) bool {
	for _, ap := range g.allowed {
		if ap.Contains(addr) {
			return true
		}
	}
	return false
}

func (g *SSRFGuard) isExplicitlyAllowed(ip net.IP) bool {
	normalized := ip.To4()
	if normalized == nil {
		normalized = ip.To16()
	}
	addr, ok := netip.AddrFromSlice(normalized)
	if !ok || !g.isAllowed(addr) {
		return false
	}
	if g.allowNonGlobalForTest {
		return true
	}
	for _, privateRange := range g.privateBlocked {
		if privateRange.Contains(addr) {
			return true
		}
	}
	return false
}

func (g *SSRFGuard) isBlocked(ip net.IP) bool {
	normalized := ip.To4()
	if normalized == nil {
		normalized = ip.To16()
	}
	if normalized == nil {
		return true
	}
	addr, ok := netip.AddrFromSlice(normalized)
	if !ok {
		return true
	}
	// 云元数据地址常拦（egresspolicy 的唯一集合），放行网段盖住也不放。
	if egresspolicy.IsMetadataAddr(addr) {
		return true
	}
	if !addr.IsGlobalUnicast() && !g.allowNonGlobalForTest {
		return true
	}

	for _, p := range g.alwaysBlocked {
		if p.Contains(addr) {
			return true
		}
	}
	if g.isAllowed(addr) {
		return false
	}
	for _, p := range g.privateBlocked {
		if g.blockPrivate && p.Contains(addr) {
			return true
		}
	}
	return false
}

func (g *SSRFGuard) resolveHost(host string) ([]net.IP, error) {
	// 云元数据主机名常拦（egresspolicy 的唯一清单），不解析。
	if egresspolicy.IsMetadataHostname(host) {
		if EgressDeniedRecorder != nil {
			EgressDeniedRecorder(host)
		}
		return nil, fmt.Errorf("目标地址被禁止访问（环回、云元数据或未授权私网）")
	}
	var ips []net.IP
	if literal := net.ParseIP(host); literal != nil {
		ips = []net.IP{literal}
	} else {
		var err error
		ips, err = g.lookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("无法解析主机名: %s", host)
		}
	}
	for _, ip := range ips {
		if g.isBlocked(ip) {
			if EgressDeniedRecorder != nil {
				EgressDeniedRecorder(host)
			}
			return nil, fmt.Errorf("目标地址被禁止访问（环回、云元数据或未授权私网）")
		}
	}
	return ips, nil
}

func (g *SSRFGuard) dialContext(ctx context.Context, network, address string, requireExplicitPrivate bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("目标地址无效")
	}
	ips, err := g.resolveHost(host)
	if err != nil {
		return nil, err
	}
	if requireExplicitPrivate {
		for _, ip := range ips {
			if !g.isExplicitlyAllowed(ip) {
				return nil, fmt.Errorf("公网身份源必须使用 HTTPS")
			}
		}
	}
	return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

func (g *SSRFGuard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return g.dialContext(ctx, network, address, false)
}

func (g *SSRFGuard) DialPrivateContext(ctx context.Context, network, address string) (net.Conn, error) {
	return g.dialContext(ctx, network, address, true)
}

func (g *SSRFGuard) CheckURL(rawURL string) (string, net.IP, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", nil, fmt.Errorf("无法解析地址: %v", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", nil, fmt.Errorf("仅支持 HTTP 或 HTTPS 协议")
	}
	if parsed.User != nil {
		return "", nil, fmt.Errorf("地址不得包含用户凭据")
	}
	host := parsed.Hostname()
	if host == "" {
		return "", nil, fmt.Errorf("地址缺少主机名")
	}
	ips, err := g.resolveHost(host)
	if err != nil {
		return "", nil, err
	}
	return parsed.String(), ips[0], nil
}

func (g *SSRFGuard) CheckRequestURL(rawURL string) (string, net.IP, error) {
	normalized, ip, err := g.CheckURL(rawURL)
	if err != nil {
		return "", nil, err
	}
	parsed, _ := url.Parse(normalized)
	if parsed.Scheme == "http" && !g.isExplicitlyAllowed(ip) {
		return "", nil, fmt.Errorf("公网身份源必须使用 HTTPS")
	}
	return normalized, ip, nil
}
