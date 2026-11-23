package handler

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
)

// errBlockedEgress 标记防跳板出站拒绝（内网、回环、链路本地、元数据等）。
var errBlockedEgress = errors.New("blocked egress target")

const maxIPv4Value = uint64(1<<32 - 1)

type IPResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type EgressTarget struct {
	OriginalAddress string
	Host            string
	Port            string
	IP              net.IP
	PinnedAddress   string
	// ViaSetting 表示目标是内部地址，靠平台出站放行设置放行。
	ViaSetting bool
}

type EgressGuard struct {
	resolver IPResolver
	dialer   DialContextFunc
	// upstreamProxy 是客户侧的出网代理（双层代理里的第二跳）。
	// 默认 nil = 不启用，SSRF 防线维持原样。见 upstream_proxy.go。
	upstreamProxy *url.URL
	// settings 返回平台的防跳板出站放行设置（允许内网/回环/元数据、放行网段与主机名）；
	// nil 或返回零值时全部拒绝。全局观察留痕不改变这里的判定。
	settings func(context.Context) egresspolicy.Settings
}

// SetSettingsSource 注入出站放行设置的读取函数。
func (g *EgressGuard) SetSettingsSource(source func(context.Context) egresspolicy.Settings) {
	if g != nil {
		g.settings = source
	}
}

// currentSettings 读出放行设置并带上独立代理的 2.9.21 分类口径（egresspolicy.CompatProxyServer）。
func (g *EgressGuard) currentSettings(ctx context.Context) egresspolicy.Settings {
	var settings egresspolicy.Settings
	if g != nil && g.settings != nil {
		settings = g.settings(ctx)
	}
	settings.Compat = egresspolicy.CompatProxyServer
	return settings
}

// checkEgressIP 按设置判定一个地址；返回是否放行、是否靠设置放行。
func checkEgressIP(settings egresspolicy.Settings, ip net.IP) (bool, bool) {
	ip = normalizeIP(ip)
	if ip == nil {
		return false, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false, false
	}
	verdict := settings.CheckAddr(addr.Unmap())
	return verdict.Allowed, verdict.ViaSetting
}

func NewEgressGuard(resolver IPResolver, dialer DialContextFunc) *EgressGuard {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if dialer == nil {
		netDialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		dialer = netDialer.DialContext
	}
	return &EgressGuard{resolver: resolver, dialer: dialer}
}

func (g *EgressGuard) HTTPTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = g.DialContext
	// 启用上层出网代理时钉死那一跳，不再读进程环境变量：环境变量是隐式的，
	// 双层代理下一旦被别处改掉，流量会静默换路。不启用时保持
	// DefaultTransport 的 ProxyFromEnvironment 语义不变。
	if g != nil && g.upstreamProxy != nil {
		proxy := g.upstreamProxy
		transport.Proxy = func(*http.Request) (*url.URL, error) { return proxy, nil }
	}
	return transport
}

func (g *EgressGuard) Resolve(ctx context.Context, address string) (EgressTarget, error) {
	host, port, err := splitNetworkAddress(address)
	if err != nil {
		return EgressTarget{}, err
	}
	settings := g.currentSettings(ctx)
	viaSetting := false
	if isBlockedMetadataHostname(host) {
		if !settings.AllowMetadata && !settings.HostListed(host) {
			return EgressTarget{}, blockedEgressError(host, nil)
		}
		viaSetting = true
	}

	// 双层代理：配置的那一跳通常在内网，需要精确豁免。只放行完全相等的
	// host:port，其余内网地址照旧挡住——不是把网段放开。
	exempt := g.upstreamProxyExemptAddress(host, port)

	if ip := parseIPLiteral(host); ip != nil {
		allowed, byIPSetting := checkEgressIP(settings, ip)
		if !allowed && !exempt {
			return EgressTarget{}, blockedEgressError(host, ip)
		}
		target := buildEgressTarget(address, host, port, ip)
		target.ViaSetting = byIPSetting && !exempt
		return target, nil
	}

	ips, err := g.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return EgressTarget{}, fmt.Errorf("resolve egress target %s: %w", host, err)
	}
	if len(ips) == 0 {
		return EgressTarget{}, fmt.Errorf("resolve egress target %s: no addresses", host)
	}
	var selected net.IP
	for _, resolved := range ips {
		ip := normalizeIP(resolved.IP)
		if ip == nil {
			continue
		}
		allowed, byIPSetting := checkEgressIP(settings, ip)
		if !allowed {
			return EgressTarget{}, blockedEgressError(host, ip)
		}
		viaSetting = viaSetting || byIPSetting
		if selected == nil {
			selected = ip
		}
	}
	if selected == nil {
		return EgressTarget{}, fmt.Errorf("resolve egress target %s: no usable addresses", host)
	}
	target := buildEgressTarget(address, host, port, selected)
	target.ViaSetting = viaSetting
	return target, nil
}

func (g *EgressGuard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// 启用上层出网代理时，TCP 该拨的是代理那一跳；到真实目标的 CONNECT
	// 由上层 transport 发起。注意这不绕过白名单——白名单在 handleConnect
	// 里按 r.Host 判定，早于这里。
	if g != nil && g.upstreamProxy != nil {
		hop, err := g.Resolve(ctx, g.upstreamProxy.Host)
		if err != nil {
			return nil, err
		}
		return g.dialer(ctx, network, hop.PinnedAddress)
	}
	target, err := g.Resolve(ctx, address)
	if err != nil {
		return nil, err
	}
	return g.dialer(ctx, network, target.PinnedAddress)
}

func (g *EgressGuard) DialTLSContext(ctx context.Context, network, address string, config *tls.Config) (net.Conn, error) {
	target, err := g.Resolve(ctx, address)
	if err != nil {
		return nil, err
	}
	conn, err := g.dialer(ctx, network, target.PinnedAddress)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config != nil {
		tlsConfig = config.Clone()
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = target.Host
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func splitNetworkAddress(address string) (string, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", fmt.Errorf("invalid egress target %q: %w", address, err)
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	port = strings.TrimSpace(port)
	if host == "" || port == "" {
		return "", "", fmt.Errorf("invalid egress target %q", address)
	}
	return strings.TrimSuffix(strings.ToLower(host), "."), port, nil
}

func buildEgressTarget(original, host, port string, ip net.IP) EgressTarget {
	pinnedIP := normalizeIP(ip)
	return EgressTarget{OriginalAddress: original, Host: host, Port: port, IP: pinnedIP, PinnedAddress: net.JoinHostPort(pinnedIP.String(), port)}
}

func parseIPLiteral(host string) net.IP {
	trimmed := strings.Trim(strings.TrimSpace(host), "[]")
	if ip := net.ParseIP(trimmed); ip != nil {
		return normalizeIP(ip)
	}
	if ip := parseSingleNumberIPv4(trimmed); ip != nil {
		return ip
	}
	if ip := parseDottedIPv4Variant(trimmed); ip != nil {
		return ip
	}
	return nil
}

func parseSingleNumberIPv4(value string) net.IP {
	lower := strings.ToLower(value)
	base := 10
	raw := lower
	if strings.HasPrefix(lower, "0x") {
		base = 16
		raw = strings.TrimPrefix(lower, "0x")
	}
	if raw == "" || strings.IndexFunc(raw, func(r rune) bool {
		if base == 16 {
			return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'))
		}
		return r < '0' || r > '9'
	}) >= 0 {
		return nil
	}
	value64, err := strconv.ParseUint(raw, base, 32)
	if err != nil {
		return nil
	}
	return uint64ToIPv4(value64)
}

func parseDottedIPv4Variant(value string) net.IP {
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return nil
	}
	parsed := make([]uint64, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil
		}
		base := 10
		raw := strings.ToLower(part)
		if strings.HasPrefix(raw, "0x") {
			base = 16
			raw = strings.TrimPrefix(raw, "0x")
		}
		if raw == "" || strings.IndexFunc(raw, func(r rune) bool {
			if base == 16 {
				return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'))
			}
			return r < '0' || r > '9'
		}) >= 0 {
			return nil
		}
		value64, err := strconv.ParseUint(raw, base, 32)
		if err != nil {
			return nil
		}
		parsed = append(parsed, value64)
	}

	var ipv4Value uint64
	switch len(parsed) {
	case 2:
		if parsed[0] > 255 || parsed[1] > 0xffffff {
			return nil
		}
		ipv4Value = parsed[0]<<24 | parsed[1]
	case 3:
		if parsed[0] > 255 || parsed[1] > 255 || parsed[2] > 0xffff {
			return nil
		}
		ipv4Value = parsed[0]<<24 | parsed[1]<<16 | parsed[2]
	case 4:
		for _, part := range parsed {
			if part > 255 {
				return nil
			}
		}
		ipv4Value = parsed[0]<<24 | parsed[1]<<16 | parsed[2]<<8 | parsed[3]
	}
	return uint64ToIPv4(ipv4Value)
}

func uint64ToIPv4(value uint64) net.IP {
	if value > maxIPv4Value {
		return nil
	}
	value32 := uint32(value) // #nosec G115 -- value is bounded to an IPv4 uint32 above.
	return uint32ToIPv4(value32)
}

func uint32ToIPv4(value uint32) net.IP {
	buf := make([]byte, net.IPv4len)
	binary.BigEndian.PutUint32(buf, value)
	return net.IP(buf)
}

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// isBlockedMetadataHostname 用全平台唯一的元数据主机名清单（egresspolicy）。
func isBlockedMetadataHostname(host string) bool {
	return egresspolicy.IsMetadataHostname(host)
}

// isBlockedEgress 判断错误是否是防跳板出站拒绝（不是 DNS 失败等）。
func isBlockedEgress(err error) bool {
	return errors.Is(err, errBlockedEgress)
}

func blockedEgressError(host string, ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("%w %s", errBlockedEgress, host)
	}
	return fmt.Errorf("%w %s resolved to %s", errBlockedEgress, host, ip.String())
}
