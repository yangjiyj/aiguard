package handler

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
)

// 双层代理：客户 PC 指向我们的正向代理，我们再经客户的出网代理上网。
//
// 默认关闭。为什么必须显式配置而不能直接读 HTTPS_PROXY：EgressGuard 会把
// 内网地址当 SSRF 目标挡掉，而出网代理几乎总在内网。如果为了让它拨通就
// 普遍放开内网，等于把 SSRF 防线拆了——正向代理是攻击面最大的组件，客户
// 的任何一台 PC 都能让它去拨内网任意地址。
//
// 所以做法是：只对「显式配置的那一个 host:port」开一个精确豁免，其余内网
// 地址照旧挡住。豁免精确到端口，而且云元数据地址永不豁免（那是凭据窃取的
// 经典路径，即使运维把它写进配置也不能放）。

// ParseUpstreamProxy 解析上层出网代理配置。空值表示不启用（不是错误——
// 否则默认部署直接起不来）。必须带端口：没有端口就无法做精确豁免，
// 只能退化成放开整个 IP，那正是我们要避免的。
func ParseUpstreamProxy(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if strings.ContainsAny(raw, "\x00\r\n") {
		return nil, fmt.Errorf("上层出网代理地址含非法字符")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("上层出网代理地址无法解析：%w", err)
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("上层出网代理只支持 http/https，得到 %q", parsed.Scheme)
	}
	host, port, splitErr := net.SplitHostPort(parsed.Host)
	if splitErr != nil {
		return nil, fmt.Errorf("上层出网代理必须写成 host:port：%w", splitErr)
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || strings.TrimSpace(port) == "" {
		return nil, fmt.Errorf("上层出网代理缺少主机或端口")
	}
	return parsed, nil
}

// SetUpstreamProxy 启用上层出网代理。传 nil 表示回到默认（不启用）。
func (g *EgressGuard) SetUpstreamProxy(proxy *url.URL) {
	if g == nil {
		return
	}
	g.upstreamProxy = proxy
}

// upstreamProxyExemptAddress 返回「这个地址是否就是配置的那一跳」。
// 只比对精确的 host:port，不做网段判断。
func (g *EgressGuard) upstreamProxyExemptAddress(host, port string) bool {
	if g == nil || g.upstreamProxy == nil {
		return false
	}
	proxyHost, proxyPort, err := net.SplitHostPort(g.upstreamProxy.Host)
	if err != nil {
		return false
	}
	proxyHost = strings.Trim(strings.TrimSpace(proxyHost), "[]")
	if !strings.EqualFold(proxyHost, host) || proxyPort != port {
		return false
	}
	// 云元数据地址永不豁免：即使被写进配置也不放，避免把凭据窃取路径开出来。
	if isBlockedMetadataHostname(host) {
		return false
	}
	if ip := parseIPLiteral(host); ip != nil && isMetadataServiceIP(ip) {
		return false
	}
	return true
}

// isMetadataServiceIP 覆盖各云的元数据端点（egresspolicy 的元数据地址）。link-local 整段拦掉，
// 因为 169.254.0.0/16 上不该有客户的出网代理。
func isMetadataServiceIP(ip net.IP) bool {
	normalized := normalizeIP(ip)
	if normalized == nil {
		return true
	}
	if addr, ok := netip.AddrFromSlice(normalized); ok && egresspolicy.IsMetadataAddr(addr) {
		return true
	}
	return normalized.IsLinkLocalUnicast() || normalized.IsLinkLocalMulticast()
}

// DialTunnelContext 给「不经 http.Transport 的裸 TCP 出网路径」用。
// 未配置上层代理时行为与 DialContext 完全一致（直拨目标）；配置了就先连
// 代理那一跳，再对真实目标发 CONNECT，把返回的连接交给调用方继续做 TLS。
func (g *EgressGuard) DialTunnelContext(ctx context.Context, network, address string) (net.Conn, error) {
	if g == nil || g.upstreamProxy == nil {
		return g.DialContext(ctx, network, address)
	}
	// CONNECT 请求行由 address 拼出来，所以控制字符必须先挡掉，
	// 否则可以往请求里注入额外的头（请求走私）。
	if strings.ContainsAny(address, "\r\n\x00 \t") {
		return nil, fmt.Errorf("非法隧道目标 %q", address)
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, fmt.Errorf("隧道目标必须是 host:port：%w", err)
	}

	hop, err := g.Resolve(ctx, g.upstreamProxy.Host)
	if err != nil {
		return nil, err
	}
	conn, err := g.dialer(ctx, network, hop.PinnedAddress)
	if err != nil {
		return nil, fmt.Errorf("无法连接上层出网代理 %s：%w", g.upstreamProxy.Host, err)
	}

	request := "CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("向上层出网代理发送 CONNECT 失败：%w", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取上层出网代理响应失败：%w", err)
	}
	fields := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(fields) < 2 || fields[1] != "200" {
		conn.Close()
		// 带上代理原话：现场最需要知道的就是「代理为什么拒了」。
		return nil, fmt.Errorf("上层出网代理拒绝建立隧道：%s", strings.TrimSpace(statusLine))
	}
	// 吃掉响应头，直到空行。
	for {
		line, headerErr := reader.ReadString('\n')
		if headerErr != nil {
			conn.Close()
			return nil, fmt.Errorf("读取上层出网代理响应头失败：%w", headerErr)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	// reader 里可能已经预读了隧道数据，必须把它接回去，否则丢字节。
	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: reader}, nil
	}
	return conn, nil
}

// bufferedConn 把 bufio 预读的字节还给调用方，避免建隧道时丢数据。
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// DialTLSThroughTunnel 供「手拨 TLS」的兜底路径使用：未配置上层代理时
// 逐字节等价于 DialTLSContext；配置了就先建 CONNECT 隧道再在隧道里握手。
func (g *EgressGuard) DialTLSThroughTunnel(ctx context.Context, network, address string, config *tls.Config) (net.Conn, error) {
	if g == nil || g.upstreamProxy == nil {
		return g.DialTLSContext(ctx, network, address, config)
	}
	conn, err := g.DialTunnelContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config != nil {
		tlsConfig = config.Clone()
	}
	if tlsConfig.ServerName == "" {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			conn.Close()
			return nil, splitErr
		}
		tlsConfig.ServerName = strings.Trim(host, "[]")
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// SetUpstreamEgressProxy 在 ProxyHandler 层启用上层出网代理。
// 必须同时重建 transport：只改 guard 的话，构造函数里已经缓存的
// transport 仍带旧的 Proxy=nil，HTTP 路径会静默直连出网。
func (h *ProxyHandler) SetUpstreamEgressProxy(proxy *url.URL) {
	if h == nil {
		return
	}
	guard := h.currentEgressGuard()
	guard.SetUpstreamProxy(proxy)
	h.egressGuard = guard
	h.transport = guard.HTTPTransport()
	// keep-alive 版 transport 是 sync.Once 懒初始化的，此处尚未初始化，
	// 首次使用时会带上新配置；这里不重置 Once，避免并发下换掉正在用的连接池。
}
