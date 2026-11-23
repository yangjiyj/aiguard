// Package clientip derives a trustworthy client IP from an *http.Request.
//
// 安全边界：gateway-core / proxy-server 默认裸暴露（无 Caddy/LB），因此
// 客户端可以任意伪造 X-Forwarded-For / X-Real-IP。只有当 TCP peer
// (r.RemoteAddr) 本身命中 TRUSTED_PROXY_CIDRS 时，才采信转发头；否则
// 一律使用 RemoteAddr。
//
// 本包仅用于“只读”地采集源 IP（审计/留证增强），不参与任何拦截/enforcement
// 决策，也不向 request context 写入任何键。
package clientip

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// TrustedProxyEnv 是存放可信代理 CIDR 列表（逗号分隔）的环境变量名。
const TrustedProxyEnv = "TRUSTED_PROXY_CIDRS"

// ClientIP 从请求中解析出客户端 IP。
//
// 规则：
//   - 先取 TCP peer = host(r.RemoteAddr)。
//   - 读 env TRUSTED_PROXY_CIDRS（默认空）。
//   - 仅当 peer 命中可信 CIDR 时，才采信 X-Forwarded-For / X-Real-IP，
//     并返回“剥掉所有尾部可信代理跳之后、最右一跳”的地址（即最接近网关
//     的那个非可信代理 IP）。
//   - 否则（peer 不可信、或无转发头），返回 peer（RemoteAddr）。
//
// 空安全：r 为 nil 或无法解析时返回 ""（或原始 RemoteAddr 兜底）。
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	return clientIP(r, parseCIDRs(os.Getenv(TrustedProxyEnv)))
}

// ClientIPWithTrusted 与 ClientIP 相同，但显式传入可信 CIDR 列表，便于测试
// 及在已解析配置的场景下复用。
func ClientIPWithTrusted(r *http.Request, trusted []*net.IPNet) string {
	if r == nil {
		return ""
	}
	return clientIP(r, trusted)
}

func clientIP(r *http.Request, trusted []*net.IPNet) string {
	peer := remoteHost(r.RemoteAddr)

	// peer 不可信 → 直接用 RemoteAddr，绝不采信任何转发头。
	if !ipInAny(peer, trusted) {
		return peer
	}

	// peer 可信：把候选链构造为 [XFF..., peer]，从右往左剥掉连续的可信跳，
	// 返回第一个非可信 IP（最右一跳）。X-Real-IP 作为单值 XFF 的退化情形处理。
	chain := forwardedChain(r)
	chain = append(chain, peer)

	for i := len(chain) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(chain[i])
		if ip == "" {
			continue
		}
		if ipInAny(ip, trusted) {
			continue // 仍是可信代理，继续向左找
		}
		return ip // 最右一个非可信跳 = 真实客户端
	}

	// 链上全是可信代理（异常配置）→ 兜底回 peer。
	return peer
}

// forwardedChain 返回 X-Forwarded-For 的有序跳列表（最左 = 最初客户端）。
// 若无 XFF 但有 X-Real-IP，则以其单值作为链。
func forwardedChain(r *http.Request) []string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return []string{xr}
	}
	return nil
}

func remoteHost(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// parseCIDRs 解析逗号分隔的 CIDR/裸 IP 列表。裸 IP 视为 /32(/128)。
func parseCIDRs(raw string) []*net.IPNet {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var nets []*net.IPNet
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(item); err == nil {
			nets = append(nets, network)
			continue
		}
		// 裸 IP 容错：转成 /32 或 /128。
		if ip := net.ParseIP(item); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			_, network, err := net.ParseCIDR(item + "/" + itoa(bits))
			if err == nil {
				nets = append(nets, network)
			}
		}
	}
	return nets
}

func ipInAny(ipStr string, nets []*net.IPNet) bool {
	if ipStr == "" || len(nets) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
