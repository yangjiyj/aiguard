// Package httpmw 提供 HTTP 中间件。
package httpmw

import (
	"net"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/clientip"
)

// TrustedRealIP 是 chi middleware.RealIP 的安全替代品。
//
// 背景：gateway-core 默认裸暴露（无 Caddy/LB），chi 的 RealIP 会无条件
// 用 X-Forwarded-For / X-Real-IP 改写 r.RemoteAddr，导致任意客户端可伪造
// 源 IP。本中间件仅当 TCP peer 命中 TRUSTED_PROXY_CIDRS 时才采信转发头并
// 改写 RemoteAddr；默认（env 为空）下完全不改写，RemoteAddr 即真实对端。
//
// 为最小化对下游的影响，仅当解析出的客户端 IP 与原 RemoteAddr 的 host
// 不同（即确实经由可信代理还原出了上游 IP）时才改写；否则保持原值不动，
// 不丢弃端口信息。
//
// 注意：这只影响 RemoteAddr 的“可读性”，不参与任何拦截/enforcement 决策。
func TrustedRealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		derived := clientip.ClientIP(r)
		if derived != "" && derived != remoteHost(r.RemoteAddr) {
			r.RemoteAddr = derived
		}
		next.ServeHTTP(w, r)
	})
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
