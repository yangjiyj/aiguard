package handler

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// AgentAuthorizationRoutes 是 hookd 通过网关对外端口访问 control-plane 的全部 T13/T15 机器路由。
// hookd 以 AGENT 网关 URL 去掉 /agent/v1 后拼接这些路径；control-plane 侧由
// agentAuthorizationAPI.Authenticate 按 principal bearer 鉴权，网关不做鉴权改写。
var AgentAuthorizationRoutes = []string{
	"/admin/v1/agent/authorize",
	"/admin/v1/agent/approval-requests",
	"/admin/v1/agent/approval-claims",
}

const (
	agentAuthorizationProxyBodyLimit = 64 << 10
	agentAuthorizationProxyTimeout   = 15 * time.Second
)

// AgentAuthorizationProxy 只透传上面三条 POST 路由到 control-plane。
// 失败一律返回非 2xx（502/503/413/405），hookd 对非 2xx fail-closed，不会放行 effect。
// 浏览器会话凭据（Cookie）不转发，避免机器路由被管理员会话混用。
func AgentAuthorizationProxy(controlPlaneURL string) http.Handler {
	target, err := url.Parse(strings.TrimRight(strings.TrimSpace(controlPlaneURL), "/"))
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") || (target.Path != "" && target.Path != "/") {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "control plane url not configured", http.StatusServiceUnavailable)
		})
	}
	allowed := make(map[string]struct{}, len(AgentAuthorizationRoutes))
	for _, route := range AgentAuthorizationRoutes {
		allowed[route] = struct{}{}
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	baseDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		baseDirector(r)
		r.Header.Del("Cookie")
		r.Host = target.Host
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "agent authorization upstream unavailable", http.StatusBadGateway)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := allowed[r.URL.Path]; !ok || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.ContentLength > agentAuthorizationProxyBodyLimit {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, agentAuthorizationProxyBodyLimit)
		ctx, cancel := context.WithTimeout(r.Context(), agentAuthorizationProxyTimeout)
		defer cancel()
		proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}
