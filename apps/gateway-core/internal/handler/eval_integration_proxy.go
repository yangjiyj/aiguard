package handler

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// EvalIntegrationProxy 把 /admin/v1/eval-integration/* 透传到 control-plane。
// 目的：让评估平台(LSE)只用网关对外端口(gateway-core:8080)即可访问 token 保护的集成 API，
// 无需暴露 control-plane:8081（其仅绑 127.0.0.1）。
// 本透传不做任何鉴权改写——eval-integration 的共享密钥校验仍在 control-plane 侧(EvalIntegrationAPIMiddleware)完成；
// 也不经过 gateway-core 的 /v1 鉴权与 enforcement 链路（注册在 /v1 组之外）。
func EvalIntegrationProxy(controlPlaneURL string) http.Handler {
	target, err := url.Parse(strings.TrimRight(strings.TrimSpace(controlPlaneURL), "/"))
	if err != nil || target.Host == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "control plane url not configured", http.StatusServiceUnavailable)
		})
	}
	// target 无 path（如 http://control-plane:8081），SingleHost Director 会原样保留请求 path，
	// 故 /admin/v1/eval-integration/health → control-plane:8081/admin/v1/eval-integration/health，鉴权头一并透传。
	return httputil.NewSingleHostReverseProxy(target)
}
