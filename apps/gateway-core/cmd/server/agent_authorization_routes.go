package main

import (
	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/handler"
)

// registerAgentAuthorizationRoutes 把 hookd 的 T13 authorize 与 T15 approval request/claim
// 机器路由透传到 control-plane；只在 AgentEndpointEnabled 时注册。
func registerAgentAuthorizationRoutes(router chi.Router, controlPlaneURL string) {
	proxy := handler.AgentAuthorizationProxy(controlPlaneURL)
	for _, route := range handler.AgentAuthorizationRoutes {
		router.Handle(route, proxy)
	}
}
