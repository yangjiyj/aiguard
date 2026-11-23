package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/handler"
)

func registerMCPRoutes(
	router chi.Router,
	authMiddleware func(http.Handler) http.Handler,
	proxy *handler.MCPProxyHandler,
) {
	router.Route("/mcp", func(r chi.Router) {
		r.Use(proxy.OriginMiddleware)
		r.Options("/{serverID}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		r.Group(func(protected chi.Router) {
			protected.Use(authMiddleware)
			proxy.Register(protected)
		})
	})
}
