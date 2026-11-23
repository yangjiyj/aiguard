package handler

import (
	"net/http"
)

func GetPortalClientConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := portalTenantID(w, r); !ok {
			return
		}
		value, mode, endpoints, err := portalGatewayAccessSettings(r.Context(), deps, r.Header.Get("X-JJDGuard-Gateway-URL"))
		if err != nil {
			writeErrorWithStatus(w, 503, "client_config_unavailable", "gateway coordinate unavailable")
			return
		}
		w.Header().Set("Cache-Control", "private, no-store")
		writeJSON(w, map[string]any{"api_url": value, "gateway_public_url_mode": mode, "gateway_public_endpoints": endpoints})
	}
}
