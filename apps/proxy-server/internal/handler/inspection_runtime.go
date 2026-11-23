package handler

import (
	"crypto/hmac"
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/headercompat"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"net/http"
	"strings"
)

const InspectionRuntimeStatusPath = "/internal/v1/inspection-scope/status"

type InspectionRuntimeStatusReader interface {
	RuntimeStatus() inspectionscope.RuntimeStatus
}

// InspectionRuntimeStatusHandler serves origin-form internal status requests.
// Absolute-form requests still belong to the forward proxy, even at this path.
func InspectionRuntimeStatusHandler(reader InspectionRuntimeStatusReader, secret string, forward http.HandlerFunc) http.HandlerFunc {
	secret = strings.TrimSpace(secret)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.IsAbs() {
			if forward != nil {
				forward(w, r)
			} else {
				http.NotFound(w, r)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		if secret == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error_code": "internal_auth_unavailable"})
			return
		}
		token, _, err := headercompat.Resolve(r.Header, headeraudit.InternalTokenHeader, "")
		if err != nil || !hmac.Equal([]byte(token), []byte(secret)) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error_code": "unauthorized"})
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		status := inspectionscope.RuntimeStatus{Component: "proxy-server", ConfigComponent: "gateway-core", NodeID: inspectionscope.ProxyRuntimeNodeID(), Status: "degraded", ErrorCode: "config_unavailable"}
		if reader != nil {
			status = reader.RuntimeStatus()
		}
		if status.Status != "applied" || !status.ConfigLoaded || !status.Fresh || status.ErrorCode != "" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(status)
	}
}
