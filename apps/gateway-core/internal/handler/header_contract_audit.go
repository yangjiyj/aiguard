package handler

import (
	"encoding/json"
	"net/http"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/headercompat"
)

func (h *ReverseProxyHandler) preflightHeaderContract(w http.ResponseWriter, r *http.Request) bool {
	if _, _, err := headercompat.Resolve(r.Header, "X-JJDGuard-Session-Id", "X-NewAPI-Session-Id"); err != nil {
		return h.rejectHeaderConflict(w, r, "session_id")
	}
	if _, err := agentdetect.InferFromHeaders(r.Header); err != nil {
		return h.rejectHeaderConflict(w, r, "agent_type")
	}
	return true
}

func (h *ReverseProxyHandler) rejectHeaderConflict(w http.ResponseWriter, r *http.Request, kind string) bool {
	event, err := headeraudit.NewEvent("gateway-core.reverse-proxy", kind, r.Header, r.RemoteAddr)
	if err != nil || h == nil || h.headerAudit == nil || h.headerAudit.AppendCritical(r.Context(), event) != nil {
		writeHeaderConflictError(w, http.StatusServiceUnavailable, "header_conflict_audit_unavailable", "security audit unavailable")
		return false
	}
	writeHeaderConflictError(w, http.StatusBadRequest, "header_value_conflict", "conflicting request metadata")
	return false
}

func writeHeaderConflictError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]map[string]string{"error": {"code": code, "message": message}})
}
