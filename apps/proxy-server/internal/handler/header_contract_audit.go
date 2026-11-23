package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
)

func (h *ProxyHandler) headerContractDecision(r *http.Request) (int, string, string, bool) {
	if _, err := agentdetect.InferFromHeaders(r.Header); err == nil {
		return 0, "", "", false
	}
	event, err := headeraudit.NewEvent("proxy-server.mitm", "agent_type", r.Header, r.RemoteAddr)
	if err != nil || h == nil || h.headerAudit == nil || h.headerAudit.AppendCritical(r.Context(), event) != nil {
		return http.StatusServiceUnavailable, "header_conflict_audit_unavailable", "security audit unavailable", true
	}
	return http.StatusBadRequest, "header_value_conflict", "conflicting request metadata", true
}

func (h *ProxyHandler) preflightHeaderContract(w http.ResponseWriter, r *http.Request) bool {
	status, code, message, conflict := h.headerContractDecision(r)
	if !conflict {
		return true
	}
	writeProxyHeaderContractError(w, status, code, message)
	return false
}

func writeProxyHeaderContractError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]map[string]string{"error": {"code": code, "message": message}})
}

func writeMITMHeaderContractError(conn net.Conn, status int, code, message string) error {
	body, _ := json.Marshal(map[string]map[string]string{"error": {"code": code, "message": message}})
	resp := &http.Response{StatusCode: status, Status: http.StatusText(status), ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(append(body, '\n'))), ContentLength: int64(len(body) + 1)}
	return resp.Write(conn)
}
