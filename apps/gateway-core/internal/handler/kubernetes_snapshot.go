package handler

import (
	"io"
	"net/http"
	"strings"
)

const kubernetesSnapshotGatewayBodyLimit int64 = 32 << 20

func (g *AgentEndpointGateway) kubernetesSnapshot(w http.ResponseWriter, r *http.Request, token string, endpoint map[string]any, internalPath string) {
	if endpoint["agent_product"] != "aiprobe-kubernetes" {
		jsonError(w, http.StatusForbidden, "AGENT_PRODUCT_NOT_ALLOWED", "registered Kubernetes collector required")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		jsonError(w, http.StatusMethodNotAllowed, "AGENT_METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		jsonError(w, http.StatusUnsupportedMediaType, "AGENT_CONTENT_ENCODING_NOT_ALLOWED", "content encoding not allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, kubernetesSnapshotGatewayBodyLimit+1))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "AGENT_INVALID_REQUEST", "invalid request")
		return
	}
	if int64(len(body)) > kubernetesSnapshotGatewayBodyLimit {
		jsonError(w, http.StatusRequestEntityTooLarge, "AGENT_REQUEST_TOO_LARGE", "request too large")
		return
	}
	g.proxyBody(w, r, internalPath, token, body)
}
