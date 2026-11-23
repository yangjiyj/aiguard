package handler

import "github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"

// SetRetentionArtifactStore is wired during service startup. Replacing it later
// is safe for the next audit operation and does not expose the store to callers.
func (h *ReverseProxyHandler) SetRetentionArtifactStore(store retentionstore.Store) {
	if h == nil {
		return
	}
	if recorder, ok := h.auditRecorder.(*reverseProxyDBAuditRecorder); ok {
		recorder.artifactStore = store
	}
}

func (h *ForwardProxyHandler) SetRetentionArtifactStore(store retentionstore.Store) {
	if h == nil || h.reverseProxy == nil {
		return
	}
	h.reverseProxy.SetRetentionArtifactStore(store)
}
