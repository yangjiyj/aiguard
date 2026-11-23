package handler

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"io"
	"net/http"
	"strings"
)

func GetPortalLegacyUploadIndex(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		tenant, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		var req struct {
			UserID string                                  `json:"user_id"`
			Items  []repository.PortalLegacyUploadPosition `json:"items"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&req) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(req.Items) > 200 || strings.TrimSpace(req.UserID) == "" {
			writeError(w, "invalid_request", "invalid legacy upload coordinates")
			return
		}
		for _, item := range req.Items {
			if item.ID == "" || len(item.ID) > 128 || item.SHA256 == "" || len(item.SHA256) > 128 || item.CreatedAt.IsZero() {
				writeError(w, "invalid_request", "invalid legacy upload coordinate")
				return
			}
		}
		if !portalBillingUser(r, w, deps, tenant, req.UserID) {
			return
		}
		if deps.PortalUploadEventRepo == nil {
			portalNotConfigured(w, "upload repository")
			return
		}
		data, err := deps.PortalUploadEventRepo.LegacyIndex(r.Context(), tenant, req.UserID, req.Items)
		if err != nil {
			writeErrorWithStatus(w, 503, "records_unavailable", "file history index unavailable")
			return
		}
		writeJSON(w, map[string]any{"data": data})
	}
}
