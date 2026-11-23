package handler

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
)

// CreateHeaderContractConflictIngest accepts only the authenticated internal envelope.
func CreateHeaderContractConflictIngest(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		var event headeraudit.Event
		if err := decoder.Decode(&event); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_header_conflict_event", "invalid audit event")
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF || event.Validate() != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_header_conflict_event", "invalid audit event")
			return
		}
		if err := persistHeaderConflict(r.Context(), deps, event); err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "header_conflict_audit_unavailable", "security audit unavailable")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
