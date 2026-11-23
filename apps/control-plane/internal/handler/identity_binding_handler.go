package handler

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
)

// SetUserDepartmentAutomatic restores automatic department assignment for a user.
func SetUserDepartmentAutomatic(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor := auth.GetUser(r.Context())
		if actor == nil {
			writeUnauthorized(w, "no user")
			return
		}
		userID := strings.TrimSpace(chi.URLParam(r, "id"))
		if userID == "" {
			writeIdentityBindingMutationError(w, identitybinding.ErrNotFound)
			return
		}
		if deps == nil || deps.IdentityBindingService == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "department assignment service is not configured")
			return
		}
		if err := deps.IdentityBindingService.SetAutomatic(
			r.Context(), actor.TenantID, userID, actor.ID,
		); err != nil {
			writeIdentityBindingMutationError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
