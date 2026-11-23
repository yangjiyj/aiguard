package handler

import (
	"encoding/json"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strings"
)

func ListPortalCustomerKeys(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		tenant, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		user := strings.TrimSpace(r.URL.Query().Get("user_id"))
		if user == "" {
			writeError(w, "user_required", "user_id is required")
			return
		}
		if !portalBillingUser(r, w, deps, tenant, user) {
			return
		}
		if deps.KeyRepo == nil {
			portalNotConfigured(w, "key repository")
			return
		}
		keys, err := deps.KeyRepo.ListByUser(r.Context(), tenant, user)
		if err != nil {
			writeError(w, "internal_error", "failed to list personal keys")
			return
		}
		data := []map[string]any{}
		for _, key := range keys {
			data = append(data, map[string]any{"id": key.ID, "user_id": key.UserID, "tenant_id": key.TenantID, "name": key.Name, "prefix": key.KeyPrefix, "project_id": key.ProjectID, "scopes": key.Scopes, "status": key.Status, "created_at": key.CreatedAt, "expires_at": key.ExpiresAt, "last_used_at": key.LastUsedAt, "employee_key": key.IsEmployee, "model_allowlist": key.ModelAllowlist})
		}
		writeJSON(w, map[string]any{"data": data})
	}
}

func UpdatePortalCustomerKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		tenant, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		user := strings.TrimSpace(r.URL.Query().Get("user_id"))
		id := strings.TrimSpace(chi.URLParam(r, "id"))
		if user == "" || id == "" {
			writeErrorWithStatus(w, 400, "invalid_request", "user and key are required")
			return
		}
		if !portalBillingUser(r, w, deps, tenant, user) {
			return
		}
		if deps.KeyRepo == nil {
			portalNotConfigured(w, "key repository")
			return
		}
		var input repository.OwnedKeyUpdate
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			writeErrorWithStatus(w, 400, "invalid_request", "invalid key update")
			return
		}
		if input.Name != nil {
			name, err := normalizeKeyName(*input.Name)
			if err != nil {
				writeErrorWithStatus(w, 400, "invalid_name", "invalid key name")
				return
			}
			input.Name = &name
		}
		err := deps.KeyRepo.UpdateOwned(r.Context(), tenant, id, user, input)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			writeErrorWithStatus(w, 404, "not_found", "key not found")
			return
		case errors.Is(err, modelaccess.ErrKeyModelUnauthorized):
			writeErrorWithStatus(w, 403, "key_model_not_authorized", "key models must be within current user authorization")
			return
		case errors.Is(err, modelaccess.ErrInvalidPolicy):
			writeErrorWithStatus(w, 400, "invalid_request", "invalid model list or status")
			return
		case errors.Is(err, repository.ErrOwnedKeyLimitReached):
			writeErrorWithStatus(w, 409, "key_limit_reached", "user already has the maximum number of active keys")
			return
		case errors.Is(err, repository.ErrOwnedKeyRevoked):
			writeErrorWithStatus(w, 409, "key_revoked", "revoked key cannot be edited")
			return
		case err != nil:
			writeErrorWithStatus(w, 503, "control_plane_error", "key update unavailable")
			return
		}
		writeJSON(w, map[string]any{"data": map[string]string{"id": id}})
	}
}

func ResetPortalCustomerKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Pragma", "no-cache")
		tenant, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		user := strings.TrimSpace(r.URL.Query().Get("user_id"))
		id := strings.TrimSpace(chi.URLParam(r, "id"))
		if user == "" || id == "" {
			writeErrorWithStatus(w, 400, "invalid_request", "user and key are required")
			return
		}
		if !portalBillingUser(r, w, deps, tenant, user) {
			return
		}
		if deps.KeyRepo == nil {
			portalNotConfigured(w, "key repository")
			return
		}
		key, raw, err := deps.KeyRepo.RotateOwned(r.Context(), tenant, id, user)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			writeErrorWithStatus(w, 404, "not_found", "key not found")
			return
		case errors.Is(err, repository.ErrOwnedKeyRevoked):
			writeErrorWithStatus(w, 409, "key_revoked", "key is already revoked")
			return
		case errors.Is(err, repository.ErrOwnedKeyEncryptionUnavailable):
			writeErrorWithStatus(w, 503, "key_encryption_unavailable", "key encryption temporarily unavailable")
			return
		case err != nil:
			writeErrorWithStatus(w, 503, "control_plane_error", "key reset unavailable")
			return
		}
		writeJSON(w, map[string]any{"full_key": raw, "data": map[string]any{"id": key.ID, "user_id": key.UserID, "tenant_id": key.TenantID, "name": key.Name, "prefix": key.KeyPrefix, "project_id": key.ProjectID, "scopes": key.Scopes, "status": key.Status, "created_at": key.CreatedAt, "expires_at": key.ExpiresAt, "model_allowlist": key.ModelAllowlist}})
	}
}

// DeletePortalCustomerKey only deletes the key belonging to the trusted portal user.
func DeletePortalCustomerKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		tenant, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		user := strings.TrimSpace(r.URL.Query().Get("user_id"))
		id := strings.TrimSpace(chi.URLParam(r, "id"))
		if user == "" || id == "" {
			writeErrorWithStatus(w, 400, "invalid_request", "user and key are required")
			return
		}
		if !portalBillingUser(r, w, deps, tenant, user) {
			return
		}
		if deps.KeyRepo == nil {
			portalNotConfigured(w, "key repository")
			return
		}
		r = withOperationAudit(r, deps)
		err := deps.KeyRepo.DeleteOwned(r.Context(), tenant, id, user)
		if errors.Is(err, pgx.ErrNoRows) {
			writeErrorWithStatus(w, 404, "not_found", "key not found")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, 503, "control_plane_error", "key deletion unavailable")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
