package handler

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const maxModelBatchDeleteBodyBytes int64 = 16 << 10
const maxModelBatchDeleteItems = 100

type modelBatchDeleteRequest struct {
	ModelIDs []string `json:"model_ids"`
}

func BatchDeleteModels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		if deps == nil || deps.PermissionChecker == nil {
			writeErrorWithStatus(w, http.StatusForbidden, "permission_check_failed", "permission check failed")
			return
		}
		allowed, err := deps.PermissionChecker.HasPermission(
			r.Context(),
			user.ID,
			user.TenantID,
			"tenant",
			user.TenantID,
			"models",
			"delete",
		)
		if err != nil {
			writeErrorWithStatus(w, http.StatusForbidden, "permission_check_failed", "permission check failed")
			return
		}
		if !allowed {
			writeErrorWithStatus(w, http.StatusForbidden, "permission_denied", "permission denied")
			return
		}

		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/json")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxModelBatchDeleteBodyBytes)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		var req modelBatchDeleteRequest
		if err := decoder.Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}
		var trailing json.RawMessage
		if err := decoder.Decode(&trailing); err != io.EOF {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "request body must contain one JSON object")
			return
		}

		if len(req.ModelIDs) == 0 || len(req.ModelIDs) > maxModelBatchDeleteItems {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "model_ids must contain between 1 and 100 items")
			return
		}
		seen := make(map[string]struct{}, len(req.ModelIDs))
		for _, id := range req.ModelIDs {
			if strings.TrimSpace(id) == "" {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "model_ids must not contain blank IDs")
				return
			}
			if _, duplicate := seen[id]; duplicate {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "model_ids must not contain duplicate IDs")
				return
			}
			seen[id] = struct{}{}
		}

		result, err := deps.ModelRepo.DeleteBatch(r.Context(), user.TenantID, req.ModelIDs)
		if errors.Is(err, repository.ErrModelsUnavailable) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "model not found or not owned")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to delete models")
			return
		}

		logAudit(r, deps, "batch_delete_models", map[string]interface{}{
			"model_ids": req.ModelIDs,
			"requested": result.Requested,
			"deleted":   result.Deleted,
			"disabled":  result.Disabled,
			"failed":    result.Failed,
		}, "model_batch", "")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(result)
	}
}
