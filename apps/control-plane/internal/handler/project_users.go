package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

// ListAppUsers returns users bound to a project
func ListAppUsers(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		projectID := chi.URLParam(r, "id")

		// Verify project exists and belongs to tenant
		project, err := deps.ProjectRepo.GetByID(r.Context(), user.TenantID, projectID)
		if err != nil {
			writeError(w, "internal_error", "failed to get project")
			return
		}
		if project == nil {
			writeError(w, "not_found", "project not found")
			return
		}
		// dept_manager 等非管理员：只能看本部门项目的成员（越权读兄弟项目 403）。
		if !callerMayAccessProject(r, deps, projectID) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		// Get project users with role information
		projectUsers, err := deps.ProjectUserRepo.GetUsersByProjectWithRole(r.Context(), projectID)
		if err != nil {
			writeError(w, "internal_error", "failed to list project users")
			return
		}

		// Fetch user details
		data := make([]types.ProjectUserInfo, 0, len(projectUsers))
		for _, pu := range projectUsers {
			u, err := deps.UserRepo.GetByID(r.Context(), pu.UserID)
			if err != nil || u == nil {
				continue
			}
			data = append(data, types.ProjectUserInfo{
				UserID:    u.ID,
				Username:  u.Username,
				Email:     u.Email,
				Role:      pu.Role, // Use role from project_users table
				CreatedAt: pu.CreatedAt.Format("2006-01-02T15:04:05Z"),
			})
		}

		resp := types.ProjectUserListResponse{Data: data, Total: len(data)}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// BindAppUser binds a user to a project
func BindAppUser(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		projectID := chi.URLParam(r, "id")
		var req types.BindUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if req.UserID == "" {
			writeError(w, "invalid_request", "user_id is required")
			return
		}

		// Default role to developer if not specified
		role := req.Role
		if role == "" {
			role = "developer"
		}
		// Validate role
		if role != "owner" && role != "developer" && role != "viewer" {
			writeError(w, "invalid_request", "role must be owner, developer, or viewer")
			return
		}

		// Verify project exists
		project, err := deps.ProjectRepo.GetByID(r.Context(), user.TenantID, projectID)
		if err != nil {
			writeError(w, "internal_error", "failed to get project")
			return
		}
		if project == nil {
			writeError(w, "not_found", "project not found")
			return
		}

		// Verify user exists
		targetUser, err := deps.UserRepo.GetByID(r.Context(), req.UserID)
		if err != nil {
			writeError(w, "internal_error", "failed to get user")
			return
		}
		if targetUser == nil {
			writeError(w, "not_found", "user not found")
			return
		}

		if err := deps.ProjectUserRepo.BindUserWithRole(r.Context(), projectID, req.UserID, role); err != nil {
			writeError(w, "internal_error", "failed to bind user")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "user bound to project successfully"})
	}
}

// UnbindAppUser unbinds a user from a project
func UnbindAppUser(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		projectID := chi.URLParam(r, "id")
		userID := chi.URLParam(r, "userId")

		if err := deps.ProjectUserRepo.UnbindUser(r.Context(), projectID, userID); err != nil {
			writeError(w, "internal_error", "failed to unbind user")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// UpdateAppModelConfig updates model whitelist and quota limits for a project
func UpdateAppModelConfig(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		projectID := chi.URLParam(r, "id")
		var req types.UpdateModelConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		// Verify project exists
		project, err := deps.ProjectRepo.GetByID(r.Context(), user.TenantID, projectID)
		if err != nil {
			writeError(w, "internal_error", "failed to get project")
			return
		}
		if project == nil {
			writeError(w, "not_found", "project not found")
			return
		}

		// Update model config
		if err := deps.ProjectRepo.UpdateModelConfig(r.Context(), projectID, req.ModelWhitelist, req.QuotaLimits); err != nil {
			writeError(w, "internal_error", "failed to update model config")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "model config updated successfully"})
	}
}
