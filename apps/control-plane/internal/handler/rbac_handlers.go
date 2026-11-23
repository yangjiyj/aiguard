package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

// GrantRequest is the payload for POST /admin/v1/users/{id}/grants
type GrantRequest struct {
	ScopeType string `json:"scope_type"`
	ScopeID   string `json:"scope_id"`
	Role      string `json:"role"`
}

// ToggleStatusRequest is the payload for PATCH /admin/v1/users/{id}/status
type ToggleStatusRequest struct {
	Status string `json:"status"` // active | disabled
}

// GrantResponse is the JSON response for a permission grant
type GrantResponse struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ScopeType string    `json:"scope_type"`
	ScopeID   string    `json:"scope_id"`
	Role      string    `json:"role"`
	GrantedBy string    `json:"granted_by,omitempty"`
	GrantedAt time.Time `json:"granted_at"`
}

// ToggleUserStatus - PATCH /admin/v1/users/{id}/status
func ToggleUserStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentUser := auth.GetUser(r.Context())
		if currentUser == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if !roles.IsSystemAdmin(currentUser.Role) && currentUser.Role != roles.TenantAdmin {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		userID := chi.URLParam(r, "id")
		var req ToggleStatusRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		if req.Status != "active" && req.Status != "disabled" {
			writeError(w, "invalid_request", "status must be 'active' or 'disabled'")
			return
		}
		if userID == currentUser.ID && req.Status == "disabled" {
			writeError(w, "invalid_request", "cannot disable yourself")
			return
		}

		existing, err := userStore(deps).GetByID(r.Context(), userID)
		if err != nil {
			writeError(w, "internal_error", "failed to get user")
			return
		}
		if existing == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		if existing.TenantID == repository.SystemTenantID ||
			(currentUser.Role == roles.TenantAdmin && existing.TenantID != currentUser.TenantID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}

		if !applyManagedUserStatus(w, r, deps, currentUser, existing, req.Status) {
			return
		}

		writeJSON(w, map[string]string{"status": req.Status})
	}
}

// ListUserGrants - GET /admin/v1/users/{id}/grants
func ListUserGrants(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentUser := auth.GetUser(r.Context())
		if currentUser == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		userID := chi.URLParam(r, "id")
		// dept_manager 等非管理员：只能看与自己同部门的用户（越权看别人一律 404）。
		if !callerSharesTeamWithUser(r, deps, userID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		grants, err := deps.PermissionGrantRepo.ListByUser(r.Context(), userID, currentUser.TenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to list grants")
			return
		}
		if grants == nil {
			grants = []*repository.PermissionGrant{}
		}

		result := make([]GrantResponse, 0, len(grants))
		for _, g := range grants {
			result = append(result, GrantResponse{
				ID:        g.ID,
				UserID:    g.UserID,
				ScopeType: g.ScopeType,
				ScopeID:   g.ScopeID,
				Role:      g.Role,
				GrantedBy: g.GrantedBy,
				GrantedAt: g.GrantedAt,
			})
		}

		writeJSON(w, map[string]interface{}{"data": result, "total": len(result)})
	}
}

// CreateUserGrant - POST /admin/v1/users/{id}/grants
func CreateUserGrant(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentUser := auth.GetUser(r.Context())
		if currentUser == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		userID := chi.URLParam(r, "id")
		var req GrantRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}

		if req.ScopeType == "" || req.ScopeID == "" || req.Role == "" {
			writeError(w, "invalid_request", "scope_type, scope_id, and role are required")
			return
		}
		// W4: only the system administrator manages grants, and officer roles are
		// assigned through users.role (not scoped grants) so they stay auditable.
		if !canManageGrants(currentUser) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		if !isGrantableScopedRole(req.Role) {
			writeError(w, "invalid_role", "role cannot be granted through scoped grants")
			return
		}

		// Verify target user exists and belongs to this tenant
		targetUser, err := deps.UserRepo.GetByID(r.Context(), userID)
		if err != nil || targetUser == nil ||
			(currentUser.TenantID != repository.SystemTenantID && targetUser.TenantID != currentUser.TenantID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}

		grant := &repository.PermissionGrant{
			ID:        fmt.Sprintf("grant_%s", uuid.New().String()[:16]),
			TenantID:  currentUser.TenantID,
			UserID:    userID,
			ScopeType: req.ScopeType,
			ScopeID:   req.ScopeID,
			Role:      req.Role,
			GrantedBy: currentUser.ID,
		}

		if err := deps.PermissionGrantRepo.Create(r.Context(), grant); err != nil {
			writeError(w, "internal_error", "failed to create grant")
			return
		}

		// Invalidate permission cache for this user
		if deps.PermissionChecker != nil {
			deps.PermissionChecker.InvalidateUserCache(userID)
		}

		logAudit(r, deps, "permission.grant", map[string]interface{}{
			"target_user_id": userID,
			"scope_type":     req.ScopeType,
			"scope_id":       req.ScopeID,
			"role":           req.Role,
		}, "permission_grant", grant.ID)

		w.WriteHeader(http.StatusCreated)
		writeJSON(w, GrantResponse{
			ID:        grant.ID,
			UserID:    grant.UserID,
			ScopeType: grant.ScopeType,
			ScopeID:   grant.ScopeID,
			Role:      grant.Role,
			GrantedBy: grant.GrantedBy,
		})
	}
}

// DeleteUserGrant - DELETE /admin/v1/users/{id}/grants/{grant_id}
func DeleteUserGrant(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentUser := auth.GetUser(r.Context())
		if currentUser == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		userID := chi.URLParam(r, "id")
		grantID := chi.URLParam(r, "grant_id")
		if !canManageGrants(currentUser) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}

		if err := deps.PermissionGrantRepo.Delete(r.Context(), grantID, currentUser.TenantID); err != nil {
			writeError(w, "internal_error", "failed to delete grant")
			return
		}

		// Invalidate permission cache
		if deps.PermissionChecker != nil {
			deps.PermissionChecker.InvalidateUserCache(userID)
		}

		logAudit(r, deps, "permission.revoke", map[string]interface{}{
			"target_user_id": userID,
			"grant_id":       grantID,
		}, "permission_grant", grantID)

		w.WriteHeader(http.StatusNoContent)
	}
}

// GetUserLoginHistory - GET /admin/v1/users/{id}/login-history
func GetUserLoginHistory(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentUser := auth.GetUser(r.Context())
		if currentUser == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		userID := chi.URLParam(r, "id")
		if !callerSharesTeamWithUser(r, deps, userID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		limitStr := r.URL.Query().Get("limit")
		limit := 20
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}

		entries, err := deps.LoginHistoryRepo.ListByUser(r.Context(), userID, limit)
		if err != nil {
			writeError(w, "internal_error", "failed to get login history")
			return
		}
		if entries == nil {
			entries = []*repository.LoginHistoryEntry{}
		}

		type entry struct {
			ID            int64     `json:"id"`
			UserID        string    `json:"user_id"`
			LoggedAt      time.Time `json:"logged_at"`
			IP            string    `json:"ip"`
			Success       bool      `json:"success"`
			FailureReason string    `json:"failure_reason,omitempty"`
		}
		result := make([]entry, 0, len(entries))
		for _, e := range entries {
			result = append(result, entry{
				ID:            e.ID,
				UserID:        e.UserID,
				LoggedAt:      e.LoggedAt,
				IP:            e.IP,
				Success:       e.Success,
				FailureReason: e.FailureReason,
			})
		}

		writeJSON(w, map[string]interface{}{"data": result, "total": len(result)})
	}
}

// GetUserDetail - GET /admin/v1/users/{id}/detail - aggregated user detail
func GetUserDetail(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentUser := auth.GetUser(r.Context())
		if currentUser == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		userID := chi.URLParam(r, "id")
		if !callerSharesTeamWithUser(r, deps, userID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		user, err := deps.UserRepo.GetByID(r.Context(), userID)
		if err != nil || user == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}

		// Grants
		grants, _ := deps.PermissionGrantRepo.ListByUser(r.Context(), userID, currentUser.TenantID)
		if grants == nil {
			grants = []*repository.PermissionGrant{}
		}

		// Team memberships（带部门中文名，避免详情页只显示 team_id/UUID）
		teamRows, _ := deps.TeamMemberRepo.ListByUserWithTeamName(r.Context(), userID)
		teams := make([]map[string]interface{}, 0, len(teamRows))
		for _, tm := range teamRows {
			// 部门已删除时 TeamName 为空，回退用 team_id，保证前端总有可读文案
			displayName := tm.TeamName
			if displayName == "" {
				displayName = tm.TeamID
			}
			teams = append(teams, map[string]interface{}{
				"team_id":    tm.TeamID,
				"team_name":  displayName,
				"name":       displayName,
				"role":       tm.Role,
				"created_at": tm.CreatedAt,
			})
		}

		// Project memberships
		projects, _ := deps.ProjectUserRepo.GetProjectsByUser(r.Context(), userID)
		if projects == nil {
			projects = []string{}
		}

		// Login history (last 5)
		loginHistory, _ := deps.LoginHistoryRepo.ListByUser(r.Context(), userID, 5)
		if loginHistory == nil {
			loginHistory = []*repository.LoginHistoryEntry{}
		}

		writeJSON(w, map[string]interface{}{
			"user": map[string]interface{}{
				"id":       user.ID,
				"username": user.Username,
				"email":    user.Email,
				"phone":    user.Phone,
				"role":     user.Role,
				"status":   user.Status,
			},
			"grants":        grants,
			"teams":         teams,
			"projects":      projects,
			"login_history": loginHistory,
		})
	}
}

// ListRoles - GET /admin/v1/roles
func ListRoles(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		roles, err := deps.SystemRolesRepo.ListAll(r.Context())
		if err != nil {
			writeError(w, "internal_error", "failed to list roles")
			return
		}
		if roles == nil {
			roles = []*repository.SystemRole{}
		}
		writeJSON(w, map[string]interface{}{"data": roles, "total": len(roles)})
	}
}

// GetRolePermissions - GET /admin/v1/roles/{name}/permissions
func GetRolePermissions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		roleName := chi.URLParam(r, "name")
		perms, err := deps.SystemRolesRepo.GetPermissionsByRole(r.Context(), roleName)
		if err != nil {
			writeError(w, "internal_error", "failed to get permissions")
			return
		}
		if perms == nil {
			perms = []*repository.SystemPermission{}
		}
		writeJSON(w, map[string]interface{}{"role": roleName, "data": perms, "total": len(perms)})
	}
}

// ListPermissionResources - GET /admin/v1/permissions/resources
func ListPermissionResources(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resources := []string{
			"users", "users.grants", "teams", "teams.members", "projects", "project_users",
			"quota_policies", "api_keys", "models", "providers", "routing_policies",
			"audit_chain", "security_events", "saving_metrics", "fx_rates", "pricing",
			"forecast_jobs", "notify_channels", "alert_inbox",
		}
		writeJSON(w, map[string]interface{}{"data": resources})
	}
}

// ListPermissionActions - GET /admin/v1/permissions/actions
func ListPermissionActions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actions := []string{"read", "write", "delete", "approve", "export"}
		writeJSON(w, map[string]interface{}{"data": actions})
	}
}

// GetMyPermissions - GET /admin/v1/me/permissions?scope_type=&scope_id=
func GetMyPermissions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentUser := auth.GetUser(r.Context())
		if currentUser == nil {
			writeUnauthorized(w, "user not found")
			return
		}

		grants, err := deps.PermissionGrantRepo.ListByUser(r.Context(), currentUser.ID, currentUser.TenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to get permissions")
			return
		}

		// Collect unique roles for this user
		scopeType := r.URL.Query().Get("scope_type")
		scopeID := r.URL.Query().Get("scope_id")

		matchedRoles := map[string]bool{}
		for _, g := range grants {
			if scopeType == "" || (g.ScopeType == scopeType && (scopeID == "" || g.ScopeID == scopeID)) {
				matchedRoles[g.Role] = true
			}
			// Always include tenant-scope grants
			if g.ScopeType == "tenant" {
				matchedRoles[g.Role] = true
			}
		}

		// Get permissions for matched roles
		permSet := map[string]map[string]bool{} // resource -> {action: true}
		for roleName := range matchedRoles {
			if roles.IsSystemAdmin(roleName) {
				// platform_admin has all resources/actions
				allResources := []string{
					"users", "users.grants", "teams", "teams.members", "projects", "project_users",
					"quota_policies", "api_keys", "models", "providers", "routing_policies",
					"audit_chain", "security_events", "saving_metrics", "fx_rates", "pricing",
					"forecast_jobs", "notify_channels", "alert_inbox",
				}
				allActions := []string{"read", "write", "delete", "approve", "export"}
				for _, res := range allResources {
					if permSet[res] == nil {
						permSet[res] = map[string]bool{}
					}
					for _, act := range allActions {
						permSet[res][act] = true
					}
				}
				continue
			}
			perms, err := deps.SystemRolesRepo.GetPermissionsByRole(r.Context(), roleName)
			if err != nil {
				continue
			}
			for _, p := range perms {
				if permSet[p.Resource] == nil {
					permSet[p.Resource] = map[string]bool{}
				}
				permSet[p.Resource][p.Action] = true
			}
		}

		// Flatten to list
		type permEntry struct {
			Resource string `json:"resource"`
			Action   string `json:"action"`
		}
		result := []permEntry{}
		for resource, actions := range permSet {
			for action := range actions {
				result = append(result, permEntry{Resource: resource, Action: action})
			}
		}

		writeJSON(w, map[string]interface{}{
			"user_id":     currentUser.ID,
			"scope_type":  scopeType,
			"scope_id":    scopeID,
			"permissions": result,
		})
	}
}

// canManageGrants reports whether the caller may create or revoke scoped grants.
// Only the system administrator may manage grants (W4 separation of duties). System
// administrators are normally in department_assignment_mode=emergency, so that
// mode is deliberately not checked here.
func canManageGrants(user *repository.User) bool {
	return user != nil && roles.IsSystemAdmin(user.Role)
}

// isGrantableScopedRole limits scoped grants to non-officer roles. The three
// officer roles (and the legacy synonyms) are assigned only through users.role,
// which is validated, audited, and covered by the separation-of-duties guard.
func isGrantableScopedRole(role string) bool {
	switch role {
	case roles.SystemAdmin, roles.SecurityOfficer, roles.Auditor, roles.LegacyAdmin:
		return false
	}
	return role != ""
}

// ListLoginHistoryAudit - GET /admin/v1/audit/login-history
//
// Tenant-wide login history for the auditor (W4 separation of duties). Access is
// restricted by the SoD guard (class login_history); the handler re-checks the
// role so it stays closed even if mounted without the guard. Since the
// 2026-10-01 decision the system administrator also has full read access.
// Callers in the system tenant see every tenant; others see their own tenant.
func ListLoginHistoryAudit(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if !roles.IsAuditor(user.Role) && !roles.IsSystemAdmin(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "separation_of_duties", "only the auditor can read login history")
			return
		}
		if deps == nil || deps.LoginHistoryRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "login_history_unavailable", "login history is unavailable")
			return
		}
		q := r.URL.Query()
		f := repository.LoginHistoryAuditFilter{UserID: q.Get("user_id")}
		if user.TenantID != repository.SystemTenantID {
			f.TenantID = user.TenantID
		}
		for key, dst := range map[string]**time.Time{"since": &f.Since, "until": &f.Until} {
			if v := q.Get(key); v != "" {
				t, err := time.Parse(time.RFC3339, v)
				if err != nil {
					writeError(w, "invalid_request", key+" must be RFC3339")
					return
				}
				*dst = &t
			}
		}
		if v, err := strconv.Atoi(q.Get("limit")); err == nil {
			f.Limit = v
		}
		if v, err := strconv.Atoi(q.Get("offset")); err == nil {
			f.Offset = v
		}

		entries, total, err := deps.LoginHistoryRepo.ListForAudit(r.Context(), f)
		if err != nil {
			writeError(w, "internal_error", "failed to list login history")
			return
		}
		type entry struct {
			ID            int64     `json:"id"`
			UserID        string    `json:"user_id"`
			Username      string    `json:"username"`
			TenantID      string    `json:"tenant_id"`
			LoggedAt      time.Time `json:"logged_at"`
			IP            string    `json:"ip"`
			UserAgent     string    `json:"user_agent"`
			Success       bool      `json:"success"`
			FailureReason string    `json:"failure_reason,omitempty"`
		}
		data := make([]entry, 0, len(entries))
		for _, e := range entries {
			data = append(data, entry{
				ID: e.ID, UserID: e.UserID, Username: e.Username, TenantID: e.TenantID,
				LoggedAt: e.LoggedAt, IP: e.IP, UserAgent: e.UserAgent,
				Success: e.Success, FailureReason: e.FailureReason,
			})
		}
		writeJSON(w, map[string]interface{}{"data": data, "total": total})
	}
}
