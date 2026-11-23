package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/go-chi/chi/v5"
)

// requirePlatformAdminTenant 验证 platform_admin 角色并取路径 {id} 单位。
// 失败时已写响应，返回 ("", false)；成功返回 (tenantID, true)。
func requirePlatformAdminTenant(w http.ResponseWriter, r *http.Request, deps *Dependencies) (string, bool) {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "user not found")
		return "", false
	}
	if user.Role != "platform_admin" {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only platform admin can view other units")
		return "", false
	}
	tenantID := chi.URLParam(r, "id")
	if tenantID == "" {
		writeError(w, "invalid_request", "tenant id required")
		return "", false
	}
	t, err := deps.TenantRepo.GetByID(r.Context(), tenantID)
	if err != nil || t == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "unit not found")
		return "", false
	}
	return tenantID, true
}

// writeTenantJSONData 以 {"data": ...} 格式写 JSON 响应。
func writeTenantJSONData(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func requireTenantTeamsAccess(w http.ResponseWriter, r *http.Request, deps *Dependencies) (string, bool) {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "user not found")
		return "", false
	}
	tenantID := chi.URLParam(r, "id")
	if tenantID == "" {
		writeError(w, "invalid_request", "tenant id required")
		return "", false
	}
	if user.Role != "platform_admin" && (user.Role != "tenant_admin" || user.TenantID != tenantID) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return "", false
	}
	if tenantID == repository.SystemTenantID || deps == nil || deps.TenantRepo == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "unit not found")
		return "", false
	}
	tenant, err := deps.TenantRepo.GetByID(r.Context(), tenantID)
	if err != nil || tenant == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "unit not found")
		return "", false
	}
	return tenantID, true
}

// ListTenantTeams GET /admin/v1/tenants/{id}/teams
// platform_admin 查看指定单位的团队列表。
func ListTenantTeams(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := requireTenantTeamsAccess(w, r, deps)
		if !ok {
			return
		}
		teams, err := deps.TeamRepo.ListByTenant(r.Context(), tenantID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		if teams == nil {
			teams = []*repository.Team{}
		}
		writeTenantJSONData(w, teams)
	}
}

// ListTenantUsers GET /admin/v1/tenants/{id}/users
// platform_admin 查看指定单位的用户列表（不含敏感字段）。
func ListTenantUsers(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := requirePlatformAdminTenant(w, r, deps)
		if !ok {
			return
		}
		users, err := deps.UserRepo.List(r.Context(), tenantID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		data := make([]map[string]any, 0, len(users))
		for _, u := range users {
			data = append(data, map[string]any{
				"id":       u.ID,
				"username": u.Username,
				"email":    u.Email,
				"phone":    u.Phone,
				"role":     u.Role,
				"status":   u.Status,
			})
		}
		writeTenantJSONData(w, data)
	}
}

// ListTenantProjects GET /admin/v1/tenants/{id}/projects
// platform_admin 查看指定单位的应用列表。
func ListTenantProjects(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := requirePlatformAdminTenant(w, r, deps)
		if !ok {
			return
		}
		projects, err := deps.ProjectRepo.List(r.Context(), tenantID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		data := make([]types.ProjectInfo, 0, len(projects))
		for _, p := range projects {
			data = append(data, types.ProjectInfo{
				ID:        p.ID,
				Name:      p.Name,
				TenantID:  p.TenantID,
				Status:    p.Status,
				CreatedAt: p.CreatedAt.Format(time.RFC3339),
			})
		}
		writeTenantJSONData(w, data)
	}
}

// DeleteTenantProject DELETE /admin/v1/tenants/{id}/projects/{projectId}
// platform_admin 在组织管理中软删除指定单位的应用；ProjectRepo 同时吊销关联密钥。
func DeleteTenantProject(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := requirePlatformAdminTenant(w, r, deps)
		if !ok {
			return
		}
		projectID := chi.URLParam(r, "projectId")
		if projectID == "" {
			writeError(w, "invalid_request", "project id required")
			return
		}
		if err := deps.ProjectRepo.Delete(r.Context(), tenantID, projectID); err != nil {
			if err.Error() == "project not found" {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "project not found")
				return
			}
			writeError(w, "internal_error", "failed to delete project")
			return
		}
		logAudit(r, deps, "delete_project", map[string]interface{}{
			"tenant_id":  tenantID,
			"project_id": projectID,
		}, "project", projectID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListTenantKeys GET /admin/v1/tenants/{id}/keys
// platform_admin 查看指定单位的 API 密钥列表（不含 hash/value）。
func ListTenantKeys(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := requirePlatformAdminTenant(w, r, deps)
		if !ok {
			return
		}
		keys, err := deps.KeyRepo.ListAll(r.Context(), tenantID)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}
		data := make([]map[string]any, 0, len(keys))
		for _, k := range keys {
			data = append(data, map[string]any{
				"id":         k.ID,
				"key_prefix": k.KeyPrefix,
				"project_id": k.ProjectID,
				"status":     k.Status,
			})
		}
		writeTenantJSONData(w, data)
	}
}
