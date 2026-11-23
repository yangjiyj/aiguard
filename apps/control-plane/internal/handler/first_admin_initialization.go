package handler

import (
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

func initializationAdmin(w http.ResponseWriter, r *http.Request, deps *Dependencies) (string, string, bool) {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "user not found in context")
		return "", "", false
	}
	if user.Role != "platform_admin" {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "platform administrator required")
		return "", "", false
	}
	if deps == nil || deps.FirstAdminInitializer == nil {
		portalNotConfigured(w, "first-admin initializer")
		return "", "", false
	}
	return user.TenantID, user.ID, true
}

// initializationStatusReader 用于只读状态：设计（ws4-rbac-matrix）把 GET system/initialization 归 common，
// 系统管理员与两个官员角色可读；重试（写）仍只认 platform_admin（initializationAdmin）。
func initializationStatusReader(w http.ResponseWriter, r *http.Request, deps *Dependencies) (string, bool) {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "user not found in context")
		return "", false
	}
	if user.Role != "platform_admin" && !roles.IsSecurityOfficer(user.Role) && !roles.IsAuditor(user.Role) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "platform administrator, security officer or auditor required")
		return "", false
	}
	if deps == nil || deps.FirstAdminInitializer == nil {
		portalNotConfigured(w, "first-admin initializer")
		return "", false
	}
	return user.TenantID, true
}

func GetFirstAdminInitializationStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := initializationStatusReader(w, r, deps)
		if !ok {
			return
		}
		status, err := deps.FirstAdminInitializer.GetStatus(r.Context(), tenantID)
		if err != nil {
			writeError(w, "internal_error", "failed to read initialization status")
			return
		}
		if status == nil {
			writeJSON(w, map[string]any{"data": map[string]any{"armed": false, "status": "not_armed"}})
			return
		}
		writeJSON(w, map[string]any{"data": status})
	}
}

func RetryFirstAdminInitialization(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, actorID, ok := initializationAdmin(w, r, deps)
		if !ok {
			return
		}
		if err := deps.FirstAdminInitializer.Initialize(r.Context(), tenantID, actorID); err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "initialization_failed", "initialization failed and remains retryable")
			return
		}
		status, err := deps.FirstAdminInitializer.GetStatus(r.Context(), tenantID)
		if err != nil {
			writeError(w, "internal_error", "initialization completed but status could not be read")
			return
		}
		if status == nil {
			writeJSON(w, map[string]any{"data": map[string]any{"armed": false, "status": "not_armed"}})
			return
		}
		writeJSON(w, map[string]any{"data": status})
	}
}
