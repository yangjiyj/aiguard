package handler

import (
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
)

// OrgWriterGuard 仅允许 platform_admin / tenant_owner 通过（组织写操作）。
// 隔离仍由各 handler 的 session 租户作用域保证；本门禁只挡角色，不动全局 RBAC 开关。
func OrgWriterGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if user.Role != "platform_admin" && user.Role != "tenant_owner" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only unit admins can manage organization")
			return
		}
		next.ServeHTTP(w, r)
	})
}
