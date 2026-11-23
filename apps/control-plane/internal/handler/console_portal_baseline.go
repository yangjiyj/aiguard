package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/portalbaseline"
)

// GetPortalLoginBaseline - GET /admin/v1/system/portal-login-baseline
// 只读：比对门户身份引擎 realm 与登录安全基线（D7：不自动改已装客户，提示 + 部署侧一键收紧）。
func GetPortalLoginBaseline(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || !isFullTenantRole(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		now := time.Now()
		if deps.PortalBaselineFetcher == nil {
			writeJSON(w, portalbaseline.Report{Status: "unavailable", CheckedAt: now.UTC().Format(time.RFC3339), Message: "门户身份引擎未启用或未配置"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		realm, err := deps.PortalBaselineFetcher.FetchRealm(ctx)
		if err != nil {
			writeJSON(w, portalbaseline.Report{Status: "unavailable", CheckedAt: now.UTC().Format(time.RFC3339), Message: "无法读取门户身份引擎配置"})
			return
		}
		writeJSON(w, portalbaseline.Evaluate(realm, now))
	}
}
