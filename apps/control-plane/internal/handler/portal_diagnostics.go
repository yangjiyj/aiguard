package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/diagnostics"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

// 门户代调的诊断接口。鉴权沿用 portal-integration 共享密钥中间件，租户来自
// X-JJDGuard-Tenant-Id，员工 ID 由门户 BFF 按登录会话传入（绝不取自浏览器）。
// 调用身份固定为非管理员：只能查本人的请求、只能读写本人的会话；他人会话表现为 404。
// 不提供诊断包下载与设置。

type portalDiagUserLookup interface {
	GetByID(ctx context.Context, id string) (*repository.User, error)
}

func portalDiagUsers(deps *Dependencies) portalDiagUserLookup {
	if deps == nil {
		return nil
	}
	if deps.UserStore != nil {
		return deps.UserStore
	}
	if deps.UserRepo != nil {
		return deps.UserRepo
	}
	return nil
}

// portalDiagCaller 校验员工在该租户存在且 active，并生成固定非管理员的调用身份。
func portalDiagCaller(w http.ResponseWriter, r *http.Request, deps *Dependencies, userID string) (diagnostics.Caller, bool) {
	w.Header().Set("Cache-Control", "private, no-store")
	tenantID, ok := portalTenantID(w, r)
	if !ok {
		return diagnostics.Caller{}, false
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		writeErrorWithStatus(w, http.StatusBadRequest, "user_required", "user id is required")
		return diagnostics.Caller{}, false
	}
	users := portalDiagUsers(deps)
	if users == nil {
		portalNotConfigured(w, "user repository")
		return diagnostics.Caller{}, false
	}
	user, err := users.GetByID(r.Context(), userID)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to read user")
		return diagnostics.Caller{}, false
	}
	if user == nil || user.TenantID != tenantID {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
		return diagnostics.Caller{}, false
	}
	if user.Status != "active" || !roles.CanLoginPortal(user.Role) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "当前账号没有使用诊断助手的权限")
		return diagnostics.Caller{}, false
	}
	return diagnostics.Caller{TenantID: tenantID, UserID: user.ID, IsAdmin: false}, true
}

// CreatePortalDiagnosticsSession handles POST /admin/v1/portal-integration/diagnostics/sessions.
func CreatePortalDiagnosticsSession(deps *Dependencies, eng *diagnostics.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID string            `json:"user_id"`
			Input  diagnostics.Input `json:"input"`
		}
		if !diagDecode(w, r, &req) {
			return
		}
		c, ok := portalDiagCaller(w, r, deps, req.UserID)
		if !ok {
			return
		}
		if req.Input.Kind != "question" && req.Input.Kind != "health" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "请求内容格式不正确")
			return
		}
		if diagRequireEngine(w, eng) == nil {
			return
		}
		id, err := eng.Start(r.Context(), c, req.Input)
		if err != nil {
			diagFail(w, err)
			return
		}
		writeJSON(w, map[string]string{"session_id": id})
	}
}

// GetPortalDiagnosticsSession handles GET /admin/v1/portal-integration/diagnostics/sessions/{id}?user_id=.
func GetPortalDiagnosticsSession(deps *Dependencies, eng *diagnostics.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := portalDiagCaller(w, r, deps, r.URL.Query().Get("user_id"))
		if !ok {
			return
		}
		if diagRequireEngine(w, eng) == nil {
			return
		}
		v, err := eng.Get(r.Context(), c, chi.URLParam(r, "id"))
		if err != nil {
			diagFail(w, err)
			return
		}
		writeJSON(w, v)
	}
}

// AddPortalDiagnosticsMessage handles POST /admin/v1/portal-integration/diagnostics/sessions/{id}/messages.
func AddPortalDiagnosticsMessage(deps *Dependencies, eng *diagnostics.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID string `json:"user_id"`
			Text   string `json:"text"`
		}
		if !diagDecode(w, r, &req) {
			return
		}
		c, ok := portalDiagCaller(w, r, deps, req.UserID)
		if !ok {
			return
		}
		if diagRequireEngine(w, eng) == nil {
			return
		}
		id := chi.URLParam(r, "id")
		if err := eng.AddMessage(r.Context(), c, id, req.Text); err != nil {
			diagFail(w, err)
			return
		}
		writeJSON(w, map[string]string{"session_id": id})
	}
}

// ListPortalDiagnosticsSessions handles GET /admin/v1/portal-integration/diagnostics/sessions?user_id=.
func ListPortalDiagnosticsSessions(deps *Dependencies, eng *diagnostics.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := portalDiagCaller(w, r, deps, r.URL.Query().Get("user_id"))
		if !ok {
			return
		}
		if diagRequireEngine(w, eng) == nil {
			return
		}
		list, err := eng.List(r.Context(), c, false)
		if err != nil {
			diagFail(w, err)
			return
		}
		writeJSON(w, list)
	}
}
