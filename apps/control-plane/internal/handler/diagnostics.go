package handler

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/diagnostics"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

// 运维诊断机器人的 HTTP 接口。身份取自 auth.GetUser：
//   - 管理员（platform_admin / tenant_admin 及其旧别名）看全租户；
//   - chat_user 不属于控制台，一律 403；
//   - 其余角色是员工，只能看到自己发起的会话和自己的请求。
// 他人的会话对员工表现为“不存在”（404），不泄露存在性。

const diagMaxBody = 64 << 10

func diagCaller(w http.ResponseWriter, r *http.Request) (diagnostics.Caller, bool) {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "no user")
		return diagnostics.Caller{}, false
	}
	if user.Role == roles.ChatUser {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "当前账号没有使用诊断助手的权限")
		return diagnostics.Caller{}, false
	}
	return diagnostics.Caller{TenantID: user.TenantID, UserID: user.ID, IsAdmin: roles.IsConsoleAdministrator(user.Role)}, true
}

func diagRequireEngine(w http.ResponseWriter, eng *diagnostics.Engine) *diagnostics.Engine {
	if eng == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "diagnostics_unavailable", "诊断功能暂不可用，请稍后再试或联系管理员")
		return nil
	}
	return eng
}

func diagDecode(w http.ResponseWriter, r *http.Request, dst any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, diagMaxBody))
	if err != nil || json.Unmarshal(body, dst) != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "请求内容格式不正确")
		return false
	}
	return true
}

func diagFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, diagnostics.ErrDiagBusy):
		writeErrorWithStatus(w, http.StatusConflict, "diagnosis_busy", "已有诊断在进行，请稍候")
	case errors.Is(err, diagnostics.ErrSessionRunning):
		writeErrorWithStatus(w, http.StatusConflict, "diagnosis_busy", err.Error())
	case errors.Is(err, diagnostics.ErrNotFound):
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "诊断会话不存在")
	case errors.Is(err, diagnostics.ErrForbidden10):
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, diagnostics.ErrInputEmpty), errors.Is(err, diagnostics.ErrModelNotInTenant):
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, diagnostics.ErrNoReport):
		writeErrorWithStatus(w, http.StatusConflict, "no_report", err.Error())
	case errors.Is(err, diagnostics.ErrUnavailable):
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "diagnostics_unavailable", "诊断功能暂不可用，请稍后再试或联系管理员")
	default:
		log.Printf("[diagnostics] 接口错误: %v", err)
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "诊断服务出错，请稍后再试")
	}
}

// CreateDiagnosticsSession handles POST /admin/v1/diagnostics/sessions.
func CreateDiagnosticsSession(eng *diagnostics.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := diagCaller(w, r)
		if !ok {
			return
		}
		if diagRequireEngine(w, eng) == nil {
			return
		}
		var req struct {
			Input diagnostics.Input `json:"input"`
		}
		if !diagDecode(w, r, &req) {
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

// GetDiagnosticsSession handles GET /admin/v1/diagnostics/sessions/{id}.
func GetDiagnosticsSession(eng *diagnostics.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := diagCaller(w, r)
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

// AddDiagnosticsMessage handles POST /admin/v1/diagnostics/sessions/{id}/messages.
func AddDiagnosticsMessage(eng *diagnostics.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := diagCaller(w, r)
		if !ok {
			return
		}
		if diagRequireEngine(w, eng) == nil {
			return
		}
		var req struct {
			Text string `json:"text"`
		}
		if !diagDecode(w, r, &req) {
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

// ListDiagnosticsSessions handles GET /admin/v1/diagnostics/sessions.
func ListDiagnosticsSessions(eng *diagnostics.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := diagCaller(w, r)
		if !ok {
			return
		}
		if diagRequireEngine(w, eng) == nil {
			return
		}
		all := r.URL.Query().Get("all") == "1"
		list, err := eng.List(r.Context(), c, all)
		if err != nil {
			diagFail(w, err)
			return
		}
		writeJSON(w, list)
	}
}

// DownloadDiagnosticsBundle handles GET /admin/v1/diagnostics/sessions/{id}/bundle (admin only).
func DownloadDiagnosticsBundle(eng *diagnostics.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := diagCaller(w, r)
		if !ok {
			return
		}
		if !c.IsAdmin {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "仅管理员可导出诊断包")
			return
		}
		if diagnostics.BundleBuilder == nil {
			writeErrorWithStatus(w, http.StatusNotImplemented, "not_implemented", "诊断包导出暂未启用")
			return
		}
		if diagRequireEngine(w, eng) == nil {
			return
		}
		id := chi.URLParam(r, "id")
		bs, err := eng.BundleFor(r.Context(), c, id)
		if err != nil {
			diagFail(w, err)
			return
		}
		b, err := diagnostics.BundleBuilder(r.Context(), bs)
		if err != nil {
			log.Printf("[diagnostics] 生成诊断包失败: %v", err)
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "生成诊断包失败")
			return
		}
		name := "diagnostics-" + url.PathEscape(strings.TrimPrefix(id, "dgs_")) + ".zip"
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Content-Length", itoa(len(b)))
		_, _ = w.Write(b)
	}
}

// GetDiagnosticsSettings handles GET /admin/v1/diagnostics/settings.
func GetDiagnosticsSettings(eng *diagnostics.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := diagCaller(w, r)
		if !ok {
			return
		}
		if diagRequireEngine(w, eng) == nil {
			return
		}
		v, err := eng.GetSettings(r.Context(), c)
		if err != nil {
			diagFail(w, err)
			return
		}
		writeJSON(w, v)
	}
}

// PutDiagnosticsSettings handles PUT /admin/v1/diagnostics/settings (admin only).
func PutDiagnosticsSettings(eng *diagnostics.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := diagCaller(w, r)
		if !ok {
			return
		}
		if !c.IsAdmin {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "仅管理员可修改诊断设置")
			return
		}
		if diagRequireEngine(w, eng) == nil {
			return
		}
		var req struct {
			AIEnabled *bool   `json:"ai_enabled"`
			ModelID   *string `json:"model_id"`
		}
		if !diagDecode(w, r, &req) {
			return
		}
		if req.AIEnabled == nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "缺少 ai_enabled")
			return
		}
		if err := eng.PutSettings(r.Context(), c, *req.AIEnabled, req.ModelID); err != nil {
			diagFail(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}
}

// GetDiagnosticsBadge handles GET /admin/v1/diagnostics/badge.
func GetDiagnosticsBadge(eng *diagnostics.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := diagCaller(w, r)
		if !ok {
			return
		}
		if diagRequireEngine(w, eng) == nil {
			return
		}
		has, err := eng.Badge(r.Context(), c)
		if err != nil {
			diagFail(w, err)
			return
		}
		writeJSON(w, map[string]bool{"has_issue": has})
	}
}
