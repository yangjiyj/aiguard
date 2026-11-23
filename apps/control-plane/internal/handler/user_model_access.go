package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

func GetUserModelAccess(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = withOperationAudit(r, deps)
		actor := auth.GetUser(r.Context())
		if actor == nil || (actor.Role != "platform_admin" && actor.Role != "tenant_admin") {
			writeErrorWithStatus(w, 403, "forbidden", "没有管理用户模型权限的权限")
			return
		}
		if deps == nil || deps.UserModelRepo == nil {
			writeErrorWithStatus(w, 503, "model_access_unavailable", "用户模型权限暂不可用")
			return
		}
		access, err := deps.UserModelRepo.GetAccess(r.Context(), actor.TenantID, chi.URLParam(r, "id"))
		if errors.Is(err, pgx.ErrNoRows) {
			writeErrorWithStatus(w, 404, "not_found", "用户不存在")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, 503, "model_access_unavailable", "无法读取用户模型权限")
			return
		}
		writeJSON(w, map[string]any{"data": access})
	}
}

func SetUserModelAccess(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = withOperationAudit(r, deps)
		actor := auth.GetUser(r.Context())
		if actor == nil || (actor.Role != "platform_admin" && actor.Role != "tenant_admin") {
			writeErrorWithStatus(w, 403, "forbidden", "没有管理用户模型权限的权限")
			return
		}
		if deps == nil || deps.UserModelRepo == nil {
			writeErrorWithStatus(w, 503, "model_access_unavailable", "用户模型权限暂不可用")
			return
		}
		var req struct {
			Mode       string   `json:"mode"`
			ModelNames []string `json:"model_names"`
			Version    *int64   `json:"version"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128*1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, "invalid_request", "模型授权配置格式不正确")
			return
		}
		if dec.Decode(&struct{}{}) != io.EOF || req.Version == nil || *req.Version < 0 {
			writeError(w, "invalid_request", "请刷新用户模型权限后重试")
			return
		}
		userID := chi.URLParam(r, "id")
		access, err := deps.UserModelRepo.SetPolicy(r.Context(), actor.TenantID, userID, actor.ID, modelaccess.Policy{Mode: req.Mode, ModelNames: req.ModelNames}, *req.Version)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			writeErrorWithStatus(w, 404, "not_found", "用户不存在")
		case errors.Is(err, repository.ErrUserModelConflict):
			writeErrorWithStatus(w, 409, "model_access_conflict", "授权配置已变化，请刷新后重试")
		case errors.Is(err, repository.ErrUserModelOutsideDepartment):
			writeError(w, "model_outside_department", "个人授权不能超出当前部门允许的模型")
		case errors.Is(err, repository.ErrUserModelUnavailable):
			writeError(w, "chat_unavailable", "该账号不可使用 Chat 模型")
		case errors.Is(err, modelaccess.ErrInvalidPolicy):
			writeError(w, "invalid_request", "请选择继承部门权限或有效的个人模型名单")
		case err != nil:
			writeErrorWithStatus(w, 503, "model_access_unavailable", "无法保存用户模型权限")
		default:
			writeJSON(w, map[string]any{"data": access})
		}
	}
}

func CreateUserModelExtraGrant(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = withOperationAudit(r, deps)
		actor := auth.GetUser(r.Context())
		if actor == nil || (actor.Role != "platform_admin" && actor.Role != "tenant_admin") {
			writeErrorWithStatus(w, 403, "forbidden", "没有管理用户模型权限的权限")
			return
		}
		if deps == nil || deps.UserModelRepo == nil {
			writeErrorWithStatus(w, 503, "model_access_unavailable", "用户模型权限暂不可用")
			return
		}
		var req struct {
			Model     string     `json:"model"`
			Reason    string     `json:"reason"`
			ExpiresAt *time.Time `json:"expires_at"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil || dec.Decode(&struct{}{}) != io.EOF {
			writeError(w, "invalid_request", "请填写有效模型、授权原因及到期时间")
			return
		}
		grant, err := deps.UserModelRepo.AddExtraGrant(r.Context(), actor.TenantID, chi.URLParam(r, "id"), actor.ID, modelaccess.ExtraGrant{Model: req.Model, Reason: req.Reason, ExpiresAt: req.ExpiresAt})
		switch {
		case errors.Is(err, repository.ErrUserModelSelfGrantForbidden):
			writeErrorWithStatus(w, 403, "self_grant_forbidden", "租户管理员暂不能给自己增加额外授权，请由平台管理员处理")
		case errors.Is(err, pgx.ErrNoRows):
			writeErrorWithStatus(w, 404, "not_found", "用户不存在")
		case errors.Is(err, modelaccess.ErrInvalidPolicy):
			writeError(w, "invalid_request", "授权原因必填，到期时间必须晚于当前时间")
		case errors.Is(err, repository.ErrUserModelUnavailable):
			writeError(w, "model_unavailable", "账号或模型线路当前不可用")
		case errors.Is(err, repository.ErrUserModelConflict):
			writeErrorWithStatus(w, 409, "model_access_conflict", "该模型已有额外授权，请刷新后重试")
		case err != nil:
			writeErrorWithStatus(w, 503, "model_access_unavailable", "无法保存个人额外授权")
		default:
			writeJSON(w, map[string]any{"data": grant})
		}
	}
}

func RevokeUserModelExtraGrant(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = withOperationAudit(r, deps)
		actor := auth.GetUser(r.Context())
		if actor == nil || (actor.Role != "platform_admin" && actor.Role != "tenant_admin") {
			writeErrorWithStatus(w, 403, "forbidden", "没有管理用户模型权限的权限")
			return
		}
		if deps == nil || deps.UserModelRepo == nil {
			writeErrorWithStatus(w, 503, "model_access_unavailable", "用户模型权限暂不可用")
			return
		}
		err := deps.UserModelRepo.RevokeExtraGrant(r.Context(), actor.TenantID, chi.URLParam(r, "id"), actor.ID, chi.URLParam(r, "grant_id"))
		if errors.Is(err, pgx.ErrNoRows) {
			writeErrorWithStatus(w, 404, "not_found", "用户或授权不存在")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, 503, "model_access_unavailable", "无法撤销个人额外授权")
			return
		}
		writeJSON(w, map[string]any{"data": map[string]bool{"revoked": true}})
	}
}
