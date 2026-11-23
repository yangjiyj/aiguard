package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity/consolesso"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// W9 9.3：控制台 CAS / 企业微信账号绑定（管理员显式绑定，登录只认这里的绑定）。
//
//	GET    /admin/v1/identity/console-sso/bindings?user_id=…
//	POST   /admin/v1/identity/console-sso/bindings           {"user_id","provider":"cas|wecom","external_subject"}
//	DELETE /admin/v1/identity/console-sso/bindings/{id}
//
// issuer 由服务端按当前启用的 CAS/企业微信配置决定，不接受客户端传入。
// 绑定等于"谁控制这个外部身份，谁就能以该账号登录控制台"，因此：
//   - 只能绑定本租户账号；
//   - platform_admin 账号只能由 platform_admin 绑定，tenant_owner 账号只能由 tenant_owner/platform_admin 绑定。

type ConsoleSSOBindingDeps struct {
	Service *consolesso.Service
	Store   *consolesso.BindingStore
	Users   *repository.UserRepository
	// Audit 用于写审计日志（logAudit 在 SystemRepo 缺失时静默跳过）。
	Audit *Dependencies
}

func canBindConsoleAccount(actor, target *repository.User) bool {
	if actor == nil || target == nil || !isIdentityAdmin(actor) || actor.TenantID != target.TenantID {
		return false
	}
	switch target.Role {
	case "platform_admin":
		return actor.Role == "platform_admin"
	case "tenant_owner":
		return actor.Role == "platform_admin" || actor.Role == "tenant_owner"
	}
	return true
}

func (d ConsoleSSOBindingDeps) ready(w http.ResponseWriter, r *http.Request) (*repository.User, bool) {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "no user")
		return nil, false
	}
	if !isIdentityAdmin(user) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "需要管理员权限")
		return nil, false
	}
	if d.Store == nil || d.Users == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "unavailable", "账号绑定不可用")
		return nil, false
	}
	return user, true
}

// target 读取并校验被绑定账号：跨租户一律按不存在处理，不泄露其他租户账号是否存在。
func (d ConsoleSSOBindingDeps) target(w http.ResponseWriter, r *http.Request, actor *repository.User, userID string) (*repository.User, bool) {
	userID = strings.TrimSpace(userID)
	if userID == "" || len(userID) > 64 {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "缺少 user_id")
		return nil, false
	}
	target, err := d.Users.GetByID(r.Context(), userID)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "读取账号失败")
		return nil, false
	}
	if target == nil || target.TenantID != actor.TenantID {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "账号不存在")
		return nil, false
	}
	if !canBindConsoleAccount(actor, target) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "无权管理该账号的登录绑定")
		return nil, false
	}
	return target, true
}

func ListConsoleSSOBindings(d ConsoleSSOBindingDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := d.ready(w, r)
		if !ok {
			return
		}
		target, ok := d.target(w, r, actor, r.URL.Query().Get("user_id"))
		if !ok {
			return
		}
		items, err := d.Store.List(r.Context(), actor.TenantID, target.ID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "读取绑定失败")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": items})
	}
}

func CreateConsoleSSOBinding(d ConsoleSSOBindingDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := d.ready(w, r)
		if !ok {
			return
		}
		var req struct {
			UserID          string `json:"user_id"`
			Provider        string `json:"provider"`
			ExternalSubject string `json:"external_subject"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "请求格式错误")
			return
		}
		if req.Provider != consolesso.ProviderCAS && req.Provider != consolesso.ProviderWeCom {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "provider 只能是 cas 或 wecom")
			return
		}
		if !consolesso.ValidBindingSubject(req.Provider, req.ExternalSubject) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "外部账号标识格式不正确")
			return
		}
		issuer, enabled := d.Service.ProviderIssuer(req.Provider)
		if !enabled {
			writeErrorWithStatus(w, http.StatusConflict, "provider_disabled", "该登录方式未启用")
			return
		}
		target, ok := d.target(w, r, actor, req.UserID)
		if !ok {
			return
		}
		b, created, err := d.Store.Create(r.Context(), consolesso.Binding{
			TenantID: actor.TenantID, UserID: target.ID, Provider: req.Provider,
			Issuer: issuer, Subject: req.ExternalSubject,
		})
		switch {
		case errors.Is(err, consolesso.ErrBindingConflict):
			writeErrorWithStatus(w, http.StatusConflict, "conflict", "该外部账号已绑定到其他账号")
			return
		case errors.Is(err, consolesso.ErrBindingInvalid):
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "绑定参数不正确")
			return
		case err != nil:
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "保存绑定失败")
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
			logAudit(r, d.Audit, "identity.console_sso.binding_created", map[string]any{
				"provider": b.Provider, "user_id": b.UserID,
			}, "user_identity_link", b.ID)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(b)
	}
}

func DeleteConsoleSSOBinding(d ConsoleSSOBindingDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := d.ready(w, r)
		if !ok {
			return
		}
		id := strings.TrimSpace(chi.URLParam(r, "id"))
		if id == "" || len(id) > 64 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "缺少绑定 ID")
			return
		}
		// 先按本租户读出绑定，校验对目标账号有权限后再删。
		existing, err := d.Store.Get(r.Context(), actor.TenantID, id)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "读取绑定失败")
			return
		}
		if existing == nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "绑定不存在")
			return
		}
		if _, ok := d.target(w, r, actor, existing.UserID); !ok {
			return
		}
		b, err := d.Store.Delete(r.Context(), actor.TenantID, id)
		if errors.Is(err, consolesso.ErrBindingNotFound) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "绑定不存在")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "删除绑定失败")
			return
		}
		logAudit(r, d.Audit, "identity.console_sso.binding_deleted", map[string]any{
			"provider": b.Provider, "user_id": b.UserID,
		}, "user_identity_link", b.ID)
		w.WriteHeader(http.StatusNoContent)
	}
}
