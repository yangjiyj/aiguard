package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
)

// ---- 双因素自助（/admin/v1/me/totp*）----

type totpSetupSessionStore interface {
	ClearTOTPSetupPending(ctx context.Context, sessionID string) error
}

// GetMyTOTPStatus - GET /admin/v1/me/totp
func GetMyTOTPStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || deps.ConsoleSecurity == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		sec, err := deps.ConsoleSecurity.Get(r.Context(), user.ID)
		if err != nil {
			writeError(w, "internal_error", "failed to load two-factor status")
			return
		}
		policy := LoadConsoleLoginPolicy(r.Context(), deps.SystemRepo)
		writeJSON(w, map[string]any{
			"enabled":  sec.TOTPEnabled,
			"required": policy.AdminTOTPRequired && isConsoleAdminRole(user.Role),
		})
	}
}

// SetupMyTOTP - POST /admin/v1/me/totp/setup：生成新密钥（未启用），返回 otpauth URI 供验证器扫码/手输。
func SetupMyTOTP(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || deps.ConsoleSecurity == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		sec, err := deps.ConsoleSecurity.Get(r.Context(), user.ID)
		if err != nil {
			writeError(w, "internal_error", "failed to load two-factor status")
			return
		}
		if sec.TOTPEnabled {
			writeErrorWithStatus(w, http.StatusConflict, "totp_already_enabled", "two-factor authentication is already enabled")
			return
		}
		secret, err := generateTOTPSecret()
		if err != nil {
			writeError(w, "internal_error", "failed to generate secret")
			return
		}
		enc, err := encryptTOTPSecret(secret)
		if err != nil {
			writeError(w, "internal_error", "failed to protect secret")
			return
		}
		if err := deps.ConsoleSecurity.SetTOTP(r.Context(), user.ID, enc, false); err != nil {
			writeError(w, "internal_error", "failed to save secret")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"secret": secret, "otpauth_uri": totpProvisioningURI(user.Username, secret)})
	}
}

// EnableMyTOTP - POST /admin/v1/me/totp/enable {code}：用验证器当前码确认后启用。
func EnableMyTOTP(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || deps.ConsoleSecurity == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		var req struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		sec, err := deps.ConsoleSecurity.Get(r.Context(), user.ID)
		if err != nil || sec.TOTPSecretEnc == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "totp_setup_missing", "start two-factor setup first")
			return
		}
		secret, err := decryptTOTPSecret(sec.TOTPSecretEnc)
		if err != nil {
			writeError(w, "internal_error", "failed to read secret")
			return
		}
		counter, ok := verifyTOTP(secret, req.Code, time.Now())
		if ok {
			ok, err = consumeTOTPStep(r.Context(), deps.RedisClient, user.ID, counter)
			if err != nil {
				writeError(w, "internal_error", "failed to verify code")
				return
			}
		}
		if !ok {
			writeErrorWithStatus(w, http.StatusBadRequest, "totp_invalid", "verification code is incorrect")
			return
		}
		if err := deps.ConsoleSecurity.SetTOTP(r.Context(), user.ID, sec.TOTPSecretEnc, true); err != nil {
			writeError(w, "internal_error", "failed to enable two-factor authentication")
			return
		}
		if session := auth.GetSession(r.Context()); session != nil {
			if store, ok := deps.SessionRepo.(totpSetupSessionStore); ok {
				_ = store.ClearTOTPSetupPending(r.Context(), session.ID)
			}
		}
		logAudit(r, deps, "enable_totp", map[string]interface{}{"user_id": user.ID}, "user", user.ID)
		writeJSON(w, map[string]any{"enabled": true})
	}
}

// ---- 管理员操作 ----

// UnlockUserLogin - POST /admin/v1/users/{id}/unlock-login：解除登录失败锁定。
func UnlockUserLogin(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor := auth.GetUser(r.Context())
		if actor == nil || !roles.IsConsoleAdministrator(actor.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		target, err := deps.UserRepo.GetByID(r.Context(), chi.URLParam(r, "id"))
		if err != nil || target == nil || (actor.Role != "platform_admin" && target.TenantID != actor.TenantID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		guard := newLoginGuard(deps.RedisClient, LoadConsoleLoginPolicy(r.Context(), deps.SystemRepo))
		if err := guard.Unlock(r.Context(), target.Username, target.TenantID); err != nil {
			writeError(w, "internal_error", "failed to unlock")
			return
		}
		logAudit(r, deps, "unlock_user_login", map[string]interface{}{"user_id": target.ID}, "user", target.ID)
		writeJSON(w, map[string]any{"unlocked": true})
	}
}

// ResetUserTOTP - POST /admin/v1/users/{id}/reset-totp：清除他人双因素（丢失手机时）。
func ResetUserTOTP(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor := auth.GetUser(r.Context())
		if actor == nil || !roles.IsConsoleAdministrator(actor.Role) || deps.ConsoleSecurity == nil {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		target, err := deps.UserRepo.GetByID(r.Context(), chi.URLParam(r, "id"))
		if err != nil || target == nil || (actor.Role != "platform_admin" && target.TenantID != actor.TenantID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		if target.ID == actor.ID {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "cannot reset your own two-factor authentication")
			return
		}
		if err := deps.ConsoleSecurity.SetTOTP(r.Context(), target.ID, "", false); err != nil {
			writeError(w, "internal_error", "failed to reset two-factor authentication")
			return
		}
		if deps.SessionRepo != nil {
			_ = deps.SessionRepo.DeleteByUser(r.Context(), target.ID)
		}
		logAudit(r, deps, "reset_user_totp", map[string]interface{}{"user_id": target.ID}, "user", target.ID)
		writeJSON(w, map[string]any{"reset": true})
	}
}

// ---- 登录安全系统设置（/admin/v1/system/login-security）----

type consoleLoginSecuritySettings struct {
	LockoutThreshold     int    `json:"lockout_threshold"`
	LockoutMinutes       int    `json:"lockout_minutes"`
	PasswordMinLength    int    `json:"password_min_length"`
	PasswordMinClasses   int    `json:"password_min_classes"`
	PasswordHistoryCount int    `json:"password_history_count"`
	PasswordMaxAgeDays   int    `json:"password_max_age_days"`
	SessionIdleMinutes   int    `json:"session_idle_minutes"`
	SessionAbsoluteHours int    `json:"session_absolute_hours"`
	SessionMaxConcurrent int    `json:"session_max_concurrent"`
	AdminTOTPRequired    bool   `json:"admin_totp_required"`
	AdminIPAllowlist     string `json:"admin_ip_allowlist"`
}

func settingsFromPolicy(p ConsoleLoginPolicy) consoleLoginSecuritySettings {
	return consoleLoginSecuritySettings{
		LockoutThreshold: p.LockoutThreshold, LockoutMinutes: p.LockoutMinutes,
		PasswordMinLength: p.PasswordMinLength, PasswordMinClasses: p.PasswordMinClasses,
		PasswordHistoryCount: p.PasswordHistoryCount, PasswordMaxAgeDays: p.PasswordMaxAgeDays,
		SessionIdleMinutes: p.SessionIdleMinutes, SessionAbsoluteHours: p.SessionAbsoluteHours,
		SessionMaxConcurrent: p.SessionMaxConcurrent, AdminTOTPRequired: p.AdminTOTPRequired,
		AdminIPAllowlist: strings.Join(p.AdminIPAllowlist, ","),
	}
}

// GetConsoleLoginSecurity - GET /admin/v1/system/login-security
func GetConsoleLoginSecurity(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || !isFullTenantRole(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		writeJSON(w, settingsFromPolicy(LoadConsoleLoginPolicy(r.Context(), deps.SystemRepo)))
	}
}

func validateCIDRList(raw string) (string, error) {
	entries := splitCIDRList(raw)
	for _, e := range entries {
		if strings.Contains(e, "/") {
			if _, _, err := net.ParseCIDR(e); err != nil {
				return "", fmt.Errorf("invalid CIDR: %s", e)
			}
		} else if net.ParseIP(e) == nil {
			return "", fmt.Errorf("invalid IP: %s", e)
		}
	}
	return strings.Join(entries, ","), nil
}

// UpdateConsoleLoginSecurity - PUT /admin/v1/system/login-security（仅 platform_admin，逐项校验范围）。
func UpdateConsoleLoginSecurity(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		var in consoleLoginSecuritySettings
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		ints := map[string]int{
			settingLockoutThreshold: in.LockoutThreshold, settingLockoutMinutes: in.LockoutMinutes,
			settingPasswordMinLength: in.PasswordMinLength, settingPasswordMinClasses: in.PasswordMinClasses,
			settingPasswordHistoryCount: in.PasswordHistoryCount, settingPasswordMaxAgeDays: in.PasswordMaxAgeDays,
			settingSessionIdleMinutes: in.SessionIdleMinutes, settingSessionAbsoluteHours: in.SessionAbsoluteHours,
			settingSessionMaxConcurrent: in.SessionMaxConcurrent,
		}
		values := make(map[string]string, len(ints)+2)
		for key, v := range ints {
			b := consoleIntSettingBounds[key]
			if v < b[0] || v > b[1] {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_login_security", fmt.Sprintf("%s must be between %d and %d", key, b[0], b[1]))
				return
			}
			values[key] = strconv.Itoa(v)
		}
		if in.SessionIdleMinutes > in.SessionAbsoluteHours*60 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_login_security", "idle timeout must not exceed absolute timeout")
			return
		}
		cidrs, err := validateCIDRList(in.AdminIPAllowlist)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_login_security", err.Error())
			return
		}
		// 防自锁：开启白名单时，当前操作者的来源地址必须在名单内。
		if cidrs != "" && !ipAllowed(splitCIDRList(cidrs), requestClientIP(r)) {
			writeErrorWithStatus(w, http.StatusBadRequest, "allowlist_excludes_current_ip", "the allowlist must include your current address")
			return
		}
		values[settingAdminIPAllowlist] = cidrs
		values[settingAdminTOTPRequired] = strconv.FormatBool(in.AdminTOTPRequired)
		if err := deps.SystemRepo.SetMultiple(r.Context(), values); err != nil {
			writeError(w, "internal_error", "failed to update settings")
			return
		}
		detail := make(map[string]interface{}, len(values))
		for k, v := range values {
			detail[k] = v
		}
		logAudit(r, deps, "update_login_security", detail, "system", "login_security")
		writeJSON(w, settingsFromPolicy(LoadConsoleLoginPolicy(r.Context(), deps.SystemRepo)))
	}
}
