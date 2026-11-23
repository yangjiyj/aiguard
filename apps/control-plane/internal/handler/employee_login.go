package handler

import (
	"encoding/json"
	"net/http"
)

// EmployeeLogin uses the same credential, captcha, lockout and TOTP policy as
// management sign-in, but grants only a one-use employee Chat handoff.
func EmployeeLogin(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Pragma", "no-cache")
		if _, ok := portalTenantID(w, r); !ok {
			return
		}
		if deps == nil || deps.UserRepo == nil {
			portalNotConfigured(w, "employee authentication")
			return
		}
		var req consoleLoginRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid employee sign-in request")
			return
		}
		valid, err := validateCaptcha(r.Context(), deps.RedisClient, req.CaptchaID, req.CaptchaCode)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "captcha_unavailable", "captcha service unavailable")
			return
		}
		if !valid {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_captcha", "captcha is invalid or expired")
			return
		}
		authenticateLogin(w, r, deps, req, false, true)
	}
}

// Account existence, directory ownership and lock state stay internal.
func writeEmployeeCredentialFailure(w http.ResponseWriter) {
	writeErrorWithStatus(w, http.StatusUnauthorized, "invalid_credentials", "登录失败，请检查凭据；公司统一身份账号请使用企业账号登录。")
}
