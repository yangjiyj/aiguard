package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// ConsoleLoginRecorder 由 repository.UserLoginHistoryRepository 实现。
type ConsoleLoginRecorder interface {
	Record(ctx context.Context, a repository.LoginAttempt) error
}

// ConsoleUserSecurityStore 由 repository.ConsoleUserSecurityRepository 实现。
type ConsoleUserSecurityStore interface {
	PasswordHistoryStore
	Get(ctx context.Context, userID string) (repository.ConsoleUserSecurity, error)
	MarkPasswordChanged(ctx context.Context, userID string) error
	SetTOTP(ctx context.Context, userID, secretEnc string, enabled bool) error
}

// consoleSessionLimiter 由 repository.SessionRepository 实现；测试替身可不实现（跳过并发限制）。
type consoleSessionLimiter interface {
	EnforceMaxConcurrent(ctx context.Context, userID string, max int) (int, error)
}

// 登录失败原因（写入 user_login_history.failure_reason；对外统一提示，不回显）。
const (
	loginFailUnknownUser   = "unknown_user"
	loginFailInactive      = "user_inactive"
	loginFailNoPassword    = "password_not_configured"
	loginFailBadPassword   = "invalid_password"
	loginFailLocked        = "account_locked"
	loginFailServiceRole   = "service_role_not_allowed"
	loginFailServiceRotate = "service_password_rotation_required"
	loginFailIPNotAllowed  = "ip_not_allowed"
	loginFailTOTPRequired  = "totp_required"
	loginFailTOTPInvalid   = "totp_invalid"
	loginFailLockTriggered = "lockout_triggered"
)

func consoleLoginRecorder(deps *Dependencies) ConsoleLoginRecorder {
	if deps.LoginRecorder != nil {
		return deps.LoginRecorder
	}
	if deps.LoginHistoryRepo != nil {
		return deps.LoginHistoryRepo
	}
	return nil
}

// recordConsoleLoginEvent 同步写库（登录不是高频路径；等保要求不能丢记录）。写库失败只记日志、不阻断登录。
func recordConsoleLoginEvent(r *http.Request, deps *Dependencies, a repository.LoginAttempt) {
	rec := consoleLoginRecorder(deps)
	if rec == nil {
		return
	}
	if a.IP == "" {
		a.IP = requestClientIP(r)
	}
	if a.UserAgent == "" {
		a.UserAgent = r.UserAgent()
	}
	if err := rec.Record(r.Context(), a); err != nil {
		log.Printf("console login history write failed: %v", err)
	}
}

func writeLoginLocked(w http.ResponseWriter, remaining time.Duration) {
	minutes := int(math.Ceil(remaining.Minutes()))
	if minutes < 1 {
		minutes = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(remaining.Seconds()))))
	writeErrorWithStatusAndDetails(w, http.StatusLocked, "account_locked",
		"account temporarily locked after repeated failed logins", map[string]int{"retry_after_minutes": minutes})
}

func authenticateConsoleLogin(w http.ResponseWriter, r *http.Request, deps *Dependencies, req consoleLoginRequest, service bool) {
	authenticateLogin(w, r, deps, req, service, false)
}
func authenticateLogin(w http.ResponseWriter, r *http.Request, deps *Dependencies, req consoleLoginRequest, service, employee bool) {
	ctx := r.Context()
	if employee && deps.UserIdentityLinkLookup == nil {
		writeErrorWithStatus(w, 503, "login_unavailable", "login service unavailable")
		return
	}
	policy := LoadConsoleLoginPolicy(ctx, deps.SystemRepo)
	guard := newLoginGuard(deps.RedisClient, policy)
	guardUsername := req.Username
	if employee {
		guardUsername = "employee:" + strings.TrimSpace(r.Header.Get(portalIntegrationTenantHeader)) + "\x00" + req.Username
	}
	ip := requestClientIP(r)
	attempt := repository.LoginAttempt{AttemptedUsername: req.Username, IP: ip, UserAgent: r.UserAgent(), Event: repository.LoginEventLogin}

	var user *repository.User
	var err error
	loadUser := func() bool {
		if employee {
			user, err = deps.UserRepo.GetByUsername(ctx, strings.TrimSpace(r.Header.Get(portalIntegrationTenantHeader)), req.Username)
		} else {
			user, err = deps.UserRepo.GetByUsernameGlobal(ctx, req.Username)
		}
		if err != nil {
			log.Printf("Login error: GetByUsernameGlobal failed: %v", err)
			writeError(w, "internal_error", "database error")
			return false
		}
		return true
	}
	if employee && !loadUser() {
		return
	}

	// Directory-managed accounts never use their local/password-form credential,
	// even when a legacy hash remains. Their anonymous response is indistinguishable.
	if employee && user != nil && deps.UserIdentityLinkLookup != nil {
		external, lookupErr := deps.UserIdentityLinkLookup.HasExternalCredentialOwner(ctx, user.TenantID, user.ID)
		if lookupErr != nil {
			writeErrorWithStatus(w, 503, "login_unavailable", "login service unavailable")
			return
		}
		if external {
			equalizeBcryptCost(req.Password)
			attempt.UserID = user.ID
			attempt.FailureReason = "enterprise_login_required"
			recordConsoleLoginEvent(r, deps, attempt)
			writeEmployeeCredentialFailure(w)
			return
		}
	}
	// 1) 已锁定：直接拒绝，不查库、不跑 bcrypt。
	if remaining, err := guard.lockedFor(ctx, guardUsername, ip); err != nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "login_guard_unavailable", "login protection unavailable")
		return
	} else if remaining > 0 {
		attempt.FailureReason = loginFailLocked
		recordConsoleLoginEvent(r, deps, attempt)
		if employee {
			equalizeBcryptCost(req.Password)
			writeEmployeeCredentialFailure(w)
		} else {
			writeLoginLocked(w, remaining)
		}
		return
	}

	fail := func(userID, reason string) {
		attempt.UserID = userID
		attempt.FailureReason = reason
		recordConsoleLoginEvent(r, deps, attempt)
		locked, err := guard.recordFailure(ctx, guardUsername, ip)
		if err != nil {
			log.Printf("console login failure counter unavailable: %v", err)
		}
		if locked {
			recordConsoleLoginEvent(r, deps, repository.LoginAttempt{
				UserID: userID, AttemptedUsername: req.Username, IP: ip, UserAgent: r.UserAgent(),
				FailureReason: loginFailLockTriggered, Event: repository.LoginEventLocked,
			})
			if employee {
				writeEmployeeCredentialFailure(w)
			} else {
				writeLoginLocked(w, guard.window())
			}
			return
		}
		if employee {
			writeEmployeeCredentialFailure(w)
		} else {
			writeUnauthorized(w, genericLoginFailureMessage)
		}
	}

	if !employee && !loadUser() {
		return
	}
	// 2) 账号不存在/未激活/无密码：统一提示 + 同成本 bcrypt（3.6）。
	if user == nil {
		equalizeBcryptCost(req.Password)
		fail("", loginFailUnknownUser)
		return
	}
	if user.Status != "active" {
		equalizeBcryptCost(req.Password)
		fail(user.ID, loginFailInactive)
		return
	}
	if user.PasswordHash == "" {
		equalizeBcryptCost(req.Password)
		fail(user.ID, loginFailNoPassword)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		fail(user.ID, loginFailBadPassword)
		return
	}

	// 机器通道只服务 platform_connector；角色不符或待轮换密钥时拒绝，
	// 且不计入人工登录锁定计数（避免端点混用误锁真人账号）。
	if service && user.Role != "platform_connector" {
		attempt.UserID = user.ID
		attempt.FailureReason = loginFailServiceRole
		recordConsoleLoginEvent(r, deps, attempt)
		writeErrorWithStatus(w, http.StatusUnauthorized, "service_role_not_allowed",
			"service login only accepts platform_connector identities")
		return
	}
	if service && user.MustChangePassword {
		attempt.UserID = user.ID
		attempt.FailureReason = loginFailServiceRotate
		recordConsoleLoginEvent(r, deps, attempt)
		writeErrorWithStatus(w, http.StatusUnauthorized, "service_credential_rotation_required",
			"service credential rotation required")
		return
	}

	if !service {
		if employee {
			if !roles.CanLoginPortal(user.Role) || user.TenantID != strings.TrimSpace(r.Header.Get(portalIntegrationTenantHeader)) {
				attempt.UserID = user.ID
				attempt.FailureReason = "employee_identity_not_allowed"
				recordConsoleLoginEvent(r, deps, attempt)
				writeErrorWithStatus(w, http.StatusForbidden, "authorization_denied", "personal sign-in requires an active human account in this tenant")
				return
			}
		} else if !isConsoleAdminRole(user.Role) {
			attempt.UserID = user.ID
			attempt.FailureReason = "console_role_required"
			recordConsoleLoginEvent(r, deps, attempt)
			writeErrorWithStatus(w, http.StatusForbidden, "console_role_required", "administrator identity required; employees must sign in through Chat")
			return
		}
	}

	// 3) 管理员来源 IP 白名单（3.7）。密码正确但来源不允许：单独错误码，便于运维定位；不计入爆破计数。
	if isConsoleAdminRole(user.Role) && !ipAllowed(policy.AdminIPAllowlist, ip) {
		attempt.UserID = user.ID
		attempt.FailureReason = loginFailIPNotAllowed
		recordConsoleLoginEvent(r, deps, attempt)
		writeErrorWithStatus(w, http.StatusForbidden, "login_ip_not_allowed", "login from this address is not allowed for administrator accounts")
		return
	}

	// 4) 双因素（3.5）。已绑定的账号一律校验；管理员被要求启用但未绑定时，只签发“绑定专用”会话。
	var security repository.ConsoleUserSecurity
	if deps.ConsoleSecurity != nil {
		security, err = deps.ConsoleSecurity.Get(ctx, user.ID)
		if err != nil {
			writeError(w, "internal_error", "failed to load account security")
			return
		}
	}
	if employee && isConsoleAdminRole(user.Role) && (!security.TOTPEnabled || security.TOTPSecretEnc == "") {
		attempt.UserID = user.ID
		attempt.FailureReason = "employee_admin_totp_not_configured"
		recordConsoleLoginEvent(r, deps, attempt)
		writeErrorWithStatus(w, http.StatusForbidden, "totp_setup_required", "请先在管理控制台绑定动态验证码后登录个人中心")
		return
	}
	totpSetupPending := false
	if security.TOTPEnabled && security.TOTPSecretEnc != "" {
		if req.TOTPCode == "" {
			attempt.UserID = user.ID
			attempt.FailureReason = loginFailTOTPRequired
			recordConsoleLoginEvent(r, deps, attempt)
			writeErrorWithStatus(w, http.StatusUnauthorized, "totp_required", "two-factor verification code required")
			return
		}
		secret, derr := decryptTOTPSecret(security.TOTPSecretEnc)
		counter, ok := verifyTOTP(secret, req.TOTPCode, time.Now())
		if derr == nil && ok {
			ok, err = consumeTOTPStep(ctx, deps.RedisClient, user.ID, counter)
			if err != nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "login_guard_unavailable", "login protection unavailable")
				return
			}
		}
		if derr != nil || !ok {
			fail(user.ID, loginFailTOTPInvalid)
			return
		}
	} else if !employee && policy.AdminTOTPRequired && isConsoleAdminRole(user.Role) && deps.ConsoleSecurity != nil {
		totpSetupPending = true
	}

	guard.reset(ctx, guardUsername, ip)

	// 5) 定期改密（3.3）：超过最长使用期限的密码视同首次登录，强制改密。
	mustChange := user.MustChangePassword
	passwordExpired := false
	if policy.PasswordMaxAgeDays > 0 && security.PasswordChangedAt != nil &&
		time.Since(*security.PasswordChangedAt) > time.Duration(policy.PasswordMaxAgeDays)*24*time.Hour {
		mustChange = true
		passwordExpired = true
	}

	// Chat-only login exchanges one-use proof for an Auth.js session. Required
	// password changes retain the existing restricted self-service session.
	if employee && (mustChange || req.NewPassword != "") {
		if req.NewPassword == "" {
			attempt.UserID = user.ID
			attempt.FailureReason = "password_change_required"
			recordConsoleLoginEvent(r, deps, attempt)
			writeErrorWithStatus(w, http.StatusForbidden, "password_change_required", "password change required before employee sign-in")
			return
		}
		body, _ := json.Marshal(types.ChangePasswordRequest{CurrentPassword: req.Password, NewPassword: req.NewPassword})
		change := r.Clone(context.WithValue(context.WithValue(r.Context(), auth.UserKey, user), personalLoginContextKey{}, true))
		change.Body = io.NopCloser(bytes.NewReader(body))
		tracked := &loginStatusWriter{ResponseWriter: w}
		ChangeCurrentPassword(deps)(tracked, change)
		attempt.UserID = user.ID
		attempt.Success = tracked.status == http.StatusOK
		if !attempt.Success {
			attempt.FailureReason = "employee_password_change_failed"
		}
		recordConsoleLoginEvent(r, deps, attempt)
		return
	}
	if employee && !mustChange && !totpSetupPending {
		ticket, ok := issueChatLoginTicket(w, r, deps, user)
		if !ok {
			return
		}
		attempt.UserID = user.ID
		attempt.Success = true
		recordConsoleLoginEvent(r, deps, attempt)
		if deps.LoginHistoryRepo != nil {
			_ = deps.LoginHistoryRepo.UpdateUserLastLogin(ctx, user.ID)
		}
		writeJSON(w, consoleLoginResponse{
			LoginResponse: types.LoginResponse{User: types.UserInfo{ID: user.ID, Username: user.Username, Role: user.Role, TenantID: user.TenantID}},
			ChatTicket:    ticket,
		})
		return
	}

	// 6) 会话：空闲/绝对超时 + 并发上限（3.4）。
	if limiter, ok := deps.SessionRepo.(consoleSessionLimiter); ok {
		if _, err := limiter.EnforceMaxConcurrent(ctx, user.ID, policy.SessionMaxConcurrent); err != nil {
			writeError(w, "internal_error", "failed to enforce session limit")
			return
		}
	}
	now := time.Now()
	sessionID := uuid.New().String()
	session := &repository.Session{
		ID:                 sessionID,
		UserID:             user.ID,
		Username:           user.Username,
		Role:               user.Role,
		TenantID:           user.TenantID,
		AbsoluteExpiresAt:  now.Add(time.Duration(policy.SessionAbsoluteHours) * time.Hour),
		IdleTimeoutSeconds: policy.SessionIdleMinutes * 60,
		IP:                 ip,
		TOTPSetupPending:   totpSetupPending,
	}
	if err := deps.SessionRepo.Create(ctx, session); err != nil {
		writeError(w, "internal_error", "failed to create session")
		return
	}
	if mustChange && !user.MustChangePassword && deps.UserRepo != nil {
		// 过期密码：落库 must_change_password，让中间件把后续请求限制在改密接口。
		if err := deps.UserRepo.UpdatePassword(ctx, user.ID, user.PasswordHash, true); err != nil {
			log.Printf("mark expired password failed: %v", err)
		}
	}

	attempt.UserID = user.ID
	attempt.Success = true
	recordConsoleLoginEvent(r, deps, attempt)
	if deps.LoginHistoryRepo != nil {
		if err := deps.LoginHistoryRepo.UpdateUserLastLogin(ctx, user.ID); err != nil {
			log.Printf("update last login failed: %v", err)
		}
	}

	// 同时下发会话 cookie:供 <img>/下载等无法带 Authorization 头的同源 GET 鉴权。
	// HttpOnly+Secure+SameSite=Strict(防 CSRF);Authorization 头仍是 API 调用主路径。
	// Secure 可经 SESSION_COOKIE_SECURE=false 关闭:HTTP 明文部署(如内网/tailscale)下,
	// Secure cookie 会被浏览器丢弃,导致 <img>/blob 留证图片鉴权失败(401)看不到图。默认 true(安全)。
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("SESSION_COOKIE_SECURE") != "false",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   policy.SessionAbsoluteHours * 3600,
	})

	resp := consoleLoginResponse{
		LoginResponse: types.LoginResponse{
			Token: sessionID,
			User: types.UserInfo{
				ID:                     user.ID,
				Username:               user.Username,
				Role:                   user.Role,
				TenantID:               user.TenantID,
				PasswordChangeRequired: mustChange,
			},
			Expires:                strconv.Itoa(policy.SessionAbsoluteHours) + "h",
			PasswordChangeRequired: mustChange,
		},
		PasswordExpired:    passwordExpired,
		TOTPSetupRequired:  totpSetupPending,
		IdleTimeoutSeconds: policy.SessionIdleMinutes * 60,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// consoleLoginRequest 在既有登录请求上追加双因素验证码（向后兼容：未开启 TOTP 的账号不需要）。
type consoleLoginRequest struct {
	types.LoginRequest
	TOTPCode    string `json:"totp_code,omitempty"`
	NewPassword string `json:"new_password,omitempty"`
}

// consoleLoginResponse 在既有登录响应上追加 W3 字段，旧前端忽略即可。
type consoleLoginResponse struct {
	ChatTicket string `json:"chat_ticket,omitempty"`
	types.LoginResponse
	PasswordExpired    bool `json:"password_expired,omitempty"`
	TOTPSetupRequired  bool `json:"totp_setup_required,omitempty"`
	IdleTimeoutSeconds int  `json:"idle_timeout_seconds"`
}

func encryptTOTPSecret(secret string) (string, error) {
	ciphertext, _, err := secrets.EncryptProviderSecret(secret)
	return ciphertext, err
}

func decryptTOTPSecret(ciphertext string) (string, error) {
	return secrets.DecryptProviderSecret(ciphertext)
}

type loginStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *loginStatusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *loginStatusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}
