package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type ChatLoginTicketStore interface {
	RevokeByUser(context.Context, string, string) error
	Issue(context.Context, string, string, string, string, ...string) (bool, error)
	Consume(context.Context, string, string, string) (*repository.ChatLoginIdentity, error)
	CurrentIdentity(context.Context, string, string, string) (*repository.ChatLoginIdentity, error)
}

// Only the server may select the personal audience during password rotation.
type personalLoginContextKey struct{}

const chatLoginTicketTTLSeconds = 60

var chatTicketPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func chatTicketHash(ticket string) string {
	sum := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(sum[:])
}
func issueChatLoginTicket(w http.ResponseWriter, r *http.Request, deps *Dependencies, user *repository.User) (string, bool) {
	w.Header().Set("Cache-Control", "private, no-store")
	if deps == nil || deps.ChatLoginTickets == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "chat_login_unavailable", "Chat 登录交接暂不可用，请管理员检查身份运行配置")
		return "", false
	}
	if user == nil || !roles.CanLoginPortal(user.Role) || user.Status != "active" || user.MustChangePassword {
		writeErrorWithStatus(w, http.StatusForbidden, "authorization_denied", "当前账号暂不能使用 Chat，请先完成密码设置并联系管理员检查账号状态")
		return "", false
	}
	if chatTicketRequiresAdminSecurity(user.Role) {
		policy := LoadConsoleLoginPolicy(r.Context(), deps.SystemRepo)
		if !ipAllowed(policy.AdminIPAllowlist, requestClientIP(r)) {
			writeErrorWithStatus(w, http.StatusForbidden, "login_ip_not_allowed", "当前来源 IP 不允许管理员登录")
			return "", false
		}
		if deps.ConsoleSecurity == nil {
			writeErrorWithStatus(w, http.StatusForbidden, "totp_setup_required", "管理员需先绑定双因素认证")
			return "", false
		}
		security, err := deps.ConsoleSecurity.Get(r.Context(), user.ID)
		if err != nil {
			writeErrorWithStatus(w, 503, "chat_login_unavailable", "无法校验管理员安全设置")
			return "", false
		}
		if !security.TOTPEnabled || security.TOTPSecretEnc == "" {
			writeErrorWithStatus(w, http.StatusForbidden, "totp_setup_required", "管理员需先绑定双因素认证")
			return "", false
		}
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		writeError(w, "internal_error", "failed to create Chat login")
		return "", false
	}
	ticket := base64.RawURLEncoding.EncodeToString(random)
	issued, err := deps.ChatLoginTickets.Issue(r.Context(), chatTicketHash(ticket), user.TenantID, user.ID, strings.TrimSuffix(strings.TrimSpace(deps.IdentityRuntimeConfig.IssuerURL), "/"), user.PasswordHash)
	if err != nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "chat_login_unavailable", "Chat 登录交接暂不可用，请稍后重试")
		return "", false
	}
	if !issued {
		writeErrorWithStatus(w, http.StatusForbidden, "chat_identity_not_ready", "此账号无法进入 Chat：请管理员检查本地身份绑定和所属部门；目录托管账号请使用员工 SSO 登录")
		return "", false
	}
	// Do not retain a previous administrator's cookie when the browser
	// changes identity through the public login entry.
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Path: "/", HttpOnly: true,
		Secure: os.Getenv("SESSION_COOKIE_SECURE") != "false", SameSite: http.SameSiteStrictMode, MaxAge: -1})
	return ticket, true
}

// CreateChatLoginTicket accepts only the authenticated user's identity. Required
// password changes finish before the restricted session can obtain this ticket.
func CreateChatLoginTicket(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ticket, ok := issueChatLoginTicket(w, r, deps, auth.GetUser(r.Context()))
		if !ok {
			return
		}
		writeJSON(w, map[string]any{"chat_ticket": ticket, "expires_in": chatLoginTicketTTLSeconds})
	}
}

// Mounted exclusively in the shared-secret portal group. No password or
// management token leaves this redemption endpoint.
func RedeemChatLoginTicket(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		var req struct {
			Ticket string `json:"ticket"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil || !chatTicketPattern.MatchString(req.Ticket) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_chat_ticket", "登录交接已失效，请重新登录")
			return
		}
		if deps == nil || deps.ChatLoginTickets == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "chat_login_unavailable", "Chat 登录交接暂不可用")
			return
		}
		identity, err := deps.ChatLoginTickets.Consume(r.Context(), chatTicketHash(req.Ticket), tenantID, strings.TrimSuffix(strings.TrimSpace(deps.IdentityRuntimeConfig.IssuerURL), "/"))
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "chat_login_unavailable", "Chat 登录交接暂不可用")
			return
		}
		if identity == nil || !identity.PortalAllowed {
			writeErrorWithStatus(w, http.StatusUnauthorized, "invalid_chat_ticket", "登录交接已失效或账号授权已变更，请重新登录")
			return
		}
		if deps.EmployeeKeyRepo != nil && identity.ChatAllowed {
			user, readErr := deps.UserRepo.GetByID(r.Context(), identity.UserID)
			project, projectErr := portalDefaultProject(r.Context(), deps, tenantID, identity.DepartmentID)
			// Personal sign-in does not depend on model/application readiness.
			// Model requests still require their independently provisioned credential.
			if readErr == nil && projectErr == nil && user != nil && user.TenantID == tenantID && user.Status == "active" && roles.CanLoginPortal(user.Role) && project != "" && deps.ProjectUserRepo != nil {
				_, _, _ = ensureEmployeeCredential(r.Context(), deps, tenantID, user, project, identity.LocalCredentialVersion)
			}
		}
		writeJSON(w, identity)
	}
}

func chatTicketRequiresAdminSecurity(role string) bool {
	switch role {
	case roles.SystemAdmin, roles.TenantAdmin, roles.SecurityOfficer, roles.Auditor, roles.DeptManager, roles.LegacyAdmin, roles.LegacyTenantOwner, roles.LegacyOperator:
		return true
	}
	return false
}
