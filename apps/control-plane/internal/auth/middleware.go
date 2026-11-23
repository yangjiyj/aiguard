package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

type sessionReader interface {
	Get(context.Context, string) (*repository.Session, error)
	Extend(context.Context, string) error
}

type userReader interface {
	GetByID(context.Context, string) (*repository.User, error)
}

// ContextKey types for auth values
type ContextKey string

const (
	SessionKey ContextKey = "session"
	UserKey    ContextKey = "user"
)

// Middleware validates admin session for protected routes
func Middleware(sessionRepo sessionReader, userRepo userReader) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for public authentication endpoints.
			if r.URL.Path == "/admin/v1/login" || r.URL.Path == "/admin/v1/captcha" || r.URL.Path == "/admin/v1/employee-login" {
				next.ServeHTTP(w, r)
				return
			}

			// 优先 Authorization 头(API 调用);无头时回退会话 cookie,让 <img>/下载等
			// 无法带头的同源 GET 也能鉴权。cookie=SameSite=Strict,仅同站 GET 携带,无 CSRF 面。
			token := ""
			if authHeader := r.Header.Get("Authorization"); authHeader != "" {
				token = extractBearerToken(authHeader)
			}
			if token == "" {
				if c, cerr := r.Cookie("session_token"); cerr == nil {
					token = strings.TrimSpace(c.Value)
				}
			}
			if token == "" {
				writeUnauthorized(w, "missing authorization")
				return
			}

			// Validate session
			session, err := sessionRepo.Get(r.Context(), token)
			if err != nil {
				// 会话存储暂时不可用（磁盘抖动、连接打满）不等于会话失效：返回 401 会让
				// 控制台把在线管理员成批登出。用 503 让前端保留登录态并稍后重试。
				writeSessionStoreUnavailable(w)
				return
			}

			if session == nil {
				writeUnauthorized(w, "invalid or expired session")
				return
			}

			// Get user details
			user, err := userRepo.GetByID(r.Context(), session.UserID)
			if err != nil {
				writeSessionStoreUnavailable(w)
				return
			}
			if user == nil {
				writeUnauthorized(w, "user not found")
				return
			}
			if session.UserID != user.ID || (session.TenantID != "" && session.TenantID != user.TenantID) {
				writeUnauthorized(w, "session identity mismatch")
				return
			}

			// Check user status
			if user.Status != "active" {
				writeUnauthorized(w, "user account is not active")
				return
			}

			admin := roles.CanLoginConsole(user.Role) && roles.CanLoginConsole(session.Role)
			connector := user.Role == "platform_connector" && session.Role == "platform_connector"
			if !admin && !connector {
				writeForbidden(w, "console_role_required", "administrator identity required; employees must sign in through Chat")
				return
			}
			// M-1：角色在会话签发之后被改过（如 auditor → tenant_admin / security_officer）时，旧会话不得继续使用，
			// 否则它会带着新角色的权限，既不用重新登录，也不用重新过 TOTP。两边都是控制台角色时要求一致，
			// 规范化口径与 roles 包一致（platform_admin 与历史别名 admin 等同）。
			if admin && !roles.SessionRoleMatches(session.Role, user.Role) {
				writeUnauthorized(w, "account role changed; please sign in again")
				return
			}

			if user.MustChangePassword && !isPasswordChangeAllowedPath(r.URL.Path) {
				writeForbidden(w, "password_change_required", "password change required before accessing other administrative functions")
				return
			}

			// 管理员被要求启用双因素但尚未绑定：会话只能用于绑定（W3 3.5）。
			if session.TOTPSetupPending && !isTOTPSetupAllowedPath(r.URL.Path) {
				writeForbidden(w, "totp_setup_required", "two-factor enrollment required before accessing other administrative functions")
				return
			}

			// A Chat-only user never reaches management/RBAC middleware. Enforce
			// this boundary before dry-run can permit otherwise denied routes.
			if user.Role == "chat_user" && !isChatUserAllowedRequest(r) {
				writeForbidden(w, "chat_only", "普通用户仅可使用 Chat；后台管理需要相应管理角色")
				return
			}

			// Set session and user in context
			ctx := r.Context()
			ctx = context.WithValue(ctx, SessionKey, session)
			ctx = context.WithValue(ctx, UserKey, user)

			// Extend session on valid access (idle expiry slides, absolute expiry never moves)
			sessionRepo.Extend(ctx, token)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetSession retrieves session from context
func GetSession(ctx context.Context) *repository.Session {
	if s := ctx.Value(SessionKey); s != nil {
		return s.(*repository.Session)
	}
	return nil
}

// GetUser retrieves user from context
func GetUser(ctx context.Context) *repository.User {
	if u := ctx.Value(UserKey); u != nil {
		return u.(*repository.User)
	}
	return nil
}

func extractBearerToken(authHeader string) string {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return parts[1]
}

// writeSessionStoreUnavailable 表示鉴权依赖的存储暂时不可用，客户端应保留登录态稍后重试。
func writeSessionStoreUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "3")
	writeAuthError(w, http.StatusServiceUnavailable, "session_store_unavailable", "服务暂时繁忙，请稍后重试")
}

func writeUnauthorized(w http.ResponseWriter, message string) {
	writeAuthError(w, http.StatusUnauthorized, "unauthorized", message)
}

func writeForbidden(w http.ResponseWriter, code, message string) {
	writeAuthError(w, http.StatusForbidden, code, message)
}

func writeAuthError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]map[string]string{
		"error": {
			"code":    code,
			"message": message,
		},
	})
}

func isPasswordChangeAllowedPath(path string) bool {
	switch path {
	case "/admin/v1/me", "/admin/v1/me/change-password", "/admin/v1/logout":
		return true
	default:
		return false
	}
}

func isTOTPSetupAllowedPath(path string) bool {
	switch path {
	case "/admin/v1/me", "/admin/v1/me/change-password", "/admin/v1/logout",
		"/admin/v1/me/totp", "/admin/v1/me/totp/setup", "/admin/v1/me/totp/enable":
		return true
	default:
		return false
	}
}

// isChatUserAllowedRequest is an exact, method-aware list of self-service
// operations. Unknown routes must fail closed, including new management APIs.
func isChatUserAllowedRequest(r *http.Request) bool {
	switch r.Method + " " + r.URL.Path {
	case "GET /admin/v1/me", "POST /admin/v1/me/change-password",
		"POST /admin/v1/logout", "POST /admin/v1/me/chat-login",
		"GET /admin/v1/me/totp", "POST /admin/v1/me/totp/setup", "POST /admin/v1/me/totp/enable":
		return true
	default:
		return false
	}
}
