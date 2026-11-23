package handler

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type nativeLegacySessionReader interface {
	Get(context.Context, string) (*repository.Session, error)
}

// A native sealed identity cannot acquire the independent legacy channel's
// capabilities by adding its shared secret. This only denies native sessions;
// ordinary legacy callers still authenticate through the existing middleware.
func denyNativeSealedLegacySession(w http.ResponseWriter, r *http.Request, deps *Dependencies, secret string) bool {
	// A shared-secret bearer is an independent credential, not a session lookup.
	// Still inspect every attached native cookie: bearer precedence must not hide it.
	tokens := []string{}
	if token := bearerToken(r); token != "" && (secret == "" || subtle.ConstantTimeCompare([]byte(token), []byte(secret)) != 1) {
		tokens = append(tokens, token)
	}
	for _, cookie := range r.Cookies() {
		if cookie.Name == "session_token" {
			if token := strings.TrimSpace(cookie.Value); token != "" {
				tokens = append(tokens, token)
			}
		}
	}
	for _, token := range tokens {
		if denyNativeLegacyToken(w, r, deps, token) {
			return true
		}
	}
	return false
}

func denyNativeLegacyToken(w http.ResponseWriter, r *http.Request, deps *Dependencies, token string) bool {
	if deps == nil || deps.SessionRepo == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "native_session_auth_unavailable", "native session validation unavailable")
		return true
	}
	sessions, ok := deps.SessionRepo.(nativeLegacySessionReader)
	if !ok {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "native_session_auth_unavailable", "native session validation unavailable")
		return true
	}
	session, err := sessions.Get(r.Context(), token)
	if err != nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "native_session_auth_unavailable", "native session validation unavailable")
		return true
	}
	if session == nil {
		return false
	}
	now := time.Now()
	if session.ID != token || session.UserID == "" || session.TenantID == "" || session.ExpiresAt.IsZero() || now.After(session.ExpiresAt) || (!session.AbsoluteExpiresAt.IsZero() && now.After(session.AbsoluteExpiresAt)) {
		writeUnauthorized(w, "invalid or expired session")
		return true
	}
	if deps.UserStore == nil && deps.UserRepo == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "native_session_auth_unavailable", "native session validation unavailable")
		return true
	}
	user, err := userStore(deps).GetByID(r.Context(), session.UserID)
	if err != nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "native_session_auth_unavailable", "native session validation unavailable")
		return true
	}
	if user == nil || user.ID != session.UserID || user.TenantID != session.TenantID || user.Status != "active" {
		writeUnauthorized(w, "invalid session identity")
		return true
	}
	if user.Role == "platform_connector" {
		writeErrorWithStatus(w, http.StatusForbidden, "capability_not_authorized", "connector operation is not authorized")
		return true
	}
	return false
}
