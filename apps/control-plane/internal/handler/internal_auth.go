package handler

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

const (
	InternalAPISecretHeader       = "X-JJDGuard-Internal-Token"
	LegacyInternalAPISecretHeader = "X-NewAPI-Internal-Token"
)

func InternalAPIMiddleware(secret string, deps *Dependencies) func(http.Handler) http.Handler {
	return internalSharedSecretMiddleware(secret, false, deps, "control-plane.internal", false)
}

func EvalIntegrationAPIMiddleware(secret string, deps *Dependencies) func(http.Handler) http.Handler {
	return internalSharedSecretMiddleware(secret, true, deps, "control-plane.eval-integration", true)
}

// PortalIntegrationAPIMiddleware protects the separately credentialed portal channel.
func PortalIntegrationAPIMiddleware(secret string, deps *Dependencies) func(http.Handler) http.Handler {
	return internalSharedSecretMiddleware(secret, true, deps, "control-plane.portal-integration", true)
}

func internalSharedSecretMiddleware(secret string, allowBearer bool, deps *Dependencies, service string, resolveTenant bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if allowBearer && denyNativeSealedLegacySession(w, r, deps, secret) {
				return
			}
			if secret == "" {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "internal_auth_not_configured", "internal API secret is not configured")
				return
			}

			token, ok := criticalHeaderValue(w, r, deps, service, "internal_token", InternalAPISecretHeader, LegacyInternalAPISecretHeader)
			if !ok {
				return
			}
			if token == "" && allowBearer {
				token = bearerToken(r)
			}
			if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(secret)) != 1 {
				writeUnauthorized(w, "invalid internal token")
				return
			}

			if resolveTenant {
				tenantID, ok := criticalHeaderValue(w, r, deps, service, "tenant_id", jjdguardTenantHeader, legacyTenantHeader)
				if !ok {
					return
				}
				if tenantID != "" {
					r.Header.Set(jjdguardTenantHeader, tenantID)
					r.Header.Del(legacyTenantHeader)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(r *http.Request) string {
	authHeader := strings.Trim(r.Header.Get("Authorization"), " \t")
	if len(authHeader) < len("Bearer ") || !strings.EqualFold(authHeader[:len("Bearer")], "Bearer") {
		return ""
	}
	return strings.Trim(authHeader[len("Bearer"):], " \t")
}
