package permission

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/jackc/pgx/v5/pgxpool"
)

// skipPaths are paths that bypass permission middleware
var skipPaths = map[string]bool{
	"/admin/v1/captcha":       true,
	"/admin/v1/login":         true,
	"/admin/v1/service-login": true,
	"/health":                 true,
}

// skipPathPrefixes are path prefixes that bypass permission middleware
var skipPathPrefixes = []string{
	"/admin/v1/me",
	"/admin/v1/internal/",
}

// Middleware returns a chi middleware that enforces RBAC.
// When dryRun=true, denied requests are allowed through but logged to security_events.
// When dryRun=false (enforce mode), denied requests return HTTP 403.
func Middleware(checker *Checker, db *pgxpool.Pool, dryRun bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			// Service identities always fail closed, including dry-run and internal paths.
			if user := auth.GetUser(r.Context()); user != nil && user.Role == "platform_connector" {
				if !connectorRouteAllowed(r) {
					writeForbidden(w, "permission_denied", "route is outside connector capabilities")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Skip exempted paths
			if skipPaths[path] {
				next.ServeHTTP(w, r)
				return
			}
			for _, prefix := range skipPathPrefixes {
				if strings.HasPrefix(path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}

			user := auth.GetUser(r.Context())
			if user == nil {
				// Should not happen (auth middleware runs first), but be safe
				writeForbidden(w, "permission_denied", "authentication required")
				return
			}
			// Logout deletes only the caller's authenticated session; it is
			// self-service, not a users:read capability. Keep the method and
			// path exact so GET and additional logout paths still use RBAC.
			if r.Method == http.MethodPost && path == "/admin/v1/logout" {
				next.ServeHTTP(w, r)
				return
			}
			// GET system settings is safe for every authenticated user because the handler
			// returns only security_execution_mode unless the caller is a full administrator.
			if r.Method == http.MethodGet && path == "/admin/v1/system/settings" {
				next.ServeHTTP(w, r)
				return
			}

			// Officer roles granted by SoDGuard on their own duties skip the
			// legacy resource matrix: the matrix predates the three-officer roles.
			if SoDAllowed(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}

			// Resolve required permission for this route
			resolved := Resolve(r)

			// Determine scope ID: if tenant scope, use user's tenant_id
			scopeID := resolved.ScopeID
			if resolved.ScopeType == "tenant" || scopeID == "" {
				scopeID = user.TenantID
			}

			// Check permission
			var allowed bool
			var checkErr error

			if resolved.RequirePlatformAdmin {
				// Unregistered path: only platform_admin grants access
				allowed, checkErr = checker.HasPermission(r.Context(), user.ID, user.TenantID, "tenant", user.TenantID, "users", "write")
				// platform_admin check: need a special check
				if checkErr == nil && !allowed {
					// Try direct platform_admin check
					allowed, checkErr = checkIsPlatformAdmin(r.Context(), checker, user.ID, user.TenantID)
				}
			} else {
				allowed, checkErr = checker.HasPermission(r.Context(), user.ID, user.TenantID, resolved.ScopeType, scopeID, resolved.Resource, resolved.Action)
			}

			if checkErr != nil {
				log.Printf("[permission] checker error for %s %s: %v", r.Method, path, checkErr)
				if dryRun {
					// fail-open in dryrun
					next.ServeHTTP(w, r)
					return
				}
				// fail-close in enforce
				writeForbidden(w, "permission_check_failed", "permission check failed")
				return
			}

			if allowed {
				next.ServeHTTP(w, r)
				return
			}

			// Permission denied
			detail := fmt.Sprintf("user=%s path=%s method=%s resource=%s action=%s scope=%s:%s",
				user.ID, path, r.Method, resolved.Resource, resolved.Action, resolved.ScopeType, scopeID)

			if dryRun {
				// dryrun: allow but log security event
				go logDryrunBlocked(context.Background(), db, user.ID, user.TenantID, r, detail)
				next.ServeHTTP(w, r)
				return
			}

			// enforce: return 403 + log audit
			go logPermissionDenied(context.Background(), db, user.ID, r, detail)
			writeForbidden(w, "permission_denied", "insufficient permissions for this operation")
		})
	}
}

func checkIsPlatformAdmin(ctx context.Context, checker *Checker, userID, tenantID string) (bool, error) {
	grants, err := checker.getGrantsForUser(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	for _, g := range grants {
		if roles.IsSystemAdmin(g.Role) {
			return true, nil
		}
	}
	return false, nil
}

func logDryrunBlocked(ctx context.Context, db *pgxpool.Pool, userID, tenantID string, r *http.Request, detail string) {
	if db == nil {
		return
	}
	id := generateID()
	_, err := db.Exec(ctx, `
		INSERT INTO security_events (id, request_id, tenant_id, project_id, user_id, event_type, severity, action_taken, matched_summary, principal_key)
		VALUES ($1, $2, $3, 'project_default', $4, 'rbac_dryrun_blocked', 'medium', 'logged', $5, NULLIF($4, ''))
		ON CONFLICT DO NOTHING
	`, id, getRequestID(r), tenantID, userID, jsonMarshal(map[string]string{
		"path":   r.URL.Path,
		"method": r.Method,
		"detail": detail,
	}))
	if err != nil {
		log.Printf("[permission] failed to log dryrun event: %v", err)
	}
}

func logPermissionDenied(ctx context.Context, db *pgxpool.Pool, userID string, r *http.Request, detail string) {
	if db == nil {
		return
	}
	id := generateID()

	// audit_operations.target_id is varchar(64); deep evidence routes exceed it
	// (e.g. /admin/v1/audit/access-retention/{id}/artifacts/{id}/original) and
	// the denied-access audit row was being silently lost (issue 2026-10-01).
	// The full path is already preserved in action_detail.path, so the
	// denormalized copy is truncated here to guarantee the record persists.
	deniedTarget := truncateAuditTarget(r.URL.Path)
	_, err := db.Exec(ctx, `
		INSERT INTO audit_operations (id, user_id, action_type, action_detail, target_type, target_id, ip_address)
		VALUES ($1, $2, 'permission.denied', $3, 'http', $4, $5)
	`, id, userID, jsonMarshal(map[string]string{
		"path":   r.URL.Path,
		"method": r.Method,
		"detail": detail,
	}), deniedTarget, r.RemoteAddr)
	if err != nil {
		log.Printf("[permission] failed to log denied audit: %v", err)
	}
}

func writeForbidden(w http.ResponseWriter, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func getRequestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); id != "" {
		return id
	}
	return generateID()
}

func generateID() string {
	return fmt.Sprintf("perm_%d", time.Now().UnixNano())
}

// truncateAuditTarget caps an audit target reference at 64 bytes so it always
// fits audit_operations.target_id (varchar(64)). Slicing never splits a UTF-8
// rune: invalid tails are dropped because PostgreSQL would reject the row as
// containing invalid UTF-8, which is exactly the failure this guard prevents.
func truncateAuditTarget(path string) string {
	const maxLen = 64
	if len(path) <= maxLen {
		return path
	}
	out := path[:maxLen]
	for len(out) > 0 && !utf8.ValidString(out) {
		out = out[:len(out)-1]
	}
	return out
}

func jsonMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
