package permission

import (
	"context"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SoDClass is the separation-of-duties class of a protected route.
type SoDClass string

const (
	SoDCommon             SoDClass = "common"               // every authenticated user
	SoDAuditRead          SoDClass = "audit"                // operation audit, audit chain
	SoDAuditExport        SoDClass = "audit_export"         // audit/evidence export
	SoDLoginHistory       SoDClass = "login_history"        // per-user login history
	SoDEvidence           SoDClass = "evidence"             // raw retained content evidence
	SoDRawEvidence        SoDClass = "raw_evidence"         // pre-masking original text (system admin + security officer only)
	SoDAlertHandle        SoDClass = "alert_handle"         // alert disposition changes
	SoDSecurityRecordRead SoDClass = "security_record_read" // alerts, blocks, tool/agent audit records
	SoDSecurityConfigRead SoDClass = "security_config_read" // security policy configuration reads
	SoDSecurityWrite      SoDClass = "security_write"       // security policy changes
	SoDDirectoryRead      SoDClass = "directory_read"       // teams/projects/keys/models lists for policy scoping
	SoDSystem             SoDClass = "system"               // users, resources, billing, system configuration
)

// SoDDecision is the guard verdict for one request.
type SoDDecision int

const (
	// SoDDefer leaves the decision to the RBAC matrix and handler checks.
	SoDDefer SoDDecision = iota
	// SoDAllow grants access even if handler role checks predate the role
	// (only used for the two new officer roles on their own duties).
	SoDAllow
	// SoDDeny rejects the request with 403.
	SoDDeny
)

// SoDClassFor returns the class of a route pattern; unknown routes are system.
func SoDClassFor(method, pattern string) SoDClass {
	if c, ok := sodRouteTable[method+" "+pattern]; ok {
		return c
	}
	return SoDSystem
}

// isDashboardEvidenceCount recognises the dashboard/overview aggregate call
// (GET /audit/access-retention?summary_only=true&summary_detail=counts): it returns
// counts only, never content, so the system administrator's home page keeps working.
func isDashboardEvidenceCount(r *http.Request, pattern string) bool {
	if r.Method != http.MethodGet || pattern != "/admin/v1/audit/access-retention" {
		return false
	}
	q := r.URL.Query()
	return q.Get("summary_only") == "true" && q.Get("summary_detail") == "counts"
}

// DecideSoD applies the three-officer separation of duties.
//
// Decision 2026-10-01: the system administrator sees everything — audit data,
// exports, login history and raw retained content evidence included — so the
// audit/evidence classes are SoDAllow for platform_admin instead of denied.
// The security officer and auditor boundaries are unchanged.
func DecideSoD(role string, class SoDClass, dashboardCount bool) SoDDecision {
	switch {
	case roles.IsSystemAdmin(role):
		switch class {
		case SoDAuditRead, SoDAuditExport, SoDLoginHistory, SoDEvidence, SoDRawEvidence:
			return SoDAllow
		}
		return SoDDefer
	case roles.IsSecurityOfficer(role):
		switch class {
		case SoDCommon, SoDSecurityRecordRead, SoDSecurityConfigRead, SoDSecurityWrite,
			SoDAlertHandle, SoDEvidence, SoDRawEvidence, SoDDirectoryRead:
			return SoDAllow
		}
		return SoDDeny
	case roles.IsAuditor(role):
		switch class {
		case SoDCommon, SoDAuditRead, SoDAuditExport, SoDLoginHistory, SoDEvidence, SoDSecurityRecordRead:
			return SoDAllow
		}
		return SoDDeny
	default:
		// Audit data is reserved for the auditor. These handlers never had a role
		// check, so every other role is denied explicitly here.
		switch class {
		case SoDAuditRead, SoDAuditExport, SoDRawEvidence:
			return SoDDeny
		}
		return SoDDefer
	}
}

type sodAllowKey struct{}

// SoDAllowed reports whether the SoD guard granted this request (officer role on
// its own duty). Handler helpers may use it to accept the new roles.
func SoDAllowed(ctx context.Context) bool {
	v, _ := ctx.Value(sodAllowKey{}).(bool)
	return v
}

// WithSoDAllowed marks a context as SoD-granted (tests and middleware).
func WithSoDAllowed(ctx context.Context) context.Context {
	return context.WithValue(ctx, sodAllowKey{}, true)
}

// SoDGuard enforces the separation of duties. Unlike the RBAC Middleware it is
// always enforcing (it does not follow UAG_RBAC_ENFORCE dry-run), because the
// three-officer split is a hard compliance requirement. It must be installed
// inside the chi router group so the route pattern is resolved; it uses
// chi's route matching to find the pattern before the handler runs.
func SoDGuard(db *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := auth.GetUser(r.Context())
			if user == nil {
				next.ServeHTTP(w, r)
				return
			}
			pattern := routePattern(r)
			if pattern == "" {
				next.ServeHTTP(w, r)
				return
			}
			class := SoDClassFor(r.Method, pattern)
			switch DecideSoD(user.Role, class, isDashboardEvidenceCount(r, pattern)) {
			case SoDDeny:
				go logPermissionDenied(context.Background(), db, user.ID, r,
					"sod_denied role="+user.Role+" class="+string(class)+" route="+r.Method+" "+pattern)
				writeForbidden(w, "separation_of_duties", "this role is not permitted to access this function")
				return
			case SoDAllow:
				r = r.WithContext(WithSoDAllowed(r.Context()))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// routePattern resolves the chi pattern for r. Middlewares registered with Use run
// before routing completes, so resolve it by matching against the router itself.
func routePattern(r *http.Request) string {
	rctx := chi.RouteContext(r.Context())
	if rctx == nil || rctx.Routes == nil {
		return ""
	}
	tctx := chi.NewRouteContext()
	path := r.URL.RawPath
	if path == "" {
		path = r.URL.Path
	}
	if rctx.Routes.Match(tctx, r.Method, path) {
		return tctx.RoutePattern()
	}
	return ""
}
