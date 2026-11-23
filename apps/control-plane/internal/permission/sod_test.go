package permission

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

func TestDecideSoDMatrix(t *testing.T) {
	type want map[SoDClass]SoDDecision
	all := []SoDClass{SoDCommon, SoDAuditRead, SoDAuditExport, SoDLoginHistory, SoDEvidence,
		SoDAlertHandle, SoDSecurityRecordRead, SoDSecurityConfigRead, SoDSecurityWrite,
		SoDDirectoryRead, SoDSystem}
	cases := map[string]want{
		// Decision 2026-10-01: the system administrator sees everything,
		// audit data and retained content evidence included.
		"platform_admin": {SoDAuditRead: SoDAllow, SoDAuditExport: SoDAllow, SoDLoginHistory: SoDAllow, SoDEvidence: SoDAllow},
		"admin":          {SoDAuditRead: SoDAllow, SoDAuditExport: SoDAllow, SoDLoginHistory: SoDAllow, SoDEvidence: SoDAllow},
		"security_officer": {
			SoDCommon: SoDAllow, SoDSecurityRecordRead: SoDAllow, SoDSecurityConfigRead: SoDAllow,
			SoDSecurityWrite: SoDAllow, SoDAlertHandle: SoDAllow, SoDEvidence: SoDAllow, SoDDirectoryRead: SoDAllow,
			SoDAuditRead: SoDDeny, SoDAuditExport: SoDDeny, SoDLoginHistory: SoDDeny, SoDSystem: SoDDeny,
		},
		"auditor": {
			SoDCommon: SoDAllow, SoDAuditRead: SoDAllow, SoDAuditExport: SoDAllow, SoDLoginHistory: SoDAllow,
			SoDEvidence: SoDAllow, SoDSecurityRecordRead: SoDAllow,
			SoDAlertHandle: SoDDeny, SoDSecurityConfigRead: SoDDeny, SoDSecurityWrite: SoDDeny,
			SoDDirectoryRead: SoDDeny, SoDSystem: SoDDeny,
		},
		"tenant_owner": {SoDAuditRead: SoDDeny, SoDAuditExport: SoDDeny},
		"developer":    {SoDAuditRead: SoDDeny, SoDAuditExport: SoDDeny},
		"dept_manager": {SoDAuditRead: SoDDeny, SoDAuditExport: SoDDeny},
	}
	for role, w := range cases {
		for _, c := range all {
			exp, ok := w[c]
			if !ok {
				exp = SoDDefer
			}
			if got := DecideSoD(role, c, false); got != exp {
				t.Errorf("DecideSoD(%s,%s)=%v want %v", role, c, got, exp)
			}
		}
	}
	// The dashboard aggregate count keeps working for the system administrator,
	// now with full evidence access rather than counts-only.
	if got := DecideSoD("platform_admin", SoDEvidence, true); got != SoDAllow {
		t.Errorf("dashboard count for platform_admin = %v, want allow", got)
	}
	if got := DecideSoD("platform_admin", SoDAuditRead, true); got != SoDAllow {
		t.Errorf("system admin must read audit data, got %v", got)
	}
}

func TestSoDClassForUnknownRouteIsSystem(t *testing.T) {
	if c := SoDClassFor("GET", "/admin/v1/does-not-exist"); c != SoDSystem {
		t.Fatalf("unknown route class = %s, want system", c)
	}
	if c := SoDClassFor("GET", "/admin/v1/system/audit-operations"); c != SoDAuditRead {
		t.Fatalf("audit-operations class = %s", c)
	}
}

func sodRouter(role string) http.Handler {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				u := &repository.User{ID: "u1", Role: role}
				next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), auth.UserKey, u)))
			})
		})
		r.Use(SoDGuard(nil))
		ok := func(w http.ResponseWriter, req *http.Request) {
			if SoDAllowed(req.Context()) {
				w.Header().Set("X-SoD", "allow")
			}
			w.WriteHeader(http.StatusOK)
		}
		r.Get("/admin/v1/system/audit-operations", ok)
		r.Get("/admin/v1/audit/access-retention", ok)
		r.Get("/admin/v1/audit/access-retention/{request_id}/content", ok)
		r.Get("/admin/v1/users/{id}/login-history", ok)
		r.Get("/admin/v1/audit/login-history", ok)
		r.Post("/admin/v1/rule-sets/{id}/publish", ok)
		r.Get("/admin/v1/users", ok)
		r.Get("/admin/v1/system/settings", ok)
		r.Put("/admin/v1/system/settings", ok)
	})
	return r
}

func TestSoDGuardHTTP(t *testing.T) {
	cases := []struct {
		role, method, path string
		code               int
		allowMark          bool
	}{
		{"platform_admin", "GET", "/admin/v1/system/audit-operations", 200, true},
		{"admin", "GET", "/admin/v1/system/audit-operations", 200, true},
		{"platform_admin", "GET", "/admin/v1/audit/access-retention", 200, true},
		{"platform_admin", "GET", "/admin/v1/audit/access-retention?summary_only=true&summary_detail=counts", 200, true},
		{"platform_admin", "GET", "/admin/v1/audit/access-retention/r1/content", 200, true},
		{"platform_admin", "GET", "/admin/v1/users/u2/login-history", 200, true},
		{"platform_admin", "GET", "/admin/v1/audit/login-history", 200, true},
		{"platform_admin", "GET", "/admin/v1/users", 200, false},
		{"auditor", "GET", "/admin/v1/system/audit-operations", 200, true},
		{"auditor", "GET", "/admin/v1/audit/login-history", 200, true},
		{"auditor", "GET", "/admin/v1/users", 403, false},
		{"auditor", "GET", "/admin/v1/system/settings", 200, true}, // common: version/branding read
		{"security_officer", "POST", "/admin/v1/rule-sets/r1/publish", 200, true},
		{"auditor", "POST", "/admin/v1/rule-sets/r1/publish", 403, false},
		{"security_officer", "PUT", "/admin/v1/system/settings", 403, false},
		{"platform_admin", "PUT", "/admin/v1/system/settings", 200, false},
		{"security_officer", "GET", "/admin/v1/system/audit-operations", 403, false},
		{"security_officer", "GET", "/admin/v1/users", 403, false},
		{"developer", "GET", "/admin/v1/system/audit-operations", 403, false},
		{"tenant_owner", "GET", "/admin/v1/system/audit-operations", 403, false},
		{"tenant_owner", "GET", "/admin/v1/users", 200, false},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		sodRouter(c.role).ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != c.code {
			t.Errorf("%s %s %s: code %d want %d", c.role, c.method, c.path, rec.Code, c.code)
		}
		if got := rec.Header().Get("X-SoD") == "allow"; got != c.allowMark {
			t.Errorf("%s %s %s: allow mark %v want %v", c.role, c.method, c.path, got, c.allowMark)
		}
	}
}

// Every protected route registered in cmd/server/main.go must have an explicit
// SoD class, otherwise a new audit endpoint could silently fall into "system".
func TestMergedRoutesHaveExpectedSoDClasses(t *testing.T) {
	cases := map[string]SoDClass{
		"GET /admin/v1/me/totp":                        SoDCommon,
		"POST /admin/v1/me/totp/setup":                 SoDCommon,
		"POST /admin/v1/me/totp/enable":                SoDCommon,
		"POST /admin/v1/users/{id}/unlock-login":       SoDSystem,
		"POST /admin/v1/users/{id}/reset-totp":         SoDSystem,
		"GET /admin/v1/system/login-security":          SoDSystem,
		"PUT /admin/v1/system/login-security":          SoDSystem,
		"GET /admin/v1/system/portal-login-baseline":   SoDSystem,
		"GET /admin/v1/security/block-records/export":  SoDAuditExport,
		"GET /admin/v1/system/audit-operations/export": SoDAuditExport,
		"GET /admin/v1/alerts/inbox/export":            SoDAuditExport,
		"POST /admin/v1/alert-groups/batch-status":     SoDAlertHandle,
	}
	for route, want := range cases {
		if got := sodRouteTable[route]; got != want {
			t.Errorf("%s: class %q want %q", route, got, want)
		}
	}
}

func TestSoDRouteTableCoversEveryProtectedRoute(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "server", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	s := string(src)
	start := regexp.MustCompile(`r\.Use\(permission\.SoDGuard\(db\)\)`).FindStringIndex(s)
	if start == nil {
		t.Fatal("SoDGuard is not mounted in main.go")
	}
	body := s[start[1]:]
	re := regexp.MustCompile(`\br\.(Get|Post|Put|Patch|Delete)\("(/admin/v1/[^"]+)"`)
	seen := 0
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		key := map[string]string{"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE"}[m[1]] + " " + m[2]
		if _, ok := sodRouteTable[key]; !ok {
			t.Errorf("route %q has no SoD class in sod_routes.go", key)
		}
		seen++
	}
	if seen < 300 {
		t.Fatalf("parsed only %d protected routes; main.go layout changed?", seen)
	}
}
