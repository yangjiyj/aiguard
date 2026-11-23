package permission

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestReadModelRoutesRegistered asserts the active read-model routes are in the
// RBAC routeTable with the expected permissions. Without registration the
// runtime falls back to platform_admin-only and tenant_admin gets 403.
func TestReadModelRoutesRegistered(t *testing.T) {
	cases := []struct {
		route    string
		resource string
		action   string
	}{
		{"GET /admin/v1/budgets/keys/{key_id}/readmodel", "saving_metrics", "read"},
		{"GET /admin/v1/service-health/readmodel", "security_events", "read"},
	}
	for _, tc := range cases {
		perm, ok := routeTable[tc.route]
		if !ok {
			t.Fatalf("route %s missing from routeTable", tc.route)
		}
		if perm.Resource != tc.resource || perm.Action != tc.action {
			t.Fatalf("route %s = %s/%s, want %s/%s",
				tc.route, perm.Resource, perm.Action, tc.resource, tc.action)
		}
		if perm.ScopeType != "tenant" {
			t.Fatalf("route %s scope = %s, want tenant", tc.route, perm.ScopeType)
		}
	}
}

// TestResolveReadModelRoutes exercises Resolve() through the chi route
// pattern path (the same path a mounted router takes at runtime) and proves
// the routes do not fall into the platform_admin-only fallback.
func TestResolveReadModelRoutes(t *testing.T) {
	cases := []struct {
		pattern  string
		path     string
		resource string
		action   string
	}{
		{"/admin/v1/budgets/keys/{key_id}/readmodel", "/admin/v1/budgets/keys/key-123/readmodel", "saving_metrics", "read"},
		{"/admin/v1/service-health/readmodel", "/admin/v1/service-health/readmodel", "security_events", "read"},
	}
	for _, tc := range cases {
		var got ResolvedPermission
		r := chi.NewRouter()
		r.Get(tc.pattern, func(w http.ResponseWriter, req *http.Request) {
			got = Resolve(req)
		})
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", tc.path, nil))
		if got.RequirePlatformAdmin {
			t.Fatalf("Resolve(%s) fell back to platform_admin-only; route not registered", tc.path)
		}
		if got.Resource != tc.resource || got.Action != tc.action {
			t.Fatalf("Resolve(%s) = %s/%s, want %s/%s", tc.path, got.Resource, got.Action, tc.resource, tc.action)
		}
		if got.ScopeType != "tenant" {
			t.Fatalf("Resolve(%s) scope = %s, want tenant", tc.path, got.ScopeType)
		}
	}
}

func TestRetiredBillingManagementRoutesStayUnregistered(t *testing.T) {
	for _, route := range []string{
		"GET /admin/v1/billing/channel-margins",
		"GET /admin/v1/billing/prices/unpriced",
		"GET /admin/v1/billing/reconciliation/readmodel",
		"GET /admin/v1/billing/holiday-calendar",
		"GET /admin/v1/billing/exceptions",
		"POST /admin/v1/billing/exceptions/{id}/cache-true-up",
	} {
		if _, exists := routeTable[route]; exists {
			t.Errorf("retired route still has an RBAC mapping: %s", route)
		}
		if _, exists := sodRouteTable[route]; exists {
			t.Errorf("retired route still has a SoD classification: %s", route)
		}
	}
}
