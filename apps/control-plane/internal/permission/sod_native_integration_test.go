package permission

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

func TestMergedNativeAndIntegrationRoutesPreserveOfficerDuties(t *testing.T) {
	groups := []struct {
		class             SoDClass
		routes            []string
		security, auditor SoDDecision
	}{
		{SoDSecurityRecordRead, []string{
			"GET /admin/v1/agent/events", "GET /admin/v1/agent/native-events", "GET /admin/v1/agent/sessions", "GET /admin/v1/agent/overview",
			"GET /admin/v1/agent/unified-assets/{id}/history", "GET /admin/v1/agent/principals/{id}/delegation-tree", "GET /admin/v1/agent/approvals",
			"GET /admin/v1/integration/audit-events", "GET /admin/v1/integration/enforcement-status",
		}, SoDAllow, SoDAllow},
		{SoDSecurityConfigRead, []string{"GET /admin/v1/agent/approval-rules", "GET /admin/v1/agent/approval-exceptions", "GET /admin/v1/agent/policy-bundles/current", "GET /admin/v1/integration/agent-policies"}, SoDAllow, SoDDeny},
		{SoDSecurityWrite, []string{
			"POST /admin/v1/agent/approval-rules", "POST /admin/v1/agent/approvals/{id}/resolve", "POST /admin/v1/agent/approval-exceptions", "PUT /admin/v1/agent/endpoints/{id}/mode",
			"PUT /admin/v1/agent/unified-assets/{id}/catalog", "POST /admin/v1/integration/agent-policies", "PUT /admin/v1/integration/agent-policies/{id}",
		}, SoDAllow, SoDDeny},
		{SoDSystem, []string{
			"POST /admin/v1/agent/enrollment-tokens", "GET /admin/v1/agent/enrollment-tokens", "POST /admin/v1/agent/endpoints/{id}/rotate-token",
			"POST /admin/v1/agent/principals", "POST /admin/v1/agent/principals/{id}/rotate-token", "POST /admin/v1/agent/kubernetes/clusters",
			"POST /admin/v1/agent/intent-tasks", "POST /admin/v1/agent/intent-tasks/{id}/revoke", "PUT /admin/v1/agent/unified-assets/{id}/ownership",
			"POST /admin/v1/integration/agent-credentials", "POST /admin/v1/integration/agent-credentials/{id}/rotate", "POST /admin/v1/integration/agent-credentials/{id}/revoke",
			"GET /admin/v1/users", "PUT /admin/v1/system/settings",
		}, SoDDeny, SoDDeny},
		{SoDDirectoryRead, []string{"GET /admin/v1/agent/principals", "GET /admin/v1/integration/projects", "GET /admin/v1/integration/upstreams", "GET /admin/v1/integration/agent-credentials"}, SoDAllow, SoDDeny},
		{SoDCommon, []string{"GET /admin/v1/system/product"}, SoDAllow, SoDAllow},
	}
	for _, group := range groups {
		for _, route := range group.routes {
			method, path, _ := strings.Cut(route, " ")
			class, registered := sodRouteTable[route]
			if !registered || class != group.class {
				t.Errorf("%s: explicit class=%q registered=%v want=%q", route, class, registered, group.class)
				continue
			}
			if got := SoDClassFor(method, path); got != group.class {
				t.Errorf("%s lookup=%q", route, got)
			}
			if got := DecideSoD("security_officer", class, false); got != group.security {
				t.Errorf("security officer %s=%v want=%v", route, got, group.security)
			}
			if got := DecideSoD("auditor", class, false); got != group.auditor {
				t.Errorf("auditor %s=%v want=%v", route, got, group.auditor)
			}
			if got := DecideSoD("platform_connector", class, false); got != SoDDefer {
				t.Errorf("service %s must retain sealed RBAC decision, got %v", route, got)
			}
		}
	}
}

func TestNativeMachineRoutesKeepMachineAuthenticationBoundary(t *testing.T) {
	for _, route := range []string{
		"POST /admin/v1/internal/agent/heartbeat", "POST /admin/v1/internal/agent/events", "POST /admin/v1/internal/agent/identity-events",
		"POST /admin/v1/internal/agent/probe-reports", "POST /admin/v1/internal/agent/kubernetes/snapshot-runs", "POST /admin/v1/internal/agent/kubernetes/snapshots",
	} {
		if class, ok := sodRouteTable[route]; !ok || class != SoDCommon {
			t.Errorf("machine observation %s class=%q registered=%v", route, class, ok)
		}
	}
	for _, route := range []string{
		"POST /admin/v1/internal/agent/register", "POST /admin/v1/internal/agent/decide", "POST /admin/v1/internal/agent/intent-authorizations/resolve", "GET /admin/v1/internal/agent/policy-bundle",
		"POST /admin/v1/agent/authorize", "POST /admin/v1/agent/approval-claims", "POST /admin/v1/agent/delegations",
	} {
		if class, ok := sodRouteTable[route]; !ok || class != SoDSystem {
			t.Errorf("machine authority %s class=%q registered=%v", route, class, ok)
		}
	}
}

func TestNativeSoDHTTPAndSealedServiceCannotGainGenericAuthority(t *testing.T) {
	routes := []struct{ method, pattern, path string }{
		{"GET", "/admin/v1/agent/native-events", "/admin/v1/agent/native-events"},
		{"POST", "/admin/v1/agent/approval-rules", "/admin/v1/agent/approval-rules"},
		{"POST", "/admin/v1/agent/principals", "/admin/v1/agent/principals"},
		{"POST", "/admin/v1/integration/agent-credentials", "/admin/v1/integration/agent-credentials"},
		{"GET", "/admin/v1/integration/audit-events", "/admin/v1/integration/audit-events"},
		{"POST", "/admin/v1/internal/agent/events", "/admin/v1/internal/agent/events"},
		{"GET", "/admin/v1/users", "/admin/v1/users"},
		{"PUT", "/admin/v1/system/settings", "/admin/v1/system/settings"},
	}
	for _, dryRun := range []bool{false, true} {
		for _, role := range []string{"security_officer", "auditor", "platform_connector"} {
			router := chi.NewRouter()
			router.Group(func(r chi.Router) {
				r.Use(func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						u := &repository.User{ID: "actor", Role: role, TenantID: "tenant-one"}
						next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), auth.UserKey, u)))
					})
				})
				r.Use(SoDGuard(nil))
				r.Use(func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						if role == "platform_connector" {
							Middleware(nil, nil, dryRun)(next).ServeHTTP(w, req)
							return
						}
						next.ServeHTTP(w, req)
					})
				})
				for _, route := range routes {
					r.Method(route.method, route.pattern, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						if auth.GetUser(req.Context()).TenantID != "tenant-one" {
							t.Error("SoD changed tenant context")
						}
						w.WriteHeader(204)
					}))
				}
			})
			for _, route := range routes {
				want := 204
				if role == "platform_connector" {
					if route.pattern != "/admin/v1/integration/audit-events" && route.pattern != "/admin/v1/integration/agent-credentials" {
						want = 403
					}
				} else {
					if route.pattern == "/admin/v1/agent/principals" || route.pattern == "/admin/v1/integration/agent-credentials" || route.pattern == "/admin/v1/users" || route.pattern == "/admin/v1/system/settings" {
						want = 403
					}
					if role == "auditor" && route.pattern == "/admin/v1/agent/approval-rules" {
						want = 403
					}
				}
				w := httptest.NewRecorder()
				router.ServeHTTP(w, httptest.NewRequest(route.method, route.path+"?tenant_id=foreign-tenant", nil))
				if w.Code != want {
					t.Errorf("role=%s dry_run=%v %s %s got=%d want=%d", role, dryRun, route.method, route.path, w.Code, want)
				}
			}
		}
	}
}
