package permission

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestResolveRegisteredPaths(t *testing.T) {
	cases := []struct {
		method            string
		path              string
		wantResource      string
		wantAction        string
		wantScopeType     string
		wantPlatformAdmin bool
	}{
		{"GET", "/admin/v1/users", "users", "read", "tenant", false},
		{"POST", "/admin/v1/alert-groups/batch-status", "alert_groups", "write", "tenant", false},
		{"POST", "/admin/v1/users", "users", "write", "tenant", false},
		{"GET", "/admin/v1/teams", "teams", "read", "tenant", false},
		{"GET", "/admin/v1/projects", "projects", "read", "tenant", false},
		{"GET", "/admin/v1/roles", "users", "read", "tenant", false},
		{"POST", "/admin/v1/models/batch-delete", "models", "delete", "tenant", false},
		{"GET", "/admin/v1/audit-chain/stats", "audit_chain", "read", "tenant", false},
		{"GET", "/admin/v1/audit-chain/export", "audit_chain", "export", "tenant", false},
		{"GET", "/admin/v1/savings/summary", "saving_metrics", "read", "tenant", false},
		{"PATCH", "/admin/v1/portal-integration/customer-keys/{id}", "api_keys", "write", "tenant", false},
		{"POST", "/admin/v1/portal-integration/customer-keys/{id}/reset", "api_keys", "write", "tenant", false},
		{"GET", "/admin/v1/billing/redemptions/export", "billing", "read", "tenant", false},
		{"GET", "/admin/v1/billing/redemptions/code-fixture", "billing", "read", "tenant", false},
		{"POST", "/admin/v1/billing/redemptions/batch-disable", "billing", "write", "tenant", false},

		{"GET", "/admin/v1/billing/customers", "billing", "read", "tenant", false},
		{"GET", "/admin/v1/billing/models", "billing", "read", "tenant", false},
		{"POST", "/admin/v1/billing/customer-groups", "billing", "write", "tenant", false},
		{"PUT", "/admin/v1/billing/customers/user-1/group", "billing", "write", "tenant", false},
		{"POST", "/admin/v1/billing/prices/newapi-ratio", "billing", "write", "tenant", false},
		{"DELETE", "/admin/v1/billing/tariffs/tariff-1", "billing", "delete", "tenant", false},
		{"PUT", "/admin/v1/fx", "fx_rates", "write", "tenant", false},
		{"GET", "/admin/v1/routing-policies", "routing_policies", "read", "tenant", false},
		{"GET", "/admin/v1/model-routing", "routing_policies", "read", "tenant", false},
		{"GET", "/admin/v1/model-routing/models", "routing_policies", "read", "tenant", false},
		{"POST", "/admin/v1/model-routing/validate", "routing_policies", "read", "tenant", false},
		{"PUT", "/admin/v1/model-routing/default", "routing_policies", "write", "tenant", false},
		{"DELETE", "/admin/v1/model-routing/default", "routing_policies", "write", "tenant", false},
		{"GET", "/admin/v1/rules/pull-status", "security_events", "read", "tenant", false},
		{"GET", "/admin/v1/security/policy-assets", "security_events", "read", "tenant", false},
		{"PUT", "/admin/v1/security/policy-assets/rule-1", "security_events", "write", "tenant", false},
		{"GET", "/admin/v1/security/policies", "security_events", "read", "tenant", false},
		{"GET", "/admin/v1/security/alert-occurrences", "security_events", "read", "tenant", false},
		{"GET", "/admin/v1/security/alert-occurrences/summary", "security_events", "read", "tenant", false},
		{"GET", "/admin/v1/security/alert-occurrences/operational", "security_events", "read", "tenant", false},
		{"GET", "/admin/v1/security/alert-occurrences/operational/summary", "security_events", "read", "tenant", false},
		{"POST", "/admin/v1/security/policies", "security_events", "write", "tenant", false},
		{"GET", "/admin/v1/security/policies/capabilities", "security_events", "read", "tenant", false},
		{"POST", "/admin/v1/security/policies/preview", "security_events", "read", "tenant", false},
		{"POST", "/admin/v1/security/policies/quick-create/generate", "security_events", "write", "tenant", false},
		{"POST", "/admin/v1/security/policies/quick-create/preview", "security_events", "write", "tenant", false},
		{"POST", "/admin/v1/security/policies/batch", "security_events", "write", "tenant", false},
		{"PATCH", "/admin/v1/security/policies/rule-1", "security_events", "write", "tenant", false},
		{"GET", "/admin/v1/content-security/industry", "security_events", "read", "tenant", false},
		{"PUT", "/admin/v1/content-security/industry", "security_events", "write", "tenant", false},
		{"GET", "/admin/v1/security/reply-policy", "security_events", "read", "tenant", false},
		{"PUT", "/admin/v1/security/reply-policy", "security_events", "write", "tenant", false},
		{"GET", "/admin/v1/system/product", "system_config", "read", "tenant", false},
		{"GET", "/admin/v1/system/license", "system_license", "read", "tenant", false},
		{"POST", "/admin/v1/system/license/import", "system_license", "write", "tenant", false},
		{"POST", "/admin/v1/system/license/trial", "system_license", "write", "tenant", false},
		{"GET", "/admin/v1/skills/assets", "skill_assets", "read", "tenant", false},
		{"POST", "/admin/v1/skills/scan", "skill_assets", "write", "tenant", false},
		{"POST", "/admin/v1/skills/versions/version-1/admission", "skill_assets", "write", "tenant", false},
		{"POST", "/admin/v1/internal/security/skills/definitions", "skill_assets", "write", "tenant", false},
		{"POST", "/admin/v1/mcp-servers/server-1/admission", "mcp_servers", "write", "tenant", false},
		{"POST", "/admin/v1/mcp-tools/tool-1/admission", "mcp_servers", "write", "tenant", false},
		{"GET", "/admin/v1/internal/security/skills/admission", "skill_assets", "read", "tenant", false},
		{"POST", "/admin/v1/agentguard/policies", "agentguard_policies", "write", "tenant", false},
		{"POST", "/admin/v1/audit/access-retention/{request_id}/content", "security_events", "read", "tenant", false},
		{"POST", "/admin/v1/audit/access-retention/{request_id}/timeline", "security_events", "read", "tenant", false},
		{"PUT", "/admin/v1/audit/dispositions", "audit_dispositions", "write", "tenant", false},
	}

	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		got := Resolve(r)
		if got.Resource != tc.wantResource {
			t.Errorf("%s %s: resource = %q, want %q", tc.method, tc.path, got.Resource, tc.wantResource)
		}
		if got.Action != tc.wantAction {
			t.Errorf("%s %s: action = %q, want %q", tc.method, tc.path, got.Action, tc.wantAction)
		}
		if got.ScopeType != tc.wantScopeType {
			t.Errorf("%s %s: scopeType = %q, want %q", tc.method, tc.path, got.ScopeType, tc.wantScopeType)
		}
		if got.RequirePlatformAdmin != tc.wantPlatformAdmin {
			t.Errorf("%s %s: requirePlatformAdmin = %v, want %v", tc.method, tc.path, got.RequirePlatformAdmin, tc.wantPlatformAdmin)
		}
	}
}

func TestDirectoryRoutesUseDirectorySourceTenantPermissions(t *testing.T) {
	cases := []struct {
		method string
		path   string
		action string
	}{
		{http.MethodGet, "/admin/v1/directory/sources/draft", "read"},
		{http.MethodPut, "/admin/v1/directory/sources/draft", "write"},
		{http.MethodPost, "/admin/v1/directory/sources/test", "write"},
		{http.MethodPost, "/admin/v1/directory/sources/sync", "manage"},
		{http.MethodPost, "/admin/v1/directory/sources/preview", "manage"},
		{http.MethodGet, "/admin/v1/directory/sources/previews/{id}", "read"},
		{http.MethodPost, "/admin/v1/directory/sources/previews/{id}/activate", "manage"},
		{http.MethodGet, "/admin/v1/directory/sync-runs", "read"},
		{http.MethodGet, "/admin/v1/directory/sync-runs/{id}", "read"},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			got := Resolve(httptest.NewRequest(tc.method, tc.path, nil))
			if got.RequirePlatformAdmin || got.Resource != "directory_sources" || got.Action != tc.action || got.ScopeType != "tenant" {
				t.Fatalf("resolved to %+v, want directory_sources:%s tenant", got, tc.action)
			}
		})
	}
}

func TestUnifiedDepartmentMappingRoutesUseIdentitySourcePermissions(t *testing.T) {
	cases := []struct {
		method string
		path   string
		action string
	}{
		{http.MethodGet, "/admin/v1/identity/department-mappings", "read"},
		{http.MethodPost, "/admin/v1/identity/department-mappings", "manage"},
		{http.MethodPatch, "/admin/v1/identity/department-mappings/idm_x", "manage"},
		{http.MethodDelete, "/admin/v1/identity/department-mappings/idm_x", "manage"},
		{http.MethodPost, "/admin/v1/identity/department-mappings/preview", "read"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			got := Resolve(httptest.NewRequest(tc.method, tc.path, nil))
			if got.RequirePlatformAdmin || got.Resource != "identity_sources" || got.Action != tc.action || got.ScopeType != "tenant" {
				t.Fatalf("resolved to %+v, want identity_sources:%s tenant", got, got.Action)
			}
		})
	}
}

func TestRoutingDecisionDetailUsesTenantReadPermission(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/routing-decisions/req_123", nil)
	rctx := chi.NewRouteContext()
	rctx.RoutePatterns = []string{"/admin/v1/routing-decisions/{request_id}"}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	got := Resolve(req)
	if got.Resource != "routing_policies" || got.Action != "read" || got.RequirePlatformAdmin {
		t.Fatalf("unexpected permission: %#v", got)
	}
}

func TestResolveModelRoutingOverrideRoutes(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		for _, path := range []string{"/admin/v1/model-routing/models/model-x", "/admin/v1/model-routing/models/org/model-x"} {
			r := chi.NewRouter()
			r.MethodFunc(method, "/admin/v1/model-routing/models/{model_name}", func(w http.ResponseWriter, req *http.Request) {
				got := Resolve(req)
				if got.RequirePlatformAdmin || got.Resource != "routing_policies" || got.Action != "write" || got.ScopeType != "tenant" {
					t.Errorf("%s %s resolved to %+v", method, path, got)
				}
			})
			r.MethodFunc(method, "/admin/v1/model-routing/models/*", func(w http.ResponseWriter, req *http.Request) {
				got := Resolve(req)
				if got.RequirePlatformAdmin || got.Resource != "routing_policies" || got.Action != "write" || got.ScopeType != "tenant" {
					t.Errorf("%s %s resolved to %+v", method, path, got)
				}
			})
			r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, path, nil))
		}
	}
}

func TestModelRoutingRoleMatrix(t *testing.T) {
	has := func(role, permission string) bool {
		for _, p := range permissionMatrix[role] {
			if p == permission {
				return true
			}
		}
		return false
	}
	cases := []struct {
		role        string
		read, write bool
	}{
		{"platform_admin", true, true}, {"tenant_owner", true, true},
		{"auditor", false, false}, {"project_owner", true, false}, // W4 4.2
		{"project_developer", false, false}, {"tenant_admin", false, false},
	}
	for _, tc := range cases {
		if got := has(tc.role, "routing_policies:read"); got != tc.read {
			t.Errorf("%s read=%v want %v", tc.role, got, tc.read)
		}
		if got := has(tc.role, "routing_policies:write"); got != tc.write {
			t.Errorf("%s write=%v want %v", tc.role, got, tc.write)
		}
	}
}

func TestResolveUnregisteredPath(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/admin/v1/some-unknown-endpoint", nil)
	got := Resolve(r)
	if !got.RequirePlatformAdmin {
		t.Error("unregistered path should require platform_admin")
	}
}

func TestResolvePathWithID(t *testing.T) {
	cases := []struct {
		method        string
		path          string
		wantResource  string
		wantAction    string
		wantScopeType string
	}{
		{"PATCH", "/admin/v1/users/user_abc123", "users", "write", "tenant"},
		{"DELETE", "/admin/v1/users/user_abc123", "users", "delete", "tenant"},
		{"POST", "/admin/v1/users/user_abc123/department/automatic", "users", "write", "tenant"},
		{"GET", "/admin/v1/users/user_abc123/grants", "users.grants", "read", "tenant"},
		{"POST", "/admin/v1/users/user_abc123/grants", "users.grants", "write", "tenant"},
		{"GET", "/admin/v1/projects/proj_abc/users", "project_users", "read", "project"},
		{"DELETE", "/admin/v1/teams/team_abc", "teams", "delete", "team"},
		{"POST", "/admin/v1/teams/team_abc/members", "teams.members", "write", "team"},
		{"PUT", "/admin/v1/agentguard/policies/agp_abc", "agentguard_policies", "write", "tenant"},
	}

	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		got := Resolve(r)
		if got.Resource != tc.wantResource {
			t.Errorf("%s %s: resource = %q, want %q", tc.method, tc.path, got.Resource, tc.wantResource)
		}
		if got.Action != tc.wantAction {
			t.Errorf("%s %s: action = %q, want %q", tc.method, tc.path, got.Action, tc.wantAction)
		}
		if got.ScopeType != tc.wantScopeType {
			t.Errorf("%s %s: scopeType = %q, want %q", tc.method, tc.path, got.ScopeType, tc.wantScopeType)
		}
	}
}

func TestResolveCostStatsAndEnterpriseRoutes(t *testing.T) {
	cases := []struct {
		method   string
		path     string
		resource string
		action   string
	}{
		{"GET", "/admin/v1/usage/summary", "saving_metrics", "read"},
		{"GET", "/admin/v1/usage/by-key", "saving_metrics", "read"},
		{"GET", "/admin/v1/usage/trend", "saving_metrics", "read"},
		{"GET", "/admin/v1/users/user_1/usage/summary", "saving_metrics", "read"},
		{"GET", "/admin/v1/users/user_1/usage/trend", "saving_metrics", "read"},
		{"GET", "/admin/v1/users/user_1/usage/by-model", "saving_metrics", "read"},
		{"GET", "/admin/v1/users/user_1/usage/records", "saving_metrics", "read"},
		{"GET", "/admin/v1/portal-integration/system/chat-portal-status", "security_events", "read"},
		{"GET", "/admin/v1/stats/overview", "saving_metrics", "read"},
		{"GET", "/admin/v1/stats/org", "saving_metrics", "read"},
		{"GET", "/admin/v1/teams/team_1/usage", "saving_metrics", "read"},
		{"PUT", "/admin/v1/teams/team_1/budget", "quota_policies", "write"},
		{"GET", "/admin/v1/settings/org-labels", "users", "read"},
		{"PUT", "/admin/v1/settings/org-labels", "users", "write"},
		{"GET", "/admin/v1/providers/deleted", "providers", "read"},
		{"POST", "/admin/v1/providers/provider_1/restore", "providers", "write"},
		{"DELETE", "/admin/v1/tenants/tenant_1/projects/project_1", "projects", "delete"},
	}
	for _, tc := range cases {
		got := Resolve(httptest.NewRequest(tc.method, tc.path, nil))
		if got.RequirePlatformAdmin || got.Resource != tc.resource || got.Action != tc.action {
			t.Fatalf("%s %s resolved to %+v, want %s:%s", tc.method, tc.path, got, tc.resource, tc.action)
		}
	}
}

func TestResolvePortalCustomerKeyRevealRoute(t *testing.T) {
	router := chi.NewRouter()
	router.Post("/admin/v1/portal-integration/customer-keys/{id}/reveal", func(w http.ResponseWriter, r *http.Request) {
		got := Resolve(r)
		if got.RequirePlatformAdmin || got.Resource != "api_keys" || got.Action != "read" || got.ScopeType != "tenant" {
			t.Fatalf("resolved to %+v, want api_keys:read tenant", got)
		}
	})

	router.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/customer-keys/key_abc123/reveal", nil),
	)
}

func TestProtectedServerRoutesHaveRBACMapping(t *testing.T) {
	body, err := os.ReadFile("../../cmd/server/main.go")
	if err != nil {
		t.Fatalf("read server routes: %v", err)
	}
	re := regexp.MustCompile(`r(?:\.With\([^)]*\))?\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	var missing []string
	for _, m := range matches {
		method := strings.ToUpper(m[1])
		path := m[2]
		if shouldSkipRBACRoute(path) {
			continue
		}
		if _, ok := routeTable[method+" "+path]; !ok {
			missing = append(missing, method+" "+path)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("routes lack RBAC mapping:\n%s", strings.Join(missing, "\n"))
	}
}

func shouldSkipRBACRoute(path string) bool {
	if !strings.HasPrefix(path, "/admin/v1/") {
		return true
	}
	if path == "/admin/v1/employee-login" || path == "/admin/v1/login" || path == "/admin/v1/service-login" || path == "/admin/v1/captcha" {
		return true
	}
	// W9 9.1/9.3：控制台 SSO 入口与 /admin/v1/login 同属公开路由（在会话/RBAC 中间件之前注册）。
	if strings.HasPrefix(path, "/admin/v1/auth/sso/") {
		return true
	}
	for _, prefix := range []string{"/admin/v1/me", "/admin/v1/internal/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// Retired console bindings must no longer grant tenant identity-source access.
func TestResolveRetiredConsoleSSOBindingRoutesFailClosed(t *testing.T) {
	router := chi.NewRouter()
	check := func(w http.ResponseWriter, r *http.Request) {
		got := Resolve(r)
		if !got.RequirePlatformAdmin {
			t.Errorf("retired console SSO route still grants access: %s %s %+v", r.Method, r.URL.Path, got)
		}
	}
	router.Get("/admin/v1/identity/console-sso/bindings", check)
	router.Post("/admin/v1/identity/console-sso/bindings", check)
	router.Delete("/admin/v1/identity/console-sso/bindings/{id}", check)
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/admin/v1/identity/console-sso/bindings?user_id=u1", nil),
		httptest.NewRequest(http.MethodPost, "/admin/v1/identity/console-sso/bindings", nil),
		httptest.NewRequest(http.MethodDelete, "/admin/v1/identity/console-sso/bindings/uil_abc", nil),
	} {
		router.ServeHTTP(httptest.NewRecorder(), request)
	}
}

func TestResolveModelSyncVerifiedRoutes(t *testing.T) {
	paths := []string{
		"/admin/v1/models/sync/preview",
		"/admin/v1/models/sync/verify",
		"/admin/v1/models/sync/commit",
	}
	for _, path := range paths {
		got := Resolve(httptest.NewRequest(http.MethodPost, path, nil))
		if got.RequirePlatformAdmin || got.Resource != "models" || got.Action != "write" || got.ScopeType != "tenant" {
			t.Errorf("POST %s resolved to %+v, want models:write tenant", path, got)
		}
	}
}

func TestPersonalKeyMutationRoutesResolveThroughChiMetadata(t *testing.T) {
	for _, tc := range []struct{ method, pattern, path string }{{"PATCH", "/admin/v1/portal-integration/customer-keys/{id}", "/admin/v1/portal-integration/customer-keys/owned-key"}, {"POST", "/admin/v1/portal-integration/customer-keys/{id}/reset", "/admin/v1/portal-integration/customer-keys/owned-key/reset"}} {
		router := chi.NewRouter()
		router.MethodFunc(tc.method, tc.pattern, func(w http.ResponseWriter, r *http.Request) {
			metadata := Resolve(r)
			if metadata.Resource != "api_keys" || metadata.Action != "write" || metadata.RequirePlatformAdmin {
				t.Fatalf("incorrect key route permission: %+v", metadata)
			}
			w.WriteHeader(204)
		})
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(tc.method, tc.path, nil))
		if recorder.Code != 204 {
			t.Fatal("key route not registered")
		}
	}
}
