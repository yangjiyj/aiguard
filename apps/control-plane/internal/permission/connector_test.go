package permission

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConnectorRouteBoundaryAlwaysFailsClosed(t *testing.T) {
	allowed := []string{"GET /admin/v1/me", "GET /admin/v1/security/policies", "POST /admin/v1/security/policies",
		"PATCH /admin/v1/security/policies/policy-1", "GET /admin/v1/security/policy-assets", "PUT /admin/v1/security/policy-assets/asset-1",
		"GET /admin/v1/agentguard/policies", "POST /admin/v1/agentguard/policies", "PUT /admin/v1/agentguard/policies/policy-1",
		"GET /admin/v1/mcp-policies", "POST /admin/v1/mcp-policies", "PUT /admin/v1/mcp-policies/policy-1",
		"GET /admin/v1/audit/events", "GET /admin/v1/integration/capabilities", "GET /admin/v1/integration/projects"}
	denied := []string{"GET /admin/v1/security/events", "GET /admin/v1/users", "POST /admin/v1/users", "GET /admin/v1/providers", "POST /admin/v1/system/ruleset/sync",
		"GET /admin/v1/audit/requests", "GET /admin/v1/audit/dispositions", "PUT /admin/v1/audit/dispositions",
		"GET /admin/v1/audit/export", "GET /admin/v1/audit/content", "GET /admin/v1/audit/events/export",
		"POST /admin/v1/anomalies/item/ack", "POST /admin/v1/security/policies/batch", "DELETE /admin/v1/mcp-policies/item",
		"GET /admin/v1/me/permissions", "POST /admin/v1/internal/agent/events", "POST /admin/v1/agent/authorize", "GET /admin/v1/agent/endpoints",
		"GET /admin/v1/system/settings", "POST /admin/v1/system/upgrade/execute"}
	for _, dryRun := range []bool{true, false} {
		for _, tc := range []struct {
			routes []string
			status int
		}{{allowed, 204}, {denied, 403}} {
			for _, route := range tc.routes {
				method, path := "", ""
				for i, c := range route {
					if c == ' ' {
						method, path = route[:i], route[i+1:]
						break
					}
				}
				r := httptest.NewRequest(method, path, nil)
				r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: "connector", TenantID: "tenant-a", Role: "platform_connector"}))
				w := httptest.NewRecorder()
				// Nil checker proves neither dry-run nor administrator grants can bypass the contract.
				Middleware(nil, nil, dryRun)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
				if w.Code != tc.status {
					t.Errorf("%s dryRun=%v got=%d want=%d", route, dryRun, w.Code, tc.status)
				}
			}
		}
	}
}
func TestConnectorSeedHasNoAdministratorPermissions(t *testing.T) {
	allowed := map[string]map[string]bool{
		"gateway_security_policies": {"read": true, "write": true}, "agentguard_policies": {"read": true, "write": true}, "mcp_policies": {"read": true, "write": true},
		"agent_credentials": {"read": true, "write": true}, "agent_enforcement_policies": {"read": true, "write": true},
		"gateway_enforcement_status": {"read": true}, "integration_events": {"read": true}, "integration_upstreams": {"read": true}, "security_events": {"read": true}, "integration_projects": {"read": true},
	}
	for _, perm := range permissionMatrix["platform_connector"] {
		r, a, ok := splitResourceAction(perm)
		if !ok || !allowed[r][a] {
			t.Fatalf("excess permission: %s", perm)
		}
	}
}
