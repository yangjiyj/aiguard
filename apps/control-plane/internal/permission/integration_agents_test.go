package permission

import (
	"net/http/httptest"
	"testing"
)

func TestAgentIntegrationRoutesResolveAndSealedIdentityCannotExpand(t *testing.T) {
	cases := []struct{ method, path, resource, action string }{
		{"POST", "/admin/v1/integration/agent-credentials", "agent_credentials", "write"},
		{"GET", "/admin/v1/integration/agent-credentials", "agent_credentials", "read"},
		{"POST", "/admin/v1/integration/agent-credentials/key1/rotate", "agent_credentials", "write"},
		{"POST", "/admin/v1/integration/agent-credentials/key1/revoke", "agent_credentials", "write"},
		{"POST", "/admin/v1/integration/agent-policies", "agent_enforcement_policies", "write"},
		{"PUT", "/admin/v1/integration/agent-policies/policy1", "agent_enforcement_policies", "write"},
		{"GET", "/admin/v1/integration/agent-policies", "agent_enforcement_policies", "read"},
		{"GET", "/admin/v1/integration/enforcement-status", "gateway_enforcement_status", "read"},
		{"GET", "/admin/v1/integration/audit-events", "integration_events", "read"},
		{"GET", "/admin/v1/integration/upstreams", "integration_upstreams", "read"},
		{"GET", "/admin/v1/integration/projects", "integration_projects", "read"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		p := Resolve(r)
		if p.Resource != tc.resource || p.Action != tc.action || p.RequirePlatformAdmin || p.ScopeType != "tenant" || !connectorRouteAllowed(r) {
			t.Fatalf("%s %s: %+v", tc.method, tc.path, p)
		}
	}
	for _, path := range []string{"/admin/v1/users", "/admin/v1/audit/content", "/admin/v1/internal/agent/events", "/admin/v1/integration/agent-credentials/key1/reveal"} {
		if connectorRouteAllowed(httptest.NewRequest("GET", path, nil)) {
			t.Fatalf("excess route %s", path)
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if connectorRouteAllowed(httptest.NewRequest(method, "/admin/v1/integration/projects", nil)) {
			t.Fatalf("project write allowed: %s", method)
		}
	}
	for _, path := range []string{"/admin/v1/integration/projects/foreign-project", "/admin/v1/projects", "/admin/v1/portal-integration/projects"} {
		if connectorRouteAllowed(httptest.NewRequest("GET", path, nil)) {
			t.Fatalf("project boundary expanded: %s", path)
		}
	}
}

func TestPhase2IntegrationRouteBoundaries(t *testing.T) {
	for _, route := range []struct{ method, path string }{
		{"GET", "/admin/v1/integration/agent-credentials/key1"},
		{"PATCH", "/admin/v1/integration/agent-credentials/key1"},
		{"GET", "/admin/v1/integration/dlp-status"},
		{"GET", "/admin/v1/security/policies/capabilities"},
	} {
		r := httptest.NewRequest(route.method, route.path, nil)
		if !connectorRouteAllowed(r) {
			t.Errorf("连接器缺少 %s %s", route.method, route.path)
		}
		if _, ok := routeTable[route.method+" "+normalizePathToTemplate(route.path)]; !ok {
			t.Errorf("权限未登记：%s", route.path)
		}
		if _, ok := sodRouteTable[route.method+" "+normalizePathToTemplate(route.path)]; !ok {
			t.Errorf("三员分立未登记：%s", route.path)
		}
	}
}
