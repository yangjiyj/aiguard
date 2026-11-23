package permission

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKubernetesAdminRoutesUseTenantAgentEndpointPermissions(t *testing.T) {
	cases := []struct {
		method string
		path   string
		action string
	}{
		{http.MethodGet, "/admin/v1/agent/kubernetes/clusters", "read"},
		{http.MethodPost, "/admin/v1/agent/kubernetes/clusters", "write"},
		{http.MethodPost, "/admin/v1/agent/kubernetes/clusters/cluster-1/namespaces", "write"},
		{http.MethodPost, "/admin/v1/agent/kubernetes/namespaces/registration-1/revoke", "write"},
		{http.MethodGet, "/admin/v1/agent/kubernetes/clusters/cluster-1/coverage", "read"},
	}
	for _, test := range cases {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			got := Resolve(httptest.NewRequest(test.method, test.path, nil))
			if got.RequirePlatformAdmin || got.Resource != "agent_endpoints" || got.Action != test.action || got.ScopeType != "tenant" {
				t.Fatalf("resolved to %+v, want agent_endpoints:%s tenant", got, test.action)
			}
		})
	}
}

func TestKubernetesAdminRoutesRemainExactMethodMatches(t *testing.T) {
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodDelete, "/admin/v1/agent/kubernetes/clusters"},
		{http.MethodPost, "/admin/v1/agent/kubernetes/clusters/cluster-1/coverage"},
	}
	for _, test := range cases {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			got := Resolve(httptest.NewRequest(test.method, test.path, nil))
			if !got.RequirePlatformAdmin {
				t.Fatalf("unregistered route escaped fail-closed policy: %+v", got)
			}
		})
	}
}
