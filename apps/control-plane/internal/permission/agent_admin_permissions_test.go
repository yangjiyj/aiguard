package permission

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestAgentAdminRoutePermissions(t *testing.T) {
	tests := []struct {
		method, path, resource, action string
	}{
		{http.MethodGet, "/admin/v1/agent/overview", "agent_endpoints", "read"},
		{http.MethodGet, "/admin/v1/agent/endpoints", "agent_endpoints", "read"},
		{http.MethodGet, "/admin/v1/agent/endpoints/ep_1", "agent_endpoints", "read"},
		{http.MethodPut, "/admin/v1/agent/endpoints/ep_1/mode", "agent_endpoints", "write"},
		{http.MethodPost, "/admin/v1/agent/endpoints/ep_1/revoke", "agent_endpoints", "write"},
		{http.MethodPost, "/admin/v1/agent/endpoints/ep_1/rotate-token", "agent_endpoints", "write"},
		{http.MethodGet, "/admin/v1/agent/enrollment-tokens", "agent_enrollment", "admin"},
		{http.MethodPost, "/admin/v1/agent/enrollment-tokens", "agent_enrollment", "admin"},
		{http.MethodPost, "/admin/v1/agent/enrollment-tokens/aet_1/revoke", "agent_enrollment", "admin"},
		{http.MethodGet, "/admin/v1/agent/sessions", "agent_sessions", "read"},
		{http.MethodGet, "/admin/v1/agent/sessions/as_1", "agent_sessions", "read"},
		{http.MethodGet, "/admin/v1/agent/events", "agent_sessions", "read"},
		{http.MethodGet, "/admin/v1/agent/assets", "agent_endpoints", "read"},
		{http.MethodGet, "/admin/v1/agent/unified-assets", "agent_endpoints", "read"},
		{http.MethodGet, "/admin/v1/agent/unified-assets/native-reference-link", "agent_endpoints", "read"},
		{http.MethodGet, "/admin/v1/agent/unified-assets/ua_1/history", "agent_endpoints", "read"},
		{http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/ownership", "agent_endpoints", "write"},
		{http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/catalog", "agent_endpoints", "write"},
		{http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/sources", "agent_endpoints", "write"},
		{http.MethodPost, "/admin/v1/agent/unified-assets/ua_1/merge", "agent_endpoints", "write"},
		{http.MethodGet, "/admin/v1/agent/approval-rules", "agent_endpoints", "read"},
		{http.MethodPost, "/admin/v1/agent/approval-rules", "agent_endpoints", "write"},
		{http.MethodPost, "/admin/v1/agent/approval-rules/dar_1/deactivate", "agent_endpoints", "write"},
		{http.MethodGet, "/admin/v1/agent/policy-bundles", "agent_endpoints", "read"},
		{http.MethodGet, "/admin/v1/agent/policy-bundles/current", "agent_endpoints", "read"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := Resolve(httptest.NewRequest(tt.method, tt.path, nil))
			if got.RequirePlatformAdmin || got.Resource != tt.resource || got.Action != tt.action || got.ScopeType != "tenant" {
				t.Fatalf("resolved to %+v, want %s:%s tenant", got, tt.resource, tt.action)
			}
		})
	}
}

func TestAgentAdminRoleMatrix(t *testing.T) {
	has := func(role, permission string) bool {
		for _, candidate := range permissionMatrix[role] {
			if candidate == permission {
				return true
			}
		}
		return false
	}
	for _, role := range []string{"platform_admin", "tenant_owner", "tenant_admin"} {
		for _, permission := range []string{"agent_endpoints:read", "agent_endpoints:write", "agent_sessions:read", "agent_enrollment:admin"} {
			if !has(role, permission) {
				t.Errorf("%s missing %s", role, permission)
			}
		}
	}
	if !has("auditor", "agent_endpoints:read") || !has("auditor", "agent_sessions:read") {
		t.Fatal("auditor must have both agent read permissions")
	}
	for _, permission := range []string{"agent_endpoints:write", "agent_enrollment:admin"} {
		if has("auditor", permission) {
			t.Errorf("auditor unexpectedly has %s", permission)
		}
	}
}

func TestAgentAdminRouteDeniedWithoutPermission(t *testing.T) {
	cache := NewGrantsCache()
	checker := NewChecker(nil, cache)
	user := &repository.User{ID: "member", TenantID: "tenant-a", Status: "active"}
	cache.Set(user.ID, nil)
	nextCalled := false
	h := Middleware(checker, nil, false)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true }))
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/agent/endpoints", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || nextCalled {
		t.Fatalf("status=%d next=%v want 403 and blocked", rec.Code, nextCalled)
	}
}
