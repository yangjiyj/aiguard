package permission

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestAgentOperationRoutesUseSeparatedTenantPermissions(t *testing.T) {
	tests := []struct {
		method, path, resource, action string
	}{
		{http.MethodGet, "/admin/v1/agent-operation-protection", "agent_operation_policy", "read"},
		{http.MethodPut, "/admin/v1/agent-operation-protection", "agent_operation_policy", "write"},
		{http.MethodGet, "/admin/v1/agent-operation-events", "agent_operation_event", "read"},
		{http.MethodGet, "/admin/v1/agent-operation-events/aevt_public", "agent_operation_event", "read"},
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

func TestAgentOperationRoleMatrixKeepsPolicyAndEventPermissionsSeparate(t *testing.T) {
	has := func(role, permission string) bool {
		for _, candidate := range permissionMatrix[role] {
			if candidate == permission {
				return true
			}
		}
		return false
	}
	tests := []struct {
		role                    string
		policyRead, policyWrite bool
		eventRead               bool
	}{
		{"platform_admin", true, true, true},
		{"tenant_owner", true, true, true},
		{"tenant_admin", true, true, true},
		{"auditor", false, false, true}, // W4 4.2: no business config reads
		{"security_officer", true, true, true},
		{"team_owner", false, false, false},
		{"team_member", false, false, false},
		{"project_owner", false, false, false},
		{"project_developer", false, false, false},
		{"project_viewer", false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			if got := has(tt.role, "agent_operation_policy:read"); got != tt.policyRead {
				t.Errorf("policy read=%v want %v", got, tt.policyRead)
			}
			if got := has(tt.role, "agent_operation_policy:write"); got != tt.policyWrite {
				t.Errorf("policy write=%v want %v", got, tt.policyWrite)
			}
			if got := has(tt.role, "agent_operation_event:read"); got != tt.eventRead {
				t.Errorf("event read=%v want %v", got, tt.eventRead)
			}
		})
	}
}

func TestAgentOperationEndpointsDenyMissingPermission(t *testing.T) {
	requests := []struct {
		method, path string
	}{
		{http.MethodGet, "/admin/v1/agent-operation-protection"},
		{http.MethodPut, "/admin/v1/agent-operation-protection"},
		{http.MethodGet, "/admin/v1/agent-operation-events"},
		{http.MethodGet, "/admin/v1/agent-operation-events/aevt_public"},
	}
	for _, tt := range requests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			cache := NewGrantsCache()
			checker := NewChecker(nil, cache)
			user := &repository.User{ID: "member", TenantID: "tenant-1", Status: "active"}
			cache.Set(user.ID, nil)
			nextCalled := false
			h := Middleware(checker, nil, false)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			}))
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d want 403: %s", rec.Code, rec.Body.String())
			}
			if nextCalled {
				t.Fatal("request without permission reached protected handler")
			}
		})
	}
}
