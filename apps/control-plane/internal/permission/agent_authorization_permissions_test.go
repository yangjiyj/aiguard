package permission

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentAuthorizationRoutesAndRoleMatrix(t *testing.T) {
	tests := []struct {
		method, path, resource, action string
	}{
		{http.MethodGet, "/admin/v1/agent/principals", "agent_principals", "read"},
		{http.MethodPost, "/admin/v1/agent/principals", "agent_principals", "admin"},
		{http.MethodPost, "/admin/v1/agent/principals/p_1/revoke", "agent_principals", "admin"},
		{http.MethodPost, "/admin/v1/agent/principals/p_1/rotate-token", "agent_principals", "admin"},
		{http.MethodGet, "/admin/v1/agent/principals/p_1/delegation-tree", "agent_principals", "read"},
		{http.MethodPost, "/admin/v1/agent/authorize", "agent_authorization", "check"},
		{http.MethodPost, "/admin/v1/agent/approval-requests", "agent_authorization", "check"},
		{http.MethodPost, "/admin/v1/agent/approval-claims", "agent_authorization", "check"},
		{http.MethodPost, "/admin/v1/agent/delegations", "agent_authorization", "check"},
		{http.MethodPost, "/admin/v1/agent/delegations/d_1/revoke", "agent_authorization", "check"},
		{http.MethodGet, "/admin/v1/agent/delegations/d_1/calls", "agent_authorization", "check"},
		{http.MethodGet, "/admin/v1/agent/approvals", "agent_principals", "read"},
		{http.MethodPost, "/admin/v1/agent/approvals/a1/resolve", "agent_principals", "admin"},
		{http.MethodPost, "/admin/v1/agent/approvals/a1/revoke", "agent_principals", "admin"},
		{http.MethodGet, "/admin/v1/agent/approval-exceptions", "agent_principals", "read"},
		{http.MethodPost, "/admin/v1/agent/approval-exceptions", "agent_principals", "admin"},
		{http.MethodDelete, "/admin/v1/agent/approval-exceptions/e1", "agent_principals", "admin"},
		{http.MethodGet, "/admin/v1/agent/intent-tasks/00000000-0000-4000-8000-000000000001", "agent_intent_tasks", "read"},
		{http.MethodPost, "/admin/v1/agent/intent-tasks", "agent_intent_tasks", "admin"},
		{http.MethodPost, "/admin/v1/agent/intent-tasks/00000000-0000-4000-8000-000000000001/revoke", "agent_intent_tasks", "admin"},
	}
	for _, test := range tests {
		got := Resolve(httptest.NewRequest(test.method, test.path, nil))
		if got.Resource != test.resource || got.Action != test.action {
			t.Errorf("%s %s resolved to %+v", test.method, test.path, got)
		}
	}
	has := func(role, permission string) bool {
		for _, candidate := range permissionMatrix[role] {
			if candidate == permission {
				return true
			}
		}
		return false
	}
	for _, role := range []string{"platform_admin", "tenant_owner", "tenant_admin"} {
		if !has(role, "agent_principals:read") || !has(role, "agent_principals:admin") {
			t.Errorf("%s missing trusted-principal management permissions", role)
		}
	}
	for _, role := range []string{"platform_admin", "tenant_owner", "tenant_admin"} {
		if !has(role, "agent_intent_tasks:read") || !has(role, "agent_intent_tasks:admin") {
			t.Errorf("%s missing approved intent task permissions", role)
		}
	}
	if has("auditor", "agent_principals:admin") || has("team_owner", "agent_principals:admin") || has("team_member", "agent_principals:admin") ||
		has("auditor", "agent_intent_tasks:admin") || has("team_owner", "agent_intent_tasks:admin") || has("team_member", "agent_intent_tasks:admin") {
		t.Fatal("default role matrix must not grant trusted principal/task approval to auditors or project/team members")
	}
}
