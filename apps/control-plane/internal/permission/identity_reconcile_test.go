package permission

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveIdentityReconcileRequiresManage(t *testing.T) {
	got := Resolve(httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/reconcile", nil))
	if got.RequirePlatformAdmin || got.Resource != "identity_sources" || got.Action != "manage" || got.ScopeType != "tenant" {
		t.Fatalf("unexpected reconcile permission: %#v", got)
	}
}

func TestIdentityManageRoleMatrix(t *testing.T) {
	has := func(role, permission string) bool {
		for _, candidate := range permissionMatrix[role] {
			if candidate == permission {
				return true
			}
		}
		return false
	}
	for _, role := range []string{"platform_admin", "tenant_owner", "tenant_admin"} {
		if !has(role, "identity_sources:manage") {
			t.Fatalf("%s must be able to reconcile tenant identity configuration", role)
		}
	}
	for _, role := range []string{"developer", "auditor", "team_owner"} {
		if has(role, "identity_sources:manage") {
			t.Fatalf("%s must not manage tenant identity configuration", role)
		}
	}
}
