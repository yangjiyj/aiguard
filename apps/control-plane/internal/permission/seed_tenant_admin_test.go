package permission

import (
	"strings"
	"testing"
)

func TestTenantAdminTeamsPermissionIsReadOnly(t *testing.T) {
	permissions := map[string]bool{}
	for _, permission := range permissionMatrix["tenant_admin"] {
		permissions[permission] = true
	}
	if !permissions["teams:read"] {
		t.Fatal("tenant_admin must have tenant-scoped teams:read")
	}
	for permission := range permissions {
		if permission == "teams:write" || permission == "teams:delete" || strings.HasPrefix(permission, "users:") {
			t.Fatalf("tenant_admin received broader permission %q", permission)
		}
	}
}
