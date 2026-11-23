package repository

import (
	"strings"
	"testing"
)

func TestBuildContentAuditUserSelectorQueryIsTenantAndDepartmentScoped(t *testing.T) {
	query, _ := buildContentAuditUserSelectorQuery(ContentAuditUserSelectorFilter{
		TenantID: "tenant-a", DepartmentIDs: []string{"dept-a"}, Query: "同", Limit: 20,
	})
	for _, required := range []string{"u.tenant_id = $1", "u.department_id = ANY(", "u.status <> 'deleted'", "ORDER BY LOWER(u.username), u.id"} {
		if !strings.Contains(query, required) {
			t.Fatalf("selector query missing %q: %s", required, query)
		}
	}
}
