package permission

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDirectoryRoutesResolveToDirectorySources 验证 4 个 directory/sources 路由
// 在 routeTable 中映射到独立资源 directory_sources，而不是落到未注册分支被锁到
// RequirePlatformAdmin。对应 resolver.go 的映射。
func TestDirectoryRoutesResolveToDirectorySources(t *testing.T) {
	cases := []struct {
		method string
		path   string
		action string
	}{
		{http.MethodGet, "/admin/v1/directory/sources/draft", "read"},
		{http.MethodPut, "/admin/v1/directory/sources/draft", "write"},
		{http.MethodPost, "/admin/v1/directory/sources/test", "write"},
		{http.MethodPost, "/admin/v1/directory/sources/sync", "manage"},
	}
	for _, c := range cases {
		got := Resolve(httptest.NewRequest(c.method, c.path, nil))
		if got.RequirePlatformAdmin {
			t.Fatalf("%s %s 落到未注册分支（RequirePlatformAdmin=true），期望命中 directory_sources", c.method, c.path)
		}
		if got.Resource != "directory_sources" {
			t.Fatalf("%s %s Resource=%s，期望 directory_sources", c.method, c.path, got.Resource)
		}
		if got.Action != c.action {
			t.Fatalf("%s %s Action=%s，期望 %s", c.method, c.path, got.Action, c.action)
		}
		if got.ScopeType != "tenant" {
			t.Fatalf("%s %s ScopeType=%s，期望 tenant", c.method, c.path, got.ScopeType)
		}
	}
}

// TestDirectorySourcesRoleMatrix 验证 directory_sources 的角色授权矩阵：
// platform_admin / tenant_owner / tenant_admin 必须有 read/write/manage；
// directory 路由没有 delete 操作，因此不应给任何角色 delete；
// auditor / team_owner / developer 不应有 directory_sources 任意权限。
func TestDirectorySourcesRoleMatrix(t *testing.T) {
	has := func(role, permission string) bool {
		for _, candidate := range permissionMatrix[role] {
			if candidate == permission {
				return true
			}
		}
		return false
	}
	// 三个特权/租户管理员角色必须有 read/write/manage
	for _, role := range []string{"platform_admin", "tenant_owner", "tenant_admin"} {
		for _, action := range []string{"read", "write", "manage"} {
			if !has(role, "directory_sources:"+action) {
				t.Fatalf("%s 必须拥有 directory_sources:%s（组织目录同步功能需租户级管理员可用）", role, action)
			}
		}
	}
	// directory/sources 路由没有 delete 操作，任何角色都不应有 directory_sources:delete
	for _, role := range []string{"platform_admin", "tenant_owner", "tenant_admin", "auditor", "team_owner", "developer"} {
		if has(role, "directory_sources:delete") {
			t.Fatalf("%s 不应拥有 directory_sources:delete（无对应路由，避免非预期提权）", role)
		}
	}
	// 只读 / 团队级角色不应有 directory_sources 权限（与 identity_sources 的边界一致）
	for _, role := range []string{"auditor", "team_owner", "developer"} {
		for _, action := range []string{"read", "write", "manage"} {
			if has(role, "directory_sources:"+action) {
				t.Fatalf("%s 不应拥有 directory_sources:%s", role, action)
			}
		}
	}
}
