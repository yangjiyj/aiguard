package permission

import (
	"strings"
	"testing"
)

// dept_manager（部门主管）是纯只读、只看本部门的角色。本测试把这两条安全不变量钉死：
// (1) 它存在于矩阵；(2) 每一条权限都是 :read（绝不含 write/delete/export/approve）；
// (3) 绝不包含高危 resource（密钥/供应商/审计链/安全事件/mcp/agentguard/通知/代理/汇率/定价/告警）。
// 任何后续改动若给它塞了写权限或高危读，这里会红。
func TestDeptManagerRoleIsReadOnlyAndMinimal(t *testing.T) {
	perms, ok := permissionMatrix["dept_manager"]
	if !ok {
		t.Fatal("permissionMatrix 缺少 dept_manager 角色")
	}
	if len(perms) == 0 {
		t.Fatal("dept_manager 权限为空")
	}

	// (2) 只读不变量：动作只能是 read。
	for _, p := range perms {
		resource, action, okSplit := splitResourceAction(p)
		if !okSplit {
			t.Errorf("非法权限串 %q", p)
			continue
		}
		if action != "read" {
			t.Errorf("dept_manager 只能只读，发现非 read 动作: %s:%s", resource, action)
		}
	}

	// (3) 高危 resource 黑名单：一旦被授予即视为回归。
	// 注：security_events/alert_groups 已按 project 收窄，故意放开（看本部门告警元信息），不在黑名单。
	// alert_inbox 仍黑名单（无 project 列，会漏全租户）。content/audit 留证原文也不给。
	forbidden := map[string]bool{
		"api_keys": true, "providers": true,
		"audit_chain": true, "mcp_servers": true, "mcp_policies": true,
		"agentguard_policies": true, "notify_channels": true,
		"proxy_access_keys": true, "fx_rates": true, "pricing": true,
		"alert_inbox": true, "system_license": true,
		"routing_policies": true, "forecast_jobs": true,
	}
	for _, p := range perms {
		resource, _, _ := splitResourceAction(p)
		if forbidden[resource] {
			t.Errorf("dept_manager 不得持有高危 resource %q（权限 %q）", resource, p)
		}
	}
}

// dept_manager 必须覆盖三块只读视图所需的最小 resource，否则通电后部门主管会看不到本该看的东西。
func TestDeptManagerHasRequiredReadResources(t *testing.T) {
	perms := permissionMatrix["dept_manager"]
	have := map[string]bool{}
	for _, p := range perms {
		have[p] = true
	}
	required := []string{
		"saving_metrics:read",              // 消耗看板
		"teams:read", "teams.members:read", // 本部门成员
		"projects:read", "models:read", // 应用 / 模型白名单
		"users:read", "users.grants:read", // 员工 AI 权限
	}
	for _, need := range required {
		if !have[need] {
			t.Errorf("dept_manager 缺少必需只读权限 %q", need)
		}
	}
}

// 防呆：不变量断言里引用的动作名与 splitResourceAction 口径一致（用最后一个冒号切分）。
func TestSplitResourceActionDottedResource(t *testing.T) {
	resource, action, ok := splitResourceAction("users.grants:read")
	if !ok || resource != "users.grants" || action != "read" {
		t.Fatalf("splitResourceAction 口径异常: got (%q,%q,%v)", resource, action, ok)
	}
	if strings.Contains(resource, ":") {
		t.Fatal("resource 不应含冒号")
	}
}

func TestContentEvidenceRolePermissionsStayAligned(t *testing.T) {
	for _, role := range []string{"tenant_owner", "tenant_admin", "auditor"} {
		perms := permissionMatrix[role]
		for _, required := range []string{"security_events:read", "security_events:export"} {
			if !containsPermission(perms, required) {
				t.Errorf("%s missing content evidence permission %q", role, required)
			}
		}
	}
	for _, role := range []string{"tenant_owner", "tenant_admin"} {
		if !containsPermission(permissionMatrix[role], "audit_dispositions:write") {
			t.Errorf("%s missing disposition mutation permission", role)
		}
	}
	if containsPermission(permissionMatrix["auditor"], "audit_dispositions:write") {
		t.Fatal("auditor must remain read-only")
	}
}

func containsPermission(perms []string, target string) bool {
	for _, permission := range perms {
		if permission == target {
			return true
		}
	}
	return false
}
