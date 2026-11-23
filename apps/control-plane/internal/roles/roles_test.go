package roles

import "testing"

func TestChatUserIsAssignableWithoutAdministratorResponsibilities(t *testing.T) {
	if !IsAssignable("chat_user") {
		t.Fatal("chat_user must be assignable")
	}
	found := false
	for _, role := range Assignable() {
		if role == "chat_user" {
			found = true
		}
	}
	if !found || IsSystemAdmin("chat_user") || CanManageSecurityPolicy("chat_user") || CanHandleAlerts("chat_user") || IsTenantWideSecurityReader("chat_user") {
		t.Fatal("chat_user must be Chat only")
	}
}

func TestPersonalPortalAllowsHumanRolesOnly(t *testing.T) {
	for _, role := range PortalRoles() {
		if !CanLoginPortal(role) {
			t.Fatalf("human role %s rejected", role)
		}
	}
	for _, role := range []string{"", "unknown", "platform_connector", "service"} {
		if CanLoginPortal(role) {
			t.Fatalf("non-human role %s accepted", role)
		}
	}
}

// SoD 项：控制台登录边界。
// 942eecff9（2026-10-12）为隔离员工登录与管理员会话引入 CanLoginConsole，但把 2026-09-30/10-01 才建立的三员
// （security_officer、auditor）与 chat_user、developer 等一起挡在控制台之外，导致三员有菜单、路由、seed 权限、SoD 类别，
// 却登录不进来。三员分立设计里三员本就是控制台角色。
func TestCanLoginConsoleAllowsTheThreeOfficersAndTenantAdmins(t *testing.T) {
	for _, role := range []string{SystemAdmin, SecurityOfficer, Auditor, TenantAdmin, LegacyAdmin, LegacyTenantOwner} {
		if !CanLoginConsole(role) {
			t.Fatalf("%s 必须能登录控制台", role)
		}
	}
}

// 员工隔离边界不变：非控制台角色仍然登录不了。
func TestCanLoginConsoleStillRejectsEmployeeAndBusinessRoles(t *testing.T) {
	for _, role := range []string{ChatUser, Developer, Viewer, DeptManager, LegacyOperator, "platform_connector", "team_owner", "team_member", "project_owner", ""} {
		if CanLoginConsole(role) {
			t.Fatalf("%s 不应能登录控制台", role)
		}
	}
}

// 登录边界（能不能进来）与管理授权（进来后能做什么）必须解耦：
// CanLoginConsole 放开三员，不能因此让三员获得「管理员」档的授权。
func TestConsoleLoginIsNotAnAdministrativeAuthorization(t *testing.T) {
	for _, role := range []string{SecurityOfficer, Auditor} {
		if !CanLoginConsole(role) {
			t.Fatalf("前提：%s 能登录", role)
		}
		if IsConsoleAdministrator(role) {
			t.Fatalf("%s 能登录不等于是『控制台管理员』：不得获得管理员档授权", role)
		}
	}
	for _, role := range []string{SystemAdmin, TenantAdmin, LegacyAdmin, LegacyTenantOwner} {
		if !IsConsoleAdministrator(role) {
			t.Fatalf("%s 仍是控制台管理员", role)
		}
	}
	// 管理员档必须是登录档的子集
	for _, role := range []string{ChatUser, Developer, Viewer, DeptManager, LegacyOperator, ""} {
		if IsConsoleAdministrator(role) {
			t.Fatalf("%s 不得是控制台管理员", role)
		}
	}
}

// 登录加固（IP 白名单、强制 TOTP）对所有能登录控制台的角色生效，包括三员——这是登录边界的一部分，不是授权。
func TestLoginHardeningAppliesToEveryConsoleLoginRole(t *testing.T) {
	for _, role := range []string{SystemAdmin, SecurityOfficer, Auditor, TenantAdmin, LegacyAdmin, LegacyTenantOwner} {
		if !RequiresLoginHardening(role) {
			t.Fatalf("%s 的登录必须受 IP 白名单与强制 TOTP 约束", role)
		}
	}
	for _, role := range []string{ChatUser, Developer, Viewer, DeptManager, LegacyOperator, ""} {
		if RequiresLoginHardening(role) {
			t.Fatalf("%s 不属于控制台登录角色，不适用管理员登录加固", role)
		}
	}
}

// M-1：会话快照角色与当前角色的一致性判定。必须和 roles 包的规范化口径一致：
// platform_admin 与历史别名 admin 视为同一角色（迁移 890 会把 admin 改写成 platform_admin）；
// tenant_owner 与 tenant_admin 是两个不同角色（seed 权限不同），不互相等同。
func TestSessionRoleMatchesUsesTheRolesPackageNormalization(t *testing.T) {
	same := [][2]string{
		{SystemAdmin, SystemAdmin}, {SecurityOfficer, SecurityOfficer}, {Auditor, Auditor},
		{TenantAdmin, TenantAdmin}, {LegacyTenantOwner, LegacyTenantOwner}, {LegacyAdmin, LegacyAdmin},
		{SystemAdmin, LegacyAdmin}, {LegacyAdmin, SystemAdmin},
	}
	for _, p := range same {
		if !SessionRoleMatches(p[0], p[1]) {
			t.Fatalf("%s / %s 应视为同一角色", p[0], p[1])
		}
	}
	console := []string{SystemAdmin, SecurityOfficer, Auditor, TenantAdmin, LegacyTenantOwner}
	for _, a := range console {
		for _, b := range console {
			if a != b && SessionRoleMatches(a, b) {
				t.Fatalf("%s 与 %s 是不同角色，会话不得互相沿用", a, b)
			}
		}
	}
	for _, p := range [][2]string{{"", SystemAdmin}, {SystemAdmin, ""}, {"", ""}, {Developer, Developer}} {
		if p[0] == p[1] && p[0] != "" {
			continue
		}
		if SessionRoleMatches(p[0], p[1]) {
			t.Fatalf("%q / %q 不应匹配", p[0], p[1])
		}
	}
	if SessionRoleMatches("", "") {
		t.Fatal("两个空角色不得视为匹配（没有身份快照的会话不可信）")
	}
}
