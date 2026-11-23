package handler

// 第 1 项：SoD 放行 security_officer / auditor 的路由，handler 层不得再用角色判定二次拒绝。
//
// 做法：officerRouteRegistry（officer_routes_registry_test.go，由 main.go 的注册表达式生成）给出全部放行三员的路由及其真实 handler，
// 这里对每条路由、每个被 SoD 放行的角色，带着会话上下文真实调用 handler（仓库是 nil 桩）：
//   - 返回 403 或 handler 层的角色类拒绝 => 失败（除非在 officerRoleGateAllowedDenials 里登记并说明设计依据）；
//   - 之后访问 nil 仓库触发 panic => 视为「已通过角色判定」，不算失败。
// 另外，officerRoleGateAllowedDenials 里的每一项必须真的仍被拒绝，否则提示清理白名单（避免白名单失真）。

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 设计上就是对该角色拒绝的路由。key = "角色 METHOD path"，value = 依据（docs/design/ws4-rbac-matrix.md 与 SoD 表对齐的理由）。
var officerRoleGateAllowedDenials = map[string]string{
	"security_officer PUT /admin/v1/security/system-settings": "安全员可写的系统设置（2.9.22 起有允许本人批准 agentguard_allow_self_approval）" +
		"存放在全局 system_settings，对全部租户生效，与语义检测配置同口径：租户级安全员被 handler 以 " +
		"global_config_requires_platform_level 拒绝，平台级安全员与系统管理员可改。行为测试见 " +
		"security_system_settings_2922_test.go 的 TestUpdateSecuritySystemSettingsAllowSelfApproval",
	"security_officer PUT /admin/v1/security/semantic/settings": "语义检测配置存放在全局 system_settings，是全平台共享、不分租户的：" +
		"任何一个租户的人改了，所有租户的检测都跟着变。所以租户级安全员（本测试用 tenant-a 的安全员）被 handler 以 " +
		"global_config_requires_platform_level 拒绝，只有平台级安全员（平台默认租户）与系统管理员可改。" +
		"SoD 仍归 SecurityWrite（角色层面安全员有这项职责），租户边界由 handler 把关；行为测试见 " +
		"semantic_settings_judge_guard_test.go 的 TestTenantScopedSecurityOfficerCannotChangeTheGlobalSemanticConfig",
	"security_officer PUT /admin/v1/audit/raw-evidence/settings": "脱敏原文留证开关 raw_evidence_enabled 存放在全局 system_settings，" +
		"对全部租户生效：任一租户的安全保密员改了，所有租户的原文留证都跟着停或开（审查 I-4）。开关属于系统配置，" +
		"只有系统管理员（platform_admin）可改，handler 以 global_config_requires_system_admin 拒绝安全保密员；" +
		"SoD 仍归 raw_evidence（安全保密员可列出、查看原文与查看开关状态）。行为测试见 raw_evidence_db_test.go 的 TestRawEvidenceConsoleDatabase",
}

func serveOfficerRoute(h http.Handler, method, path, role string) (code int, body string, panicked bool) {
	user := &repository.User{ID: "officer-u", TenantID: "tenant-a", Role: role, Status: "active"}
	session := &repository.Session{ID: "officer-s", UserID: user.ID, TenantID: user.TenantID}
	concrete := path
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") {
			concrete = strings.Replace(concrete, seg, "00000000-0000-0000-0000-000000000001", 1)
		}
	}
	req := httptest.NewRequest(method, concrete, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	ctx = context.WithValue(ctx, auth.SessionKey, session)
	ctx = permission.WithSoDAllowed(ctx)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		h.ServeHTTP(rec, req)
	}()
	return rec.Code, rec.Body.String(), panicked
}

func TestOfficerRoutesNeverRejectedByHandlerRoleGate(t *testing.T) {
	registry := officerRouteRegistry()
	if len(registry) < 200 {
		t.Fatalf("路由注册表异常：只有 %d 条", len(registry))
	}
	var denied []string
	seenDenial := map[string]bool{}
	for key, entry := range registry {
		parts := strings.SplitN(key, " ", 2)
		method, path := parts[0], parts[1]
		class := permission.SoDClassFor(method, path)
		for _, role := range []string{"security_officer", "auditor"} {
			if permission.DecideSoD(role, class, false) != permission.SoDAllow && class != permission.SoDCommon {
				continue
			}
			if permission.DecideSoD(role, class, false) == permission.SoDDeny {
				continue
			}
			code, body, _ := serveOfficerRoute(entry.build(), method, path, role)
			if code != http.StatusForbidden {
				continue
			}
			id := role + " " + key
			seenDenial[id] = true
			if _, ok := officerRoleGateAllowedDenials[id]; ok {
				continue
			}
			denied = append(denied, fmt.Sprintf("%s -> %d %s (%s)", id, code, strings.TrimSpace(body), entry.expr))
		}
	}
	sort.Strings(denied)
	if len(denied) > 0 {
		t.Fatalf("SoD 放行但 handler 层角色拒绝（共 %d 条）。要么放行 handler，要么在 SoD 表里收窄，要么登记到 officerRoleGateAllowedDenials 并写明依据:\n  %s",
			len(denied), strings.Join(denied, "\n  "))
	}
	for id := range officerRoleGateAllowedDenials {
		if !seenDenial[id] {
			t.Errorf("白名单里的 %q 已不再被 handler 拒绝（或路由已删除），请清理", id)
		}
	}
}

// 注册表必须与 SoD 表严格一致（未知即失败）：officerRouteRegistry 是 main.go 注册表达式的快照。
// 如果 SoD 表新增了一条对官员放行的路由、或把某条路由改成放行，而注册表没有同步，上面的遍历根本看不到它，
// 「SoD 放行、handler 拒绝」就会重新溜进来。所以这里反向核对：SoD 表里每条对官员放行的路由都必须在注册表里，
// 注册表里的每条也必须仍被 SoD 放行且类别一致。
// 例外：officerRegistryNotRegistered 里逐条登记的、SoD 表预留但 main.go 并未注册的路由。
func TestOfficerRouteRegistryMatchesSoDTable(t *testing.T) {
	registry := officerRouteRegistry()
	grantedToAnOfficer := func(class permission.SoDClass) bool {
		return permission.DecideSoD("security_officer", class, false) == permission.SoDAllow ||
			permission.DecideSoD("auditor", class, false) == permission.SoDAllow
	}
	var problems []string
	for route, class := range permission.OfficerRouteKeys() {
		if !grantedToAnOfficer(class) {
			continue
		}
		entry, ok := registry[route]
		if !ok {
			if _, allowed := officerRouteTableOnly[route]; allowed {
				continue
			}
			problems = append(problems, "SoD 表对官员放行但注册表没有（请重新生成 officer_routes_registry_test.go）: "+route+" ["+string(class)+"]")
			continue
		}
		if entry.class != string(class) {
			problems = append(problems, "类别不一致（SoD 表="+string(class)+"，注册表="+entry.class+"）: "+route)
		}
	}
	for route := range registry {
		class, ok := permission.OfficerRouteKeys()[route]
		if !ok || !grantedToAnOfficer(class) {
			problems = append(problems, "注册表里有、但 SoD 表已不对官员放行（或已删除）: "+route)
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("三员路由注册表与 SoD 表不一致（共 %d 处）:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
}
