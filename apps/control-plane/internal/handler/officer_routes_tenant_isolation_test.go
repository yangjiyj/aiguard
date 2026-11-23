package handler

// 跨租户全量核对（自动化）：遍历 SoD 放行三员的路由，源码级验证 handler 以会话里的 user.TenantID 做租户隔离，
// 不会从请求参数、header 或 body 取 tenant 作为查询/写入目标。
//
// 做法：扫描对三员放行的 SoD 类别（Common、SecurityRecordRead、SecurityConfigRead、SecurityWrite、AlertHandle、Evidence、
// DirectoryRead）所有路由对应的 handler 源码，凡出现「从请求取 tenant」的模式，必须在白名单里并附理由
// （理由必须说明：为什么这是安全的，并有对应的行为测试）。新增路由或改动 handler 引入新的取值模式会让本测试失败，
// 迫使作者回答「A 租户的三员能不能碰到 B 租户」。行为侧见 agent_operation_cross_tenant_test.go 等。

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
)

var tenantFromRequest = regexp.MustCompile(`(?i)(Query\(\)\.Get\("tenant|URL\.Query\(\)\.Get\("tenant_id|Header\.Get\("X-Tenant|FormValue\("tenant|URLParam\(r, "tenant|\breq\.TenantID\b|\bbody\.TenantID\b|\bin\.TenantID\b|\bpayload\.TenantID\b)`)

// 审定过的例外。key = handler 函数名。
var tenantFromRequestAllowed = map[string]string{
	"GetAgentOperationProtection": "tenant_id 经 resolveAgentOperationTarget：非系统管理员只能是自己的租户，否则 403；agent_operation_cross_tenant_test.go 覆盖读/写/全局",
	"PutAgentOperationProtection": "同上",
	"CreateAgentGuardException":   "req.TenantID 在落库前被 user.TenantID 覆盖（agentguard_policy.go），请求里的值无效",
	"CreateAgentGuardRollout":     "同上",
}

// officerSoDClasses 是 SoD 对安全员/审计员放行「业务职责」的类别（审计员专属的 audit/export/login_history 类不在此列，
// 它们的 handler 已由 permission 包与 officer_routes_role_gate_test.go 守护）。
func officerSoDClass(c permission.SoDClass) bool {
	switch c {
	case permission.SoDCommon, permission.SoDSecurityRecordRead, permission.SoDSecurityConfigRead,
		permission.SoDSecurityWrite, permission.SoDAlertHandle, permission.SoDEvidence, permission.SoDDirectoryRead:
		return true
	}
	return false
}

// officerRouteTableOnly 是 SoD 表里登记、但 main.go 并未注册的路由。逐条登记并写明原因；其余扫描不到的一律失败。
var officerRouteTableOnly = map[string]string{
	"POST /admin/v1/internal/agent/heartbeat": "SoD 表为 /internal/agent 系列预留的行，main.go 实际没有注册这条路由（心跳走 internal/agent/endpoints/heartbeat）；TestSoDRouteTableCoversEveryProtectedRoute 只检查 main→表方向",
}

var (
	// r.Get(...) / r.With(...).Get(...) 两种写法；表达式取到行尾括号前。
	officerRouteLineRe = regexp.MustCompile(`^\s*r\.(?:With\([^\n]*?\)\.)?(Get|Post|Put|Patch|Delete)\("(/(?:admin/v1|api)/[^"]+)",\s*(.+)\)\s*$`)
	officerFuncExprRe  = regexp.MustCompile(`^handler\.(\w+)\(.*\)$`)
	officerMethodExpr  = regexp.MustCompile(`^(\w+)\.(\w+)$`)
	officerCtorAssign  = regexp.MustCompile(`(?m)^\s*(\w+)\s*:?=\s*handler\.(New\w+)\(`)
	officerCtorDecl    = regexp.MustCompile(`(?m)^func (New\w+)\([^)]*\)\s*\*?(\w+)\s*\{`)
)

// officerRouteHandlers 返回 路由 -> 函数体键。键是 "函数名"（handler.Xxx(...) 写法）或 "类型.方法名"（agentAdminAPI.Xxx 这类方法值写法）。
// 任何一条对三员放行的路由，只要在 main.go 里找不到注册行、或注册表达式无法解析成函数体，就让测试失败（未知即失败）。
func officerRouteHandlers(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../cmd/server/main.go")
	if err != nil {
		t.Fatal(err)
	}
	main := string(raw)

	// 变量 -> 类型：main.go 里 xxxAPI := handler.NewXxxAPI(...)，再由构造函数声明取返回类型。
	ctorType := map[string]string{}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, _ := os.ReadFile(f)
		for _, m := range officerCtorDecl.FindAllStringSubmatch(string(src), -1) {
			ctorType[m[1]] = m[2]
		}
	}
	varType := map[string]string{}
	for _, m := range officerCtorAssign.FindAllStringSubmatch(main, -1) {
		if typ, ok := ctorType[m[2]]; ok {
			varType[m[1]] = typ
		}
	}

	registered := map[string]string{}
	for _, line := range strings.Split(main, "\n") {
		if m := officerRouteLineRe.FindStringSubmatch(line); m != nil {
			registered[strings.ToUpper(m[1])+" "+m[2]] = strings.TrimSpace(m[3])
		}
	}

	out := map[string]string{}
	var problems []string
	for route := range permission.OfficerRouteKeys() {
		method, path, _ := strings.Cut(route, " ")
		if !officerSoDClass(permission.SoDClassFor(method, path)) {
			continue
		}
		expr, ok := registered[route]
		if !ok {
			if _, allowed := officerRouteTableOnly[route]; !allowed {
				problems = append(problems, route+" → main.go 里找不到注册行（或写法无法识别）")
			}
			continue
		}
		if m := officerFuncExprRe.FindStringSubmatch(expr); m != nil {
			out[route] = m[1]
		} else if m := officerMethodExpr.FindStringSubmatch(expr); m != nil {
			typ, known := varType[m[1]]
			if !known {
				problems = append(problems, route+" → 无法确定 "+m[1]+" 的类型（main.go 里没有 "+m[1]+" := handler.NewXxx(...)）")
				continue
			}
			out[route] = typ + "." + m[2]
		} else {
			problems = append(problems, route+" → 注册表达式无法解析："+expr)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		t.Fatalf("以下对三员放行的路由扫描不到可核对的 handler（未知即失败，请补扫描规则或登记 officerRouteTableOnly）:\n  %s", strings.Join(problems, "\n  "))
	}
	for route := range officerRouteTableOnly {
		if _, ok := registered[route]; ok {
			t.Fatalf("officerRouteTableOnly 里的 %s 现在已在 main.go 注册，请从登记表删除", route)
		}
	}
	return out
}

// officerHandlerBodies 返回 函数体键 -> 源码，键同上；同名方法按接收者类型区分，避免 List/Create 之类互相串。
func officerHandlerBodies(t *testing.T) map[string]string {
	t.Helper()
	files, _ := filepath.Glob("*.go")
	bodies := map[string]string{}
	funcRe := regexp.MustCompile(`(?m)^func (?:\(\s*\w*\s*\*?(\w+)\)\s*)?(\w+)\(`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, _ := os.ReadFile(f)
		src := string(raw)
		idx := funcRe.FindAllStringSubmatchIndex(src, -1)
		for i, m := range idx {
			end := len(src)
			if i+1 < len(idx) {
				end = idx[i+1][0]
			}
			name := src[m[4]:m[5]]
			if m[2] >= 0 {
				name = src[m[2]:m[3]] + "." + name
			}
			bodies[name] += src[m[0]:end]
		}
	}
	return bodies
}

func TestOfficerRoutesNeverTakeTheTenantFromTheRequest(t *testing.T) {
	handlers := officerRouteHandlers(t)
	if len(handlers) < 200 {
		t.Fatalf("路由扫描异常：只找到 %d 个对三员放行的 handler", len(handlers))
	}
	bodies := officerHandlerBodies(t)
	var offenders, missing []string
	for route, name := range handlers {
		body := bodies[name]
		if body == "" {
			missing = append(missing, route+" → "+name)
			continue
		}
		if tenantFromRequest.MatchString(body) {
			if _, ok := tenantFromRequestAllowed[name]; !ok {
				offenders = append(offenders, route+" → "+name)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("以下路由的 handler 找不到函数体，无法核对租户来源（未知即失败）:\n  %s", strings.Join(missing, "\n  "))
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("以下对三员放行的路由从请求取 tenant，请改用会话里的 user.TenantID，或在 tenantFromRequestAllowed 里登记并说明理由、补行为测试:\n  %s", strings.Join(offenders, "\n  "))
	}
	// 白名单不得失真：登记的例外必须仍然存在且仍然命中模式
	for name := range tenantFromRequestAllowed {
		if body, ok := bodies[name]; !ok || !tenantFromRequest.MatchString(body) {
			t.Fatalf("白名单里的 %s 已不再从请求取 tenant（或已删除），请清理", name)
		}
	}
}
