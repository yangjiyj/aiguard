package main

// MCP 路由契约测试（验收缺陷 D1）：
//   - 前端 apps/web-console/src/services/api.ts 里调用的每个 /admin/v1/mcp* 路径，control-plane 路由表里必须存在；
//   - gateway-core 通过内部密钥调用的 control-plane 接口（/admin/v1/internal/mcp/*）同样必须存在；
//   - 每个 MCP 相关的管理路由必须在权限表（permission/resolver.go）里登记，否则会按“未登记路由”退化为仅平台管理员可访问。
//
// 背景：W1 并行开发时 mcp_redline_settings.go 的三个 handler 备忘“需集成人在 main.go 接线”，
// 但从未接线，导致红线配置页 404、网关拉取失败后红线只告警。

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	// 测试工作目录是 apps/control-plane/cmd/server。
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

var routeRegistration = regexp.MustCompile(`r(?:\.With\([^)]*\))?\.(Get|Post|Put|Delete|Patch)\("(/[^"]+)"`)

// registeredRoutes 返回 main.go 里注册的全部路由 "METHOD /path"。
func registeredRoutes(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]bool{}
	for _, m := range routeRegistration.FindAllStringSubmatch(string(src), -1) {
		routes[strings.ToUpper(m[1])+" "+m[2]] = true
	}
	return routes
}

// templateToRegexp 把 chi 风格的 /a/{id}/b 与前端 `/a/${x}/b` 都规整成同一形态，便于比较。
var frontendParam = regexp.MustCompile(`\$\{[^}]+\}`)
var chiParam = regexp.MustCompile(`\{[^}/]+\}`)

func normalizePath(p string) string {
	p = frontendParam.ReplaceAllString(p, "{p}")
	p = chiParam.ReplaceAllString(p, "{p}")
	return strings.TrimRight(p, "/")
}

// frontendMCPCalls 解析 api.ts 里对 /mcp* 路径的调用：api.get('/mcp-servers/${id}/sync') 等。
var frontendCall = regexp.MustCompile("api\\.(get|post|put|delete|patch)(?:<[^>(]*>)?\\(\\s*[`'\"](/mcp[^`'\"?]*)")

func frontendMCPCalls(t *testing.T) map[string]bool {
	t.Helper()
	src := readRepoFile(t, "apps/web-console/src/services/api.ts")
	calls := map[string]bool{}
	for _, m := range frontendCall.FindAllStringSubmatch(src, -1) {
		calls[strings.ToUpper(m[1])+" "+normalizePath("/admin/v1"+m[2])] = true
	}
	return calls
}

func TestFrontendMCPCallsAreAllRegisteredRoutes(t *testing.T) {
	registered := map[string]bool{}
	for k := range registeredRoutes(t) {
		method, path, _ := strings.Cut(k, " ")
		registered[method+" "+normalizePath(path)] = true
	}
	calls := frontendMCPCalls(t)
	// 解析器自检：解析结果必须覆盖已知的关键调用，避免正则静默失效后测试“空转通过”。
	for _, must := range []string{
		"GET /admin/v1/mcp-servers", "POST /admin/v1/mcp-servers/{p}/sync", "PUT /admin/v1/mcp-policies/{p}",
		"GET /admin/v1/mcp-redline-settings", "PUT /admin/v1/mcp-redline-settings", "GET /admin/v1/mcp-audit/export",
	} {
		if !calls[must] {
			t.Fatalf("parser sanity: expected to parse the console call %q, got %d calls", must, len(calls))
		}
	}
	if len(calls) < 15 {
		t.Fatalf("parser sanity: expected at least 15 /mcp* console calls, parsed %d", len(calls))
	}
	var missing []string
	for call := range calls {
		if !registered[call] {
			missing = append(missing, call)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("前端调用了 control-plane 路由表里不存在的 MCP 接口（会得到 404）：\n  %s", strings.Join(missing, "\n  "))
	}
}

// gateway-core 调用的 control-plane 内部 MCP 接口必须存在。
func TestGatewayInternalMCPEndpointsAreRegistered(t *testing.T) {
	registered := registeredRoutes(t)
	for _, want := range []string{
		"GET /admin/v1/internal/mcp/effective-policy",
		"GET /admin/v1/internal/mcp/policy-contract",
		"GET /admin/v1/internal/mcp/redline-settings",
	} {
		if !registered[want] {
			t.Errorf("gateway-core 依赖的内部接口未注册：%s", want)
		}
	}
	// 网关代码里实际使用的内部 MCP 路径也要都在路由表里（避免“网关新增了调用、控制面忘了注册”）。
	gwSrc := readRepoFile(t, "apps/gateway-core/internal/handler/mcp_policy_client.go") +
		readRepoFile(t, "apps/gateway-core/internal/handler/mcp_redline_settings.go") +
		readRepoFile(t, "apps/gateway-core/internal/handler/mcp_confirmation_client.go")
	used := regexp.MustCompile(`"(/admin/v1/internal/[a-z0-9/_-]+)`).FindAllStringSubmatch(gwSrc, -1)
	if len(used) == 0 {
		t.Fatal("parser sanity: gateway-core MCP client sources should reference internal control-plane paths")
	}
	norm := map[string]bool{}
	for k := range registered {
		_, p, _ := strings.Cut(k, " ")
		norm[normalizePath(p)] = true
	}
	for _, m := range used {
		p := strings.TrimRight(m[1], "/")
		if !norm[normalizePath(p)] {
			t.Errorf("gateway-core 调用的内部接口在 control-plane 路由表中不存在：%s", p)
		}
	}
}

// 每条 MCP 相关管理路由都要在权限表登记：未登记的路由退化为“仅平台管理员”，tenant_admin 会被误拒。
func TestMCPAdminRoutesAreRegisteredInPermissionTable(t *testing.T) {
	resolver := readRepoFile(t, "apps/control-plane/internal/permission/resolver.go")
	internal := map[string]bool{ // 内部密钥通道不走用户权限表
		"/admin/v1/internal/mcp/effective-policy": true, "/admin/v1/internal/mcp/policy-contract": true,
		"/admin/v1/internal/mcp/redline-settings": true,
	}
	var missing []string
	for k := range registeredRoutes(t) {
		method, path, _ := strings.Cut(k, " ")
		if !strings.HasPrefix(path, "/admin/v1/mcp") || internal[path] {
			continue
		}
		if !strings.Contains(resolver, `"`+method+" "+path+`"`) {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("MCP 管理路由未在 permission/resolver.go 登记：\n  %s", strings.Join(missing, "\n  "))
	}
}
