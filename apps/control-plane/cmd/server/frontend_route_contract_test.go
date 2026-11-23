package main

// 前端 API 全量路由契约测试。
//
// 背景：web-console 的 pricingApi.syncStatus / pricingApi.update 调用的 /prices/sync-status 与 PUT /prices/{id}
// 在 8 月的“定价单一来源”改造（6a41c42a6）里被后端删除，前端 PricesFx 页面与 api 层却没有同步清理，
// 之后一直是 404 的死代码。本测试把“前端调用的 /admin/v1 路径必须在后端路由表里存在”固化下来，
// 防止同类漂移再次发生。
//
// 比对口径：
//   - 前端侧：扫描 apps/web-console/src 下非测试源码里 api / apiClient 的 get|post|put|patch|delete 调用，
//     以及所有以 /admin/v1/ 开头的字符串字面量（下载链接、常量等）；
//   - 后端侧：扫描 control-plane 全部非测试 Go 源码里的路由注册（chi 风格 Get/Post/Put/Patch/Delete/Handle/Method...）。
//     console 的 nginx / server.js 把 /admin/ 整体转发给 control-plane，所以 gateway-core 自己注册的
//     /admin/v1 路由前端实际打不到，只在单独的检查里使用；
//   - 路径参数统一归一化：前端 ${x}、chi {id}、chi 通配符 /* 都按“单段参数”比较。

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func feRepoRoot(t *testing.T) string {
	t.Helper()
	// 测试工作目录是 apps/control-plane/cmd/server。
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func feWalk(t *testing.T, dir string, accept func(path string) bool) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "node_modules", "dist", ".git", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if accept(path) {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

var (
	feParamTpl   = regexp.MustCompile(`\$\{[^}]*\}`)
	feChiParam   = regexp.MustCompile(`\{[^}/]*\}`)
	feWildcard   = regexp.MustCompile(`/\*$`)
	feMultiSlash = regexp.MustCompile(`/{2,}`)
)

// feNormalize 把前端模板、chi 参数、chi 通配符统一成 {p}，并去掉查询串与尾部斜杠。
func feNormalize(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = feWildcard.ReplaceAllString(p, "/{*}")
	p = feParamTpl.ReplaceAllString(p, "{p}")
	p = feChiParam.ReplaceAllString(p, "{p}")
	p = feMultiSlash.ReplaceAllString(p, "/")
	return strings.TrimRight(p, "/")
}

// ---------- 后端路由表 ----------

var feRouteReg = regexp.MustCompile(`\.(Get|Post|Put|Patch|Delete|Head|Options|Handle|HandleFunc)\(\s*"(/[^"]*)"`)
var feMethodReg = regexp.MustCompile(`\.(?:Method|MethodFunc)\(\s*(?:"([A-Z]+)"|http\.Method(\w+))\s*,\s*"(/[^"]*)"`)

// feBackendRoutes 返回某个应用目录下注册的全部路由：key 为 "METHOD 归一化路径"，Handle 类（不限方法）记为 ANY。
func feBackendRoutes(t *testing.T, appDir string) map[string]bool {
	t.Helper()
	files := feWalk(t, filepath.Join(feRepoRoot(t), appDir), func(p string) bool {
		return strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go")
	})
	routes := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, m := range feRouteReg.FindAllStringSubmatch(src, -1) {
			method := strings.ToUpper(m[1])
			if method == "HANDLE" || method == "HANDLEFUNC" {
				method = "ANY"
			}
			routes[method+" "+feNormalize(m[2])] = true
		}
		for _, m := range feMethodReg.FindAllStringSubmatch(src, -1) {
			method := m[1]
			if method == "" {
				method = strings.ToUpper(m[2])
			}
			routes[method+" "+feNormalize(m[3])] = true
		}
	}
	return routes
}

// feRouteMatches 判断 “METHOD path” 是否被路由表覆盖。
//   - 按路径段比较：任一侧是参数 {p} 都视为匹配（前端 `${variant}` 对后端的字面量段 preview/original，
//     或前端字面量 network_egress 对后端的 {key}）；
//   - 路由表里的 {*} 通配符匹配其前缀下任意子路径；
//   - 路由表的 ANY（Handle）匹配任意方法；调用方法为 ANY（字符串字面量，如下载链接）匹配任意方法的路由。
func feRouteMatches(routes map[string]bool, method, path string) bool {
	segs := strings.Split(path, "/")
	for k := range routes {
		rm, rp, _ := strings.Cut(k, " ")
		if method != "ANY" && rm != "ANY" && rm != method {
			continue
		}
		rsegs := strings.Split(rp, "/")
		ok := true
		for i, rs := range rsegs {
			if rs == "{*}" {
				break
			}
			if i >= len(segs) {
				ok = false
				break
			}
			if rs != segs[i] && rs != "{p}" && segs[i] != "{p}" {
				ok = false
				break
			}
			if i == len(rsegs)-1 && len(segs) != len(rsegs) {
				ok = false
			}
		}
		if ok && (len(rsegs) > 0 && rsegs[len(rsegs)-1] == "{*}" || len(segs) == len(rsegs)) {
			return true
		}
	}
	return false
}

// feJoinConcat 处理 '/a/' + encodeURIComponent(id) + '/sources' 这类顶层 + 拼接：
// 字符串字面量原样拼接，非字面量操作数记为参数 {p}。仅当首个操作数是以 / 开头的字面量时生效。
func feJoinConcat(expr string, consts map[string]string) (string, bool) {
	var parts []string
	depth, last := 0, 0
	var quote byte
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '?', ':':
			if depth == 0 {
				return "", false // 三元表达式走常规路径
			}
		case '+':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(expr[last:i]))
				last = i + 1
			}
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	parts = append(parts, strings.TrimSpace(expr[last:]))
	var b strings.Builder
	for i, part := range parts {
		m := feStringLit.FindStringSubmatch(part)
		if m != nil && m[0] == part {
			lit := m[1] + m[2] + m[3]
			if i == 0 && !strings.HasPrefix(lit, "/") {
				return "", false
			}
			b.WriteString(lit)
		} else {
			if i == 0 {
				return "", false
			}
			b.WriteString("{p}")
		}
	}
	return b.String(), true
}

// ---------- 前端调用扫描 ----------

type feCall struct {
	Method string // GET/POST/...；字符串字面量下载链接等记为 ANY
	Path   string // 归一化后的完整路径（含 /admin/v1 前缀）
	Where  string // 文件:行号
}

type feUnresolved struct {
	Where string
	Expr  string
}

// ws8Blob(url, params) 是 api.ts 里对 api.get 的薄封装（导出下载），按 GET 处理。
var feCallStart = regexp.MustCompile(`\b(?:api|apiClient)\.(get|post|put|patch|delete)\b|\b(ws8Blob)\(`)
var feConstDecl = regexp.MustCompile("const\\s+(\\w+)\\s*=\\s*(['\"`])(/[^'\"`$]*)['\"`]")
var feAdminLiteral = regexp.MustCompile("['\"`](/admin/v1/[^'\"`\\s]*)")
var feStringLit = regexp.MustCompile("`([^`]*)`|'([^']*)'|\"([^\"]*)\"")

func feLine(src string, idx int) int { return strings.Count(src[:idx], "\n") + 1 }

// feSkipGeneric 跳过 api.get<...>( 里的泛型参数（可跨行、含 =>）。idx 指向 '<'，返回 '>' 之后的位置。
func feSkipGeneric(src string, idx int) int {
	depth := 0
	for i := idx; i < len(src); i++ {
		switch src[i] {
		case '<':
			depth++
		case '>':
			if i > 0 && src[i-1] == '=' { // 箭头函数 =>
				continue
			}
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return idx
}

// feFirstArg 取出调用的第一个实参文本（到顶层逗号或右括号为止），idx 指向 '(' 之后。
func feFirstArg(src string, idx int) string {
	depth := 0
	var quote byte
	for i := idx; i < len(src); i++ {
		c := src[i]
		if quote != 0 {
			if c == '\\' {
				i++
				continue
			}
			if quote == '`' && c == '$' && i+1 < len(src) && src[i+1] == '{' {
				// 模板里的 ${...}：整体跳过，允许嵌套括号
				d := 0
				for j := i + 1; j < len(src); j++ {
					if src[j] == '{' {
						d++
					} else if src[j] == '}' {
						d--
						if d == 0 {
							i = j
							break
						}
					}
				}
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return src[idx:i]
			}
			depth--
		case ',':
			if depth == 0 {
				return src[idx:i]
			}
		}
	}
	return src[idx:]
}

// feExtractPaths 从实参表达式里取出所有以 / 开头的路径字面量（支持三元、拼接）；
// ${ident} 若是文件内的字符串常量则展开，否则记为参数。
func feExtractPaths(expr string, consts map[string]string) []string {
	if joined, ok := feJoinConcat(expr, consts); ok {
		return []string{joined}
	}
	var out []string
	for _, loc := range feStringLit.FindAllStringSubmatchIndex(expr, -1) {
		lit := ""
		for g := 1; g <= 3; g++ {
			if loc[2*g] >= 0 {
				lit = expr[loc[2*g]:loc[2*g+1]]
			}
		}
		tail := strings.TrimSpace(expr[loc[1]:])
		lit = regexp.MustCompile(`\$\{\s*(\w+)\s*\}`).ReplaceAllStringFunc(lit, func(s string) string {
			name := strings.Trim(s, "${} ")
			if v, ok := consts[name]; ok {
				return v
			}
			return s
		})
		if !strings.HasPrefix(lit, "/") || lit == "/admin/v1" {
			continue // "/admin/v1" 单独出现时是 slice('/admin/v1'.length) 之类的前缀运算，不是请求路径
		}
		// '/x/' + encodeURIComponent(id)：以斜杠结尾且后面还有拼接，补一个参数段。
		if strings.HasSuffix(lit, "/") && strings.HasPrefix(tail, "+") {
			lit += "{p}"
		}
		out = append(out, lit)
	}
	return out
}

func feFrontendCalls(t *testing.T) ([]feCall, []feUnresolved) {
	t.Helper()
	srcRoot := filepath.Join(feRepoRoot(t), "apps", "web-console", "src")
	files := feWalk(t, srcRoot, func(p string) bool {
		if !(strings.HasSuffix(p, ".ts") || strings.HasSuffix(p, ".tsx")) {
			return false
		}
		rel, _ := filepath.Rel(srcRoot, p)
		return !strings.HasPrefix(rel, "test"+string(filepath.Separator)) &&
			!strings.Contains(rel, ".test.") && !strings.Contains(rel, ".spec.")
	})
	var calls []feCall
	var unresolved []feUnresolved
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		rel, _ := filepath.Rel(feRepoRoot(t), f)
		consts := map[string]string{}
		for _, m := range feConstDecl.FindAllStringSubmatch(src, -1) {
			consts[m[1]] = m[3]
		}
		for _, loc := range feCallStart.FindAllStringSubmatchIndex(src, -1) {
			method := "GET"
			if loc[2] >= 0 {
				method = strings.ToUpper(src[loc[2]:loc[3]])
			}
			i := loc[1]
			if loc[4] >= 0 { // ws8Blob( 已经带了左括号，回退一位交给下面统一处理
				i = loc[1] - 1
			}
			for i < len(src) && (src[i] == ' ' || src[i] == '\n' || src[i] == '\t') {
				i++
			}
			if i < len(src) && src[i] == '<' {
				i = feSkipGeneric(src, i)
			}
			for i < len(src) && (src[i] == ' ' || src[i] == '\n' || src[i] == '\t') {
				i++
			}
			if i >= len(src) || src[i] != '(' {
				continue // 不是调用（如 api.get 作为值传递）
			}
			expr := feFirstArg(src, i+1)
			where := rel + ":" + itoa(feLine(src, loc[0]))
			paths := feExtractPaths(expr, consts)
			if len(paths) == 0 {
				unresolved = append(unresolved, feUnresolved{Where: where, Expr: strings.TrimSpace(expr)})
				continue
			}
			for _, p := range paths {
				calls = append(calls, feCall{Method: method, Path: feNormalize("/admin/v1" + p), Where: where})
			}
		}
		for _, loc := range feAdminLiteral.FindAllStringSubmatchIndex(src, -1) {
			p := src[loc[2]:loc[3]]
			// 注释里的说明（// Backend: GET /admin/v1/...）不以引号开头，不会命中；这里只收真正的字符串字面量。
			calls = append(calls, feCall{Method: "ANY", Path: feNormalize(p), Where: rel + ":" + itoa(feLine(src, loc[0]))})
		}
	}
	return calls, unresolved
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// ---------- 白名单 ----------

// feKnownMissing：确认是死代码或历史遗留、暂不处理的“前端有调用、后端无路由”。
// key 为 "METHOD 归一化路径"，value 必须写明原因。新增条目需要评审；目标是保持为空。
var feKnownMissing = map[string]string{}

// feUnresolvedAllow：调用路径不是字面量、扫描器无法静态解析的位置，已人工核对其实际路径。
// key 为 "文件:表达式前缀"，value 写明已核对的实际路径与结论。
var feUnresolvedAllow = map[string]string{
	"apps/web-console/src/services/api.ts|url":                       "ws8Blob 内部的 api.get(url,...)；其全部调用方 ws8Blob('/...') 已被单独扫描并参与比对",
	"apps/web-console/src/services/alertOccurrences.ts|OPERATIONAL_": "路径来自同文件常量 OPERATIONAL_LIST_PATH / OPERATIONAL_SUMMARY_PATH 再 slice 掉 /admin/v1 前缀；两个常量以 /admin/v1 字面量被单独扫描并参与比对",
}

// ---------- 测试 ----------

func TestFrontendAPICallsAreAllRegisteredInControlPlane(t *testing.T) {
	cp := feBackendRoutes(t, "apps/control-plane")
	calls, _ := feFrontendCalls(t)

	// 解析器自检：避免正则静默失效后测试“空转通过”。
	if len(calls) < 300 {
		t.Fatalf("parser sanity: 期望至少解析出 300 个前端 /admin/v1 调用，实际 %d", len(calls))
	}
	seen := map[string]bool{}
	for _, c := range calls {
		seen[c.Method+" "+c.Path] = true
	}
	for _, must := range []string{
		"GET /admin/v1/billing/prices", "POST /admin/v1/billing/prices", "GET /admin/v1/mcp-servers",
		"PUT /admin/v1/system/settings", "GET /admin/v1/agent/endpoints/{p}",
	} {
		if !seen[must] {
			t.Fatalf("parser sanity: 期望解析出前端调用 %q", must)
		}
	}
	if len(cp) < 500 {
		t.Fatalf("parser sanity: control-plane 路由表应有 500+ 条，实际 %d", len(cp))
	}

	missing := map[string][]string{}
	for _, c := range calls {
		if feRouteMatches(cp, c.Method, c.Path) {
			continue
		}
		key := c.Method + " " + c.Path
		if _, ok := feKnownMissing[key]; ok {
			continue
		}
		missing[key] = append(missing[key], c.Where)
	}
	if len(missing) > 0 {
		var keys []string
		for k := range missing {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			b.WriteString("\n  " + k + "  <- " + strings.Join(missing[k], ", "))
		}
		t.Fatalf("前端调用了 control-plane 路由表里不存在的接口（运行时会 404）：%s", b.String())
	}
	// 白名单不得积灰：条目一旦有了后端路由，或前端不再调用，就必须删掉。
	for k := range feKnownMissing {
		method, path, _ := strings.Cut(k, " ")
		if feRouteMatches(cp, method, path) {
			t.Errorf("白名单条目 %q 已有后端路由，请从 feKnownMissing 删除", k)
		}
		if !seen[k] {
			t.Errorf("白名单条目 %q 前端已不再调用，请从 feKnownMissing 删除", k)
		}
	}
}

// 非字面量路径的调用无法静态比对，必须逐条人工登记，防止新增的动态调用绕过契约。
func TestFrontendDynamicAPICallsAreReviewed(t *testing.T) {
	_, unresolved := feFrontendCalls(t)
	var offenders []string
	used := map[string]bool{}
	for _, u := range unresolved {
		file, _, _ := strings.Cut(u.Where, ":")
		matched := false
		for k := range feUnresolvedAllow {
			f, prefix, _ := strings.Cut(k, "|")
			if f == file && strings.HasPrefix(u.Expr, prefix) {
				matched, used[k] = true, true
			}
		}
		if !matched {
			offenders = append(offenders, u.Where+"  "+u.Expr)
		}
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("存在无法静态解析路径的前端 API 调用，请改成字面量路径或在 feUnresolvedAllow 登记（写明实际路径）：\n  %s",
			strings.Join(offenders, "\n  "))
	}
	for k := range feUnresolvedAllow {
		if !used[k] {
			t.Errorf("feUnresolvedAllow 条目 %q 已无对应调用，请删除", k)
		}
	}
}

// gateway-core 只在自己的监听端口注册少量 /admin/v1 路由；console 的 /admin/ 流量全部去 control-plane，
// 所以前端不得依赖这些仅存在于 gateway-core 的路径。
func TestFrontendDoesNotDependOnGatewayOnlyAdminRoutes(t *testing.T) {
	cp := feBackendRoutes(t, "apps/control-plane")
	gw := feBackendRoutes(t, "apps/gateway-core")
	calls, _ := feFrontendCalls(t)
	for _, c := range calls {
		if feRouteMatches(gw, c.Method, c.Path) && !feRouteMatches(cp, c.Method, c.Path) {
			t.Errorf("前端调用 %s %s（%s）只在 gateway-core 注册，console 的 /admin/ 流量不会到达 gateway-core", c.Method, c.Path, c.Where)
		}
	}
}
