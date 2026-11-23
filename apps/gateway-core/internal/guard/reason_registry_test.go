package guard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// cardGovernedReasons 是不属于防护项、但能写成阻断或确认的原因码。它们都由
// 管理员可配置的东西决定处置：六类卡片规则、未配置规则时的“未配置规则的高风险调用”
// 阶段项（agent.high_risk_without_rule），或管理员在某个页面上的手动操作。
// 新增原因码必须登记为防护项，或在这里写明归谁管；不允许整批塞进来。
var cardGovernedReasons = map[string]string{
	"behavior_sensitive_read_then_egress":  "网络外联卡片的“读敏感文件后外发”窗口（填 0 关闭）",
	"blocked_destructive_sql":              "数据库变更卡片；未配置规则时按“未配置规则的高风险调用”",
	"command_not_allowlisted":              "系统命令卡片；未配置规则时只告警",
	"destructive_command_requires_confirm": "删除与破坏卡片",
	"scoped_mutation_requires_confirm":     "数据库变更卡片",
	"sensitive_personal_data_egress":       "网络外联卡片",
	"shell_interpolation_requires_confirm": "系统命令卡片",
	"skill_version_quarantined":            "管理员在 Skill 安全准入页手动隔离",
	"skill_version_revoked":                "管理员在 Skill 安全准入页手动撤销",
	"tainted_irreversible_file_operation":  "敏感资源访问卡片；未配置规则时按“未配置规则的高风险调用”",
	"tainted_irreversible_network_egress":  "网络外联卡片；未配置规则时按“未配置规则的高风险调用”",
}

// enforcingReasons 用语法树找出 dir 下非测试代码里写成
// Decision{RawDecision: DecisionBlock|DecisionConfirm, Reason: <字面量或常量>} 的原因码。
func enforcingReasons(t *testing.T, dirs ...string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	// 常量可能写成字面量，也可能引用别的常量（含 shared-go/protection 的原因码常量），
	// 先收集表达式、最后按名字逐层解析。
	constExprs := map[string]ast.Expr{}
	collectConsts := func(f *ast.File) {
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						constExprs[name.Name] = vs.Values[i]
					}
				}
			}
		}
	}
	var files []*ast.File
	var names []string
	parseDir := func(dir string, scan bool) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			collectConsts(f)
			if scan {
				files = append(files, f)
				names = append(names, path)
			}
		}
	}
	for _, dir := range dirs {
		parseDir(dir, true)
	}
	parseDir(filepath.Join(repoRoot(t), "packages/shared-go/protection"), false)
	var resolveConst func(expr ast.Expr, depth int) string
	resolveConst = func(expr ast.Expr, depth int) string {
		if depth > 8 {
			return ""
		}
		switch x := expr.(type) {
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				if v, err := strconv.Unquote(x.Value); err == nil {
					return v
				}
			}
		case *ast.Ident:
			if next, ok := constExprs[x.Name]; ok {
				return resolveConst(next, depth+1)
			}
		case *ast.SelectorExpr:
			if next, ok := constExprs[x.Sel.Name]; ok {
				return resolveConst(next, depth+1)
			}
		}
		return ""
	}
	consts := map[string]string{}
	for name, expr := range constExprs {
		if v := resolveConst(expr, 0); v != "" {
			consts[name] = v
		}
	}
	isDecisionType := func(expr ast.Expr) bool {
		switch x := expr.(type) {
		case *ast.Ident:
			return x.Name == "Decision"
		case *ast.SelectorExpr:
			return x.Sel.Name == "Decision"
		}
		return false
	}
	enforcing := func(expr ast.Expr) bool {
		name := ""
		switch x := expr.(type) {
		case *ast.Ident:
			name = x.Name
		case *ast.SelectorExpr:
			name = x.Sel.Name
		}
		return name == "DecisionBlock" || name == "DecisionConfirm"
	}
	resolve := func(expr ast.Expr) string {
		switch x := expr.(type) {
		case *ast.BasicLit:
			if v, err := strconv.Unquote(x.Value); err == nil {
				return v
			}
		case *ast.Ident:
			return consts[x.Name]
		case *ast.SelectorExpr:
			return consts[x.Sel.Name]
		}
		return ""
	}
	out := map[string]string{}
	for i, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isDecisionType(lit.Type) {
				return true
			}
			var raw, reason ast.Expr
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				switch key := kv.Key.(*ast.Ident); {
				case key == nil:
				case key.Name == "RawDecision":
					raw = kv.Value
				case key.Name == "Reason":
					reason = kv.Value
				}
			}
			if raw == nil || reason == nil || !enforcing(raw) {
				return true
			}
			if v := resolve(reason); v != "" {
				out[v] = filepath.Base(names[i]) + ":" + strconv.Itoa(fset.Position(lit.Pos()).Line)
			}
			return true
		})
	}
	return out
}

func TestEveryEnforcingReasonIsConfigurable(t *testing.T) {
	root := repoRoot(t)
	reasons := enforcingReasons(t,
		filepath.Join(root, "apps/gateway-core/internal/agentguard"),
		filepath.Join(root, "apps/gateway-core/internal/handler"),
	)
	if len(reasons) == 0 {
		t.Fatal("没有收集到任何原因码，扫描失效")
	}
	keys := make([]string, 0, len(reasons))
	for r := range reasons {
		keys = append(keys, r)
	}
	sort.Strings(keys)
	for _, r := range keys {
		if _, ok := protection.ItemForReason(r); ok {
			continue
		}
		if _, ok := cardGovernedReasons[r]; ok {
			continue
		}
		t.Errorf("原因码 %q（%s）会产生阻断或确认，但既不是防护项也没归入卡片管辖：登记到 packages/shared-go/protection，或在 cardGovernedReasons 写明归谁管", r, reasons[r])
	}
	for r := range cardGovernedReasons {
		if _, ok := protection.ItemForReason(r); ok {
			t.Errorf("%q 已是防护项，从 cardGovernedReasons 删除", r)
		}
	}
}
