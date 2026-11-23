package repository

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 守门：留存详情（按请求读正文）、会话正文与正文关键字检索的读查询都在关 JIT 的只读事务里执行。
func TestContentLogRetentionReadsRunWithoutJIT(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "content_logs.go")
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"ListBySession": false, "scanContentLogs": false, "ListBySessionPage": false, "ListBySessionPageScoped": false,
		"SearchPage": false, "ListByRequest": false, "ListByRequestScoped": false, "ListByRequests": false, "ListByRequestsScoped": false}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil {
			continue
		}
		if _, tracked := want[fn.Name.Name]; !tracked {
			continue
		}
		want[fn.Name.Name] = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Query" && sel.Sel.Name != "QueryRow") {
				return true
			}
			if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "db" {
				t.Errorf("%s reads through r.db.%s; use r.retentionRead()", fn.Name.Name, sel.Sel.Name)
			}
			return true
		})
	}
	for name, seen := range want {
		if !seen && !strings.HasPrefix(name, "_") {
			t.Errorf("guarded reader %s not found", name)
		}
	}
}
