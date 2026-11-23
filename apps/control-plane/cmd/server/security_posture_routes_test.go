package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

func TestSecurityPostureAliasesStayInProtectedReadOnlyGroup(t *testing.T) {
	source, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{"/admin/v1/security/posture": false, "/api/security/posture": false}
	ast.Inspect(source, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Group" {
			return true
		}
		group, ok := call.Args[0].(*ast.FuncLit)
		if !ok {
			return true
		}
		var guards []string
		for _, statement := range group.Body.List {
			expression, ok := statement.(*ast.ExprStmt)
			if !ok {
				continue
			}
			route, ok := expression.X.(*ast.CallExpr)
			if !ok || len(route.Args) == 0 {
				continue
			}
			method, ok := route.Fun.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if method.Sel.Name == "Use" {
				if guard, ok := route.Args[0].(*ast.CallExpr); ok {
					if function, ok := guard.Fun.(*ast.SelectorExpr); ok {
						if packageName, ok := function.X.(*ast.Ident); ok {
							guards = append(guards, packageName.Name+"."+function.Sel.Name)
						}
					}
				}
				continue
			}
			literal, ok := route.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				continue
			}
			path, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := wanted[path]; !ok {
				continue
			}
			if wanted[path] || method.Sel.Name != "Get" {
				t.Fatalf("posture route %s must have a single GET registration", path)
			}
			expected := []string{"auth.Middleware", "permission.SoDGuard", "permission.Middleware", "handler.LicenseGuard"}
			if len(guards) != len(expected) {
				t.Fatalf("posture route %s has unexpected middleware: %v", path, guards)
			}
			for index, name := range expected {
				if guards[index] != name {
					t.Fatalf("posture route %s middleware order changed: %v", path, guards)
				}
			}
			wanted[path] = true
		}
		return true
	})
	for path, found := range wanted {
		if !found {
			t.Errorf("protected posture GET route missing: %s", path)
		}
	}
}
