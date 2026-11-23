package handler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestIdentityHandlersUseBoundedFailureLogs(t *testing.T) {
	for _, filename := range []string{"portal_integration.go", "org_handler.go"} {
		filename := filename
		t.Run(filename, func(t *testing.T) {
			files := token.NewFileSet()
			parsed, err := parser.ParseFile(files, filename, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := selector.X.(*ast.Ident)
				if !ok || pkg.Name != "log" {
					return true
				}
				switch selector.Sel.Name {
				case "Print", "Printf", "Println":
				default:
					return true
				}
				position := files.Position(call.Pos())
				if len(call.Args) == 0 {
					t.Errorf("%s: log call has no bounded diagnostic message", position)
					return true
				}
				literal, ok := call.Args[0].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Errorf("%s: log message must be a fixed string", position)
				} else {
					message, unquoteErr := strconv.Unquote(literal.Value)
					if unquoteErr != nil {
						t.Errorf("%s: invalid log message: %v", position, unquoteErr)
					} else {
						for _, field := range []string{"component=", "stage=", "error_code="} {
							if !strings.Contains(message, field) {
								t.Errorf("%s: bounded log message missing %s", position, field)
							}
						}
					}
				}
				for _, arg := range call.Args[1:] {
					ast.Inspect(arg, func(node ast.Node) bool {
						if ident, ok := node.(*ast.Ident); ok && ident.Name == "err" {
							t.Errorf("%s: raw err passed to log.%s", position, selector.Sel.Name)
						}
						return true
					})
				}
				return true
			})
		})
	}
}
func TestGetTeamEffectiveDoesNotReturnRawErrors(t *testing.T) {
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, "iam_handler.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var target *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "GetTeamEffective" {
			target = function
			break
		}
	}
	if target == nil {
		t.Fatal("GetTeamEffective not found")
	}
	ast.Inspect(target.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		function, ok := call.Fun.(*ast.Ident)
		if !ok || (function.Name != "writeError" && function.Name != "writeErrorWithStatus") {
			return true
		}
		for _, arg := range call.Args {
			ast.Inspect(arg, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				receiver, receiverOK := selector.X.(*ast.Ident)
				if ok && receiverOK && receiver.Name == "err" && selector.Sel.Name == "Error" {
					t.Errorf("%s: raw err.Error() returned in HTTP response", files.Position(call.Pos()))
				}
				return true
			})
		}
		return true
	})
}
