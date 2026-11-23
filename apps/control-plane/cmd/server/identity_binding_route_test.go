package main

import (
	"os"
	"regexp"
	"testing"
)

func TestServerRegistersSetUserDepartmentAutomaticRoute(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	route := regexp.MustCompile(
		`r\.Post\("/admin/v1/users/\{id\}/department/automatic",\s*` +
			`handler\.SetUserDepartmentAutomatic\(deps\)\)`,
	)
	if !route.Match(source) {
		t.Fatal("SetUserDepartmentAutomatic POST route is not registered")
	}
}
