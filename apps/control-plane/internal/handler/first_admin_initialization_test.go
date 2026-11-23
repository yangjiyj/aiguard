package handler

import (
	"os"
	"strings"
	"testing"
)

func TestAdminLoginDoesNotTriggerEnterpriseInitialization(t *testing.T) {
	source, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	start := strings.Index(text, "func Login(deps *Dependencies)")
	if start < 0 {
		t.Fatalf("unable to locate Login handler")
	}
	end := strings.Index(text[start:], "func Logout(deps *Dependencies)")
	if end < 0 {
		t.Fatalf("unable to isolate Login handler")
	}
	login := text[start : start+end]
	if strings.Contains(login, "runFirstAdminInitialization") || strings.Contains(login, ".Initialize(") {
		t.Fatalf("admin login must not trigger enterprise initialization")
	}
}
