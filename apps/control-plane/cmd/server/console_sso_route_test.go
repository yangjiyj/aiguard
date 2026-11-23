package main

import (
	"os"
	"strings"
	"testing"
)

func TestServerDoesNotRegisterConsoleSSORoutes(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"/admin/v1/auth/sso/", "MountConsoleSSOProviders", "MountConsoleSSOBindings"} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("retired console SSO surface mounted: %s", forbidden)
		}
	}
	if !strings.Contains(string(source), `r.Post("/admin/v1/login", handler.Login(deps))`) {
		t.Fatal("local console login missing")
	}
}

func TestLoadConsoleSSOConfigDisabledWithoutRuntime(t *testing.T) {
	cfg := loadConsoleSSOConfig(func(string) string { return "" })
	if cfg.Validate() == nil {
		t.Fatal("console SSO must stay disabled without identity runtime configuration")
	}
}
