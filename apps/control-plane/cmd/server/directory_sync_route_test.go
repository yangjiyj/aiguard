package main

import (
	"os"
	"strings"
	"testing"
)

func TestServerDoesNotRegisterLegacyDirectorySyncRoute(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	legacyRoute := `r.Post("/admin/v1/directory/sources/sync", handler.SyncDirectoryAccounts(deps))`
	if strings.Contains(string(source), legacyRoute) {
		t.Fatal("legacy directory sync route bypasses the required preview and confirmation gate")
	}
}
