package main

import (
	"os"
	"strings"
	"testing"
)

func TestNativeEventRoutesUseSeparateAuthGroups(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	internal := strings.Index(s, "// Agent endpoint internal ledger routes")
	protected := strings.Index(s, "// Protected routes (auth required)")
	if internal < 0 || protected <= internal {
		t.Fatal("route groups missing")
	}
	private := s[internal:protected]
	start := strings.Index(private, "r.Use(handler.EndpointAuth(agentEndpointRepo, deps))")
	if start < 0 {
		t.Fatal("EndpointAuth missing")
	}
	end := strings.Index(private[start:], "\n\t\t})")
	if end < 0 {
		t.Fatal("endpoint group boundary missing")
	}
	if !strings.Contains(private[start:start+end], `r.Post("/admin/v1/internal/agent/identity-events", nativeEventAPI.Ingest)`) {
		t.Fatal("native ingest outside endpoint auth")
	}
	prefix := private[:start]
	if !strings.Contains(prefix, "if cfg.AgentEndpointEnabled {") || !strings.Contains(prefix, "r.Use(handler.InternalAPIMiddleware(cfg.InternalAPISecret, deps))") {
		t.Fatal("native ingest lacks private and feature gates")
	}
	admin := s[protected:]
	auth := strings.Index(admin, "r.Use(auth.Middleware(sessionRepo, userRepo))")
	perm := strings.Index(admin, "r.Use(permission.Middleware(permChecker, db, dryRun))")
	lic := strings.Index(admin, "r.Use(handler.LicenseGuard(deps))")
	flag := strings.Index(admin, "if cfg.AgentEndpointEnabled {")
	route := strings.Index(admin, `r.Get("/admin/v1/agent/native-events", nativeEventAPI.List)`)
	if auth < 0 || perm < auth || lic < perm || flag < lic || route < flag {
		t.Fatal("native read lacks auth/permission/license/feature order")
	}
	end = strings.Index(admin[flag:], "\n\t\t}")
	if end < 0 || route >= flag+end {
		t.Fatal("native read outside feature flag")
	}
}
