package main

import (
	"os"
	"strings"
	"testing"
)

func TestAgentAdminRoutesAreFeatureFlaggedInsideProtectedGroup(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	protected := strings.Index(source, "r.Use(auth.Middleware(sessionRepo, userRepo))")
	permission := strings.Index(source, "r.Use(permission.Middleware(permChecker, db, dryRun))")
	license := strings.Index(source, "r.Use(handler.LicenseGuard(deps))")
	flag := strings.Index(source[protected:], "if cfg.AgentEndpointEnabled {")
	if protected < 0 || permission < protected || license < permission || flag < 0 {
		t.Fatal("agent admin routes are not under session auth, permission, LicenseGuard and feature flag")
	}
	block := source[protected+flag:]
	end := strings.Index(block, "\n\t\t}")
	if end < 0 {
		t.Fatal("feature-flagged route block end not found")
	}
	block = block[:end]
	for _, route := range []string{
		`r.Get("/admin/v1/agent/overview"`,
		`r.Get("/admin/v1/agent/endpoints"`,
		`r.Get("/admin/v1/agent/endpoints/{id}"`,
		`r.Put("/admin/v1/agent/endpoints/{id}/mode"`,
		`r.Post("/admin/v1/agent/endpoints/{id}/revoke"`,
		`r.Post("/admin/v1/agent/endpoints/{id}/rotate-token"`,
		`r.Get("/admin/v1/agent/enrollment-tokens"`,
		`r.Post("/admin/v1/agent/enrollment-tokens"`,
		`r.Post("/admin/v1/agent/enrollment-tokens/{id}/revoke"`,
		`r.Get("/admin/v1/agent/sessions"`,
		`r.Get("/admin/v1/agent/sessions/{id}"`,
		`r.Get("/admin/v1/agent/events"`,
		`r.Get("/admin/v1/agent/assets"`,
		`r.Get("/admin/v1/agent/policy-bundles"`,
		`r.Get("/admin/v1/agent/policy-bundles/current"`,
	} {
		if !strings.Contains(block, route) {
			t.Errorf("feature-flagged protected block missing %s", route)
		}
	}
}
