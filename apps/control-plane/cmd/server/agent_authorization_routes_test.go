package main

import (
	"os"
	"strings"
	"testing"
)

func TestAgentAuthorizationRoutesAreFlaggedAndUseSeparateCredentialAuth(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		"agentAuthorizationRepo := repository.NewAgentAuthorizationRepository(db)",
		"agentAuthorizationAPI := handler.NewAgentAuthorizationAPI(agentAuthorizationRepo, deps)",
		"r.Use(agentAuthorizationAPI.Authenticate)",
		`r.Post("/admin/v1/agent/authorize", agentAuthorizationAPI.Authorize)`,
		`r.Post("/admin/v1/agent/principals", agentAuthorizationAPI.RegisterPrincipal)`,
		`r.Post("/admin/v1/agent/principals/{id}/revoke", agentAuthorizationAPI.RevokePrincipal)`,
		`r.Post("/admin/v1/agent/principals/{id}/rotate-token", agentAuthorizationAPI.RotatePrincipalCredential)`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("main.go missing %q", required)
		}
	}
	flag := strings.Index(source, "if cfg.AgentEndpointEnabled {")
	authGroup := strings.Index(source[flag:], "r.Use(agentAuthorizationAPI.Authenticate)")
	protected := strings.Index(source, "r.Use(auth.Middleware(sessionRepo, userRepo))")
	if flag < 0 || authGroup < 0 || protected < 0 || flag+authGroup >= protected {
		t.Fatal("machine authorization route must be behind the agent feature flag and outside the session-only group")
	}
}
