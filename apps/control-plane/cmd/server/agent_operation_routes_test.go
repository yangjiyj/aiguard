package main

import (
	"os"
	"strings"
	"testing"
)

func TestServerRegistersAgentOperationRepositoryAndRoutes(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	for _, required := range []string{
		"agentOperationRepo := repository.NewAgentOperationRepository(db)",
		"AgentOperationRepo:",
		`r.Get("/admin/v1/agent-operation-protection", handler.GetAgentOperationProtection(deps))`,
		`r.Put("/admin/v1/agent-operation-protection", handler.PutAgentOperationProtection(deps))`,
		`r.Get("/admin/v1/agent-operation-events", handler.ListAgentOperationEvents(deps))`,
		`r.Get("/admin/v1/agent-operation-events/{public_event_id}", handler.GetAgentOperationEvent(deps))`,
	} {
		if !strings.Contains(string(source), required) {
			t.Fatalf("main.go missing %q", required)
		}
	}
}
