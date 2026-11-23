package handler

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestWS5HandlerResolvesToolTypeFromDefinitionAndConfig(t *testing.T) {
	h := &ChatCompletionsHandler{agentGuardToolTypes: newAgentGuardToolTypeCache()}
	tenantA := &modelrouter.RequestEnvelope{TenantID: "tenant-a"}
	tenantB := &modelrouter.RequestEnvelope{TenantID: "tenant-b"}

	if got := h.resolveAgentGuardToolType(tenantA, "acme_sync"); got != agentguard.ToolTypeUnknown {
		t.Fatalf("unseen custom tool = %q, want unknown", got)
	}
	h.rememberAgentGuardToolDefinition(tenantA, ToolDef{Type: "function", Function: ToolFunc{Name: "acme_sync", Parameters: json.RawMessage(`{"properties":{"command":{}}}`)}})
	if got := h.resolveAgentGuardToolType(tenantA, "acme_sync"); got != agentguard.ToolTypeSystem {
		t.Fatalf("schema-inferred type = %q, want system", got)
	}
	if got := h.resolveAgentGuardToolType(tenantB, "acme_sync"); got != agentguard.ToolTypeUnknown {
		t.Fatalf("tool types must not leak across tenants, got %q", got)
	}
	h.rememberAgentGuardToolConfig(tenantA, "acme_sync", &ToolRiskConfigResponse{ToolType: "network"})
	if got := h.resolveAgentGuardToolType(tenantA, "ACME_SYNC"); got != agentguard.ToolTypeNetwork {
		t.Fatalf("explicit console mapping must win, got %q", got)
	}
	h.rememberAgentGuardToolConfig(tenantA, "acme_sync", nil)
	if got := h.resolveAgentGuardToolType(tenantA, "acme_sync"); got != agentguard.ToolTypeSystem {
		t.Fatalf("removed mapping falls back to the schema, got %q", got)
	}

	var nilCache *ChatCompletionsHandler = &ChatCompletionsHandler{}
	if got := nilCache.resolveAgentGuardToolType(tenantA, "read_file"); got != agentguard.ToolTypeFile {
		t.Fatalf("handler without cache keeps name heuristics, got %q", got)
	}
}
