package handler

import "testing"

func TestToolRiskClientMCPConfirmationSecretNeverFallsBackToInternalAPISecret(t *testing.T) {
	client := NewToolRiskClient("http://control-plane.invalid", "internal-api-secret-must-not-be-reused")
	if got := client.mcpConfirmationSecret(); got != "" {
		t.Fatalf("constructor reused internal API secret for MCP confirmation scope: %q", got)
	}

	client.SetMCPConfirmationScopeSecret("")
	if got := client.mcpConfirmationSecret(); got != "" {
		t.Fatalf("empty dedicated secret fell back to internal API secret: %q", got)
	}

	const dedicated = "dedicated-mcp-confirmation-scope-secret"
	client.SetMCPConfirmationScopeSecret(dedicated)
	if got := client.mcpConfirmationSecret(); got != dedicated {
		t.Fatalf("MCP confirmation scope secret = %q, want dedicated value", got)
	}
}
