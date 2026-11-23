package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMCPRouteRequiresExplicitScopeForAllDataMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/mcp/server-1", nil)
			for _, scopes := range [][]string{nil, {}, {"chat"}, {"models"}} {
				if err := enforceRouteScope(req, scopes); err == nil {
					t.Fatalf("method=%s scopes=%v unexpectedly authorized MCP", method, scopes)
				}
			}
			for _, scopes := range [][]string{{"mcp"}, {"*"}} {
				if err := enforceRouteScope(req, scopes); err != nil {
					t.Fatalf("method=%s scopes=%v rejected: %v", method, scopes, err)
				}
			}
		})
	}
}

func TestLegacyEmptyScopesRemainCompatibleOnlyForModelRoutes(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	if err := enforceRouteScope(req, nil); err != nil {
		t.Fatalf("legacy empty scopes should keep model route compatibility: %v", err)
	}
}
