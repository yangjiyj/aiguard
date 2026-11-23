package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
)

func TestEnforceRouteScope(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		scopes  []string
		wantErr bool
	}{
		{name: "empty scopes remain compatible", method: http.MethodPost, path: "/v1/chat/completions", scopes: nil, wantErr: false},
		{name: "wildcard scope allowed", method: http.MethodPost, path: "/v1/embeddings", scopes: []string{"*"}, wantErr: false},
		{name: "matching scope allowed", method: http.MethodPost, path: "/v1/responses", scopes: []string{"responses"}, wantErr: false},
		{name: "messages uses chat scope", method: http.MethodPost, path: "/v1/messages", scopes: []string{"chat"}, wantErr: false},
		{name: "models scope allowed", method: http.MethodGet, path: "/v1/models", scopes: []string{"models"}, wantErr: false},
		{name: "mismatched scope rejected", method: http.MethodPost, path: "/v1/embeddings", scopes: []string{"chat"}, wantErr: true},
		{name: "messages rejects non-chat scope", method: http.MethodPost, path: "/v1/messages", scopes: []string{"responses"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			err := enforceRouteScope(req, tt.scopes)
			if (err != nil) != tt.wantErr {
				t.Fatalf("enforceRouteScope() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseScopesJSON(t *testing.T) {
	scopes := parseScopesJSON([]byte(`["chat","embeddings"]`))
	if len(scopes) != 2 || scopes[0] != "chat" || scopes[1] != "embeddings" {
		t.Fatalf("unexpected scopes parse result: %#v", scopes)
	}

	invalid := parseScopesJSON([]byte(`{bad json`))
	if len(invalid) != 0 {
		t.Fatalf("expected invalid scopes json to return empty slice, got %#v", invalid)
	}
}

func TestEnvironmentScopeComesOnlyFromExplicitAPIKeyScope(t *testing.T) {
	if got := EnvironmentScopeFromAPIKeyScopes([]string{"chat", "customer"}); got != "customer" {
		t.Fatalf("scope = %q, want customer", got)
	}
	if got := EnvironmentScopeFromAPIKeyScopes([]string{"chat", "workspace-id"}); got != "legacy-unclassified" {
		t.Fatalf("untrusted scope = %q, want legacy-unclassified", got)
	}
}

func TestResolveEnvironmentScopePrefersTrustedDeploymentBoundary(t *testing.T) {
	if got := ResolveEnvironmentScope([]string{"chat", "home"}, "customer"); got != "customer" {
		t.Fatalf("scope = %q, want trusted deployment scope customer", got)
	}
}

func TestResolveEnvironmentScopeUsesExplicitKeyWithoutDeploymentBoundary(t *testing.T) {
	if got := ResolveEnvironmentScope([]string{"chat", "home"}, "legacy-unclassified"); got != "home" {
		t.Fatalf("scope = %q, want explicit key scope home", got)
	}
}

func TestResolveEnvironmentScopeFallsBackToTrustedDeploymentScope(t *testing.T) {
	if got := ResolveEnvironmentScope([]string{"chat"}, " CUSTOMER "); got != "customer" {
		t.Fatalf("scope = %q, want deployment scope customer", got)
	}
	if got := ResolveEnvironmentScope([]string{"chat"}, "untrusted"); got != "legacy-unclassified" {
		t.Fatalf("invalid deployment scope = %q, want legacy-unclassified", got)
	}
}

func TestExtractRequestTokenAcceptsAnthropicAPIKeyHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("x-api-key", "na_test_x_api_key")

	if got := extractRequestToken(req); got != "na_test_x_api_key" {
		t.Fatalf("extractRequestToken() = %q, want x-api-key token", got)
	}
}

func TestExtractRequestTokenPrefersBearerHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer na_bearer")
	req.Header.Set("x-api-key", "na_x_api_key")

	if got := extractRequestToken(req); got != "na_bearer" {
		t.Fatalf("extractRequestToken() = %q, want bearer token", got)
	}
}

func TestInferAgentTypeFromRequestHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("User-Agent", "Trae IDE/1.0")

	got, err := agentdetect.InferFromHeaders(req.Header)
	if err != nil || got != "trae" {
		t.Fatalf("InferFromHeaders() = (%q, %v), want trae", got, err)
	}
}
