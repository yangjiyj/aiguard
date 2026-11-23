package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

func TestSecurityActionHeaderPostureMatchesRuntimeDefault(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		record, want bool
	}{
		{"record default", "", true, false}, {"protect default", "", false, true},
		{"record explicit", "true", true, true}, {"protect disabled", "false", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MCP_GATEWAY_ENABLED", "false")
			t.Setenv("SECURITY_AUDIT_ONLY", "false")
			t.Setenv("SECURITY_ACTION_HEADER_ENABLED", tc.header)
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, tc.record, false)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(payload) }))
			defer server.Close()
			client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
			runtime, err := client.fetchSemanticRuntimeConfig(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			client.runtimeCache.setSemanticConfig(runtime)
			mcp := NewMCPProxyHandler(nil, client, false)
			forward := NewForwardProxyHandler(nil, "tenant-123", "http://unused.invalid")
			forward.SetRuntimeConfigClient(client, cfg.SecurityAuditOnly)
			client.ConfigureSecurityPosture(cfg, mcp, forward)
			posture := client.postureProvider(context.Background(), runtime)
			if posture == nil || posture.SecurityActionHeaderEnabled == nil {
				t.Fatal("runtime posture omitted header state")
			}
			if got := *posture.SecurityActionHeaderEnabled; got != tc.want {
				t.Fatalf("runtime record=%v reported header=%v want=%v", tc.record, got, tc.want)
			}
		})
	}
}
