package handler

import (
	"context"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
)

func TestAgentDispositionMatchesOnlyBoundAgentAndCorrectEgress(t *testing.T) {
	p := ai.Policy{TenantID: "tenant1", AgentInstanceID: "agent1", Action: "block_model_egress", Enabled: true, Mode: "protect"}
	for _, tc := range []struct {
		tenant, agent, path string
		match               bool
	}{{"tenant1", "agent1", "/v1/chat/completions", true}, {"tenant2", "agent1", "/v1/chat/completions", false}, {"tenant1", "agent2", "/v1/chat/completions", false}, {"tenant1", "agent1", "/v1/models", false}, {"tenant1", "agent1", "/health", false}} {
		if got := integrationPolicyMatches(p, tc.tenant, tc.agent, tc.path, ""); got != tc.match {
			t.Fatalf("%+v match=%v", tc, got)
		}
	}
	p.Action, p.MCPServerID = "disable_mcp", "server1"
	if !integrationPolicyMatches(p, "tenant1", "agent1", "/mcp/server1", "server1") || integrationPolicyMatches(p, "tenant1", "agent1", "/mcp/server2", "server2") {
		t.Fatal("MCP server binding failed")
	}
}

func TestAgentIdentitySurvivesDurableOutboxSerialization(t *testing.T) {
	envelope := &modelrouter.RequestEnvelope{RequestID: "request1", TenantID: "tenant1", ClientID: "key1", AgentInstanceID: "agent1"}
	payload := eventbus.AuditSecurityEventPayload{RequestLog: requestLogSnapshotFromEnvelope(envelope, time.Now()), EventID: "event1"}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var restored eventbus.AuditSecurityEventPayload
	if err = json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.RequestLog.AgentInstanceID != "agent1" || restored.RequestLog.ClientID != "key1" {
		t.Fatal("outbox attribution lost")
	}
}

func TestAgentDispositionUsesSecurityExitRecordAndProtectModes(t *testing.T) {
	for _, record := range []bool{true, false} {
		t.Run(map[bool]string{true: "record", false: "protect"}[record], func(t *testing.T) {
			g := NewIntegrationPolicyRuntime(nil, func(context.Context) bool { return record }, nil)
			g.policies = []ai.Policy{{TenantID: "tenant1", AgentInstanceID: "agent1", Action: "block_model_egress", Enabled: true, Mode: "protect", Version: "1"}}
			request := httptest.NewRequest("POST", "/v1/chat/completions", nil)
			ctx := context.WithValue(request.Context(), auth.TenantKey, "tenant1")
			ctx = context.WithValue(ctx, auth.AgentInstanceIDKey, "agent1")
			request = request.WithContext(ctx)
			response := httptest.NewRecorder()
			called := false
			g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(204) })).ServeHTTP(response, request)
			if record && (response.Code != 204 || !called) {
				t.Fatal("record mode interrupted request")
			}
			if !record && (response.Code != 403 || called) {
				t.Fatal("protect mode forwarded blocked request")
			}
		})
	}
}

func TestAgentMCPDispositionUsesChiServerRoute(t *testing.T) {
	for _, all := range []bool{false, true} {
		t.Run(map[bool]string{false: "one server", true: "all servers"}[all], func(t *testing.T) {
			g := NewIntegrationPolicyRuntime(nil, func(context.Context) bool { return false }, nil)
			serverID := "mcp_registered_native_id"
			if all {
				serverID = ""
			}
			g.policies = []ai.Policy{{TenantID: "tenant1", AgentInstanceID: "agent1", Action: "disable_mcp", MCPServerID: serverID, Enabled: true, Mode: "protect", Version: "1"}}
			router := chi.NewRouter()
			seen := ""
			router.With(g.Middleware).Post("/mcp/{serverID}", func(w http.ResponseWriter, r *http.Request) { seen = chi.URLParam(r, "serverID"); w.WriteHeader(204) })
			for _, target := range []string{"mcp_registered_native_id", "mcp_other_native_id"} {
				request := httptest.NewRequest("POST", "/mcp/"+target, nil)
				ctx := context.WithValue(request.Context(), auth.TenantKey, "tenant1")
				ctx = context.WithValue(ctx, auth.AgentInstanceIDKey, "agent1")
				response := httptest.NewRecorder()
				seen = ""
				router.ServeHTTP(response, request.WithContext(ctx))
				blocked := all || target == "mcp_registered_native_id"
				if blocked && (response.Code != 403 || seen != "") {
					t.Fatalf("target=%s was forwarded", target)
				}
				if !blocked && (response.Code != 204 || seen != target) {
					t.Fatalf("other target=%s blocked or missing native chi parameter", target)
				}
			}
		})
	}
}
