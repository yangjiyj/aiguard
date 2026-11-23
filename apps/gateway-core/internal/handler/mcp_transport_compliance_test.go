package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
)

func TestMCPOriginMiddlewareEnforcesExactAllowlist(t *testing.T) {
	h := NewMCPProxyHandler(nil, nil, false)
	h.SetAllowedOrigins([]string{"https://trusted.example"})

	nextHits := 0
	wrapped := h.OriginMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextHits++
		w.WriteHeader(http.StatusNoContent)
	}))

	native := httptest.NewRecorder()
	wrapped.ServeHTTP(native, httptest.NewRequest(http.MethodPost, "/mcp/server-1", nil))
	if native.Code != http.StatusNoContent || nextHits != 1 {
		t.Fatalf("native client status=%d hits=%d", native.Code, nextHits)
	}

	untrustedReq := httptest.NewRequest(http.MethodPost, "/mcp/server-1", nil)
	untrustedReq.Header.Set("Origin", "https://trusted.example.attacker.invalid")
	untrusted := httptest.NewRecorder()
	wrapped.ServeHTTP(untrusted, untrustedReq)
	if untrusted.Code != http.StatusForbidden || nextHits != 1 {
		t.Fatalf("untrusted origin status=%d hits=%d", untrusted.Code, nextHits)
	}

	preflightReq := httptest.NewRequest(http.MethodOptions, "/mcp/server-1", nil)
	preflightReq.Header.Set("Origin", "https://trusted.example")
	preflight := httptest.NewRecorder()
	wrapped.ServeHTTP(preflight, preflightReq)
	if preflight.Code != http.StatusNoContent || nextHits != 1 {
		t.Fatalf("preflight status=%d hits=%d", preflight.Code, nextHits)
	}
	if preflight.Header().Get("Access-Control-Allow-Origin") != "https://trusted.example" {
		t.Fatalf("allow origin=%q", preflight.Header().Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(preflight.Header().Get("Access-Control-Allow-Methods"), http.MethodDelete) {
		t.Fatalf("allow methods=%q", preflight.Header().Get("Access-Control-Allow-Methods"))
	}
}

func TestMCPDeleteForwardsSessionTermination(t *testing.T) {
	var gotMethod, gotSession, gotVersion string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotSession = r.Header.Get("Mcp-Session-Id")
		gotVersion = r.Header.Get("MCP-Protocol-Version")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	h := NewMCPProxyHandler(nil, nil, false)
	useMCPTestUpstream(h, upstream)
	h.serverCache.set("tenant_test\x1fmcp_srv1", &mcpServerRoute{
		ID: "mcp_srv1", TenantID: "tenant_test", Name: "demo",
		ServerURL: upstream.URL, Status: "active", AllowPrivateEgress: true,
	})

	router := chi.NewRouter()
	router.Route("/mcp", func(r chi.Router) { h.Register(r) })
	registerStreamableTestSession(t, h, "tenant_test", "mcp_srv1", "session-delete-1", "\x1f\x1f", "")

	req := httptest.NewRequest(http.MethodDelete, "/mcp/mcp_srv1", nil)
	ctx := context.WithValue(req.Context(), auth.TenantKey, "tenant_test")
	ctx = context.WithValue(ctx, auth.RequestIDKey, "req-delete")
	req = req.WithContext(ctx)
	req.Header.Set("Mcp-Session-Id", "session-delete-1")
	req.Header.Set("MCP-Protocol-Version", mcpProtocolVersionLatest)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if gotMethod != http.MethodDelete || gotSession != "session-delete-1" || gotVersion != mcpProtocolVersionLatest {
		t.Fatalf("upstream method=%q session=%q version=%q", gotMethod, gotSession, gotVersion)
	}
}

func TestMCPDeleteRequiresSessionAndProtocolHeaders(t *testing.T) {
	h := NewMCPProxyHandler(nil, nil, false)
	h.serverCache.set("tenant_test\x1fmcp_srv1", &mcpServerRoute{
		ID: "mcp_srv1", TenantID: "tenant_test", Name: "demo",
		ServerURL: "https://example.invalid/mcp", Status: "active",
	})
	router := chi.NewRouter()
	router.Route("/mcp", func(r chi.Router) { h.Register(r) })

	for _, test := range []struct {
		name    string
		session string
		version string
	}{
		{name: "missing session", version: mcpProtocolVersionLatest},
		{name: "missing version", session: "session-delete-1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/mcp/mcp_srv1", nil)
			ctx := context.WithValue(req.Context(), auth.TenantKey, "tenant_test")
			req = req.WithContext(ctx)
			req.Header.Set("Mcp-Session-Id", test.session)
			req.Header.Set("MCP-Protocol-Version", test.version)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}
