package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
)

func mcpEgressTestRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://gateway.local/mcp/servers/mcp_local", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), auth.TenantKey, "tenant_test")
	ctx = context.WithValue(ctx, auth.RequestIDKey, "req_mcp_egress")
	return r.WithContext(ctx)
}

func TestMCPUpstreamLoopbackDeniedByDefaultAndRecordsSecurityEvent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()
	db := newFakeAuditDB()
	h := &MCPProxyHandler{client: upstream.Client(), auditRecorder: &mcpProxyAuditRecorder{db: db}}
	server := &mcpServerRoute{ID: "mcp_local", TenantID: "tenant_test", Name: "local", ServerURL: upstream.URL + "/mcp", Status: "active", Transport: "streamable_http"}
	_, _, err := h.forwardMCPUpstream(context.Background(), server, mcpEgressTestRequest(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if !errors.Is(err, errMCPUpstreamEgressDenied) || !strings.Contains(err.Error(), "MCP 上游未通过出站安全校验") {
		t.Fatalf("err=%v, want egress denied", err)
	}
	found := false
	for i, sql := range db.tx.execedSQL {
		if !strings.Contains(sql, "INSERT INTO security_events") {
			continue
		}
		for _, arg := range db.tx.execedArgs[i] {
			text, _ := arg.(string)
			if raw, ok := arg.([]byte); ok {
				text = string(raw)
			}
			if strings.Contains(text, mcpUpstreamEgressDeniedReason) {
				found = true
			}
		}
	}
	if !found || !db.tx.committed {
		t.Fatalf("security event with %s not committed (sql=%d committed=%v)", mcpUpstreamEgressDeniedReason, len(db.tx.execedSQL), db.tx.committed)
	}
}

func TestMCPUpstreamLoopbackOverrideReachesUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()
	h := &MCPProxyHandler{client: upstream.Client()}
	server := &mcpServerRoute{ID: "mcp_local", TenantID: "tenant_test", Name: "local", ServerURL: upstream.URL + "/mcp", Status: "active", Transport: "streamable_http",
		EgressOverrides: safetarget.EgressOverrides{AllowLoopback: true}}
	resp, _, err := h.forwardMCPUpstream(context.Background(), server, mcpEgressTestRequest(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatalf("loopback override: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestMCPServerRouteEgressOptionsCombinePrivateFlagAndOverrides(t *testing.T) {
	server := &mcpServerRoute{AllowPrivateEgress: true, EgressOverrides: safetarget.EgressOverrides{AllowSameHostRedirect: true, InsecureSkipVerify: true}}
	opts := server.egressOptions()
	if !opts.AllowPrivate || !opts.AllowSameHostRedirect || !opts.InsecureSkipVerify || opts.AllowLoopback {
		t.Fatalf("options = %+v", opts)
	}
}
