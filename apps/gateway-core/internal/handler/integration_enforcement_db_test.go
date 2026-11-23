package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAgentMCPDispositionUsesRegisteredNativeRouteOnPostgres(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ns := fmt.Sprintf("tri_review_%d", time.Now().UnixNano())
	tenant, agent, server, other, policy := ns+"_tenant", ns+"_agent", ns+"_mcp", ns+"_other", ns+"_policy"
	if _, err = db.Exec(ctx, `INSERT INTO tenants(id,name,is_test) VALUES($1,$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM integration_gateway_receipts WHERE instance_id=$1`, ns)
		_, _ = db.Exec(ctx, `DELETE FROM integration_gateway_instances WHERE instance_id=$1`, ns)
		_, _ = db.Exec(ctx, `DELETE FROM integration_agent_policies WHERE id=$1`, policy)
		_, _ = db.Exec(ctx, `DELETE FROM mcp_servers WHERE tenant_id=$1`, tenant)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant)
	})
	if _, err = db.Exec(ctx, `INSERT INTO mcp_servers(id,tenant_id,name,server_url,status) VALUES($1,$3,'display selected','http://127.0.0.1:9/mcp','active'),($2,$3,'display other','http://127.0.0.1:9/mcp','active')`, server, other, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO integration_agent_policies(id,tenant_id,agent_instance_id,action,enabled,mode,mcp_server_id) VALUES($1,$2,$3,'disable_mcp',true,'protect',$4)`, policy, tenant, agent, server); err != nil {
		t.Fatal(err)
	}
	g := NewIntegrationPolicyRuntime(db, func(context.Context) bool { return false }, nil)
	g.instanceID = ns
	if err = g.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	mcp := NewMCPProxyHandler(db, nil, false)
	router := chi.NewRouter()
	router.With(g.Middleware).Post("/mcp/{serverID}", func(w http.ResponseWriter, r *http.Request) {
		route := mcp.resolveMCPServer(r.Context(), w, r, auth.GetAuthInfo(r))
		if route != nil {
			w.WriteHeader(204)
		}
	})
	for _, tc := range []struct {
		target string
		status int
	}{{server, 403}, {other, 204}, {"display_selected", 404}, {ns + "_missing", 404}} {
		request := httptest.NewRequest("POST", "/mcp/"+tc.target, nil)
		request = request.WithContext(context.WithValue(context.WithValue(request.Context(), auth.TenantKey, tenant), auth.AgentInstanceIDKey, agent))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != tc.status {
			t.Fatalf("native target=%s status=%d want=%d", tc.target, response.Code, tc.status)
		}
	}
	var hits, blocked int
	if err = db.QueryRow(ctx, `SELECT hit_count,blocked_count FROM integration_gateway_receipts WHERE instance_id=$1 AND policy_id=$2`, ns, policy).Scan(&hits, &blocked); err != nil || hits != 1 || blocked != 1 {
		t.Fatalf("native receipt hits=%d blocked=%d err=%v", hits, blocked, err)
	}
}
