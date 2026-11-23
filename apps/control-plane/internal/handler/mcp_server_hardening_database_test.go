package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func mcpHardeningDatabaseFixture(t *testing.T) (*pgxpool.Pool, *Dependencies, string, string, string) {
	t.Helper()
	dsn := os.Getenv("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL is required; use disposable PostgreSQL")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	tenant := fmt.Sprintf("f_mcp_%d", time.Now().UnixNano())
	user, server := tenant+"_admin", tenant+"_server"
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, "DELETE FROM audit_operations WHERE user_id=$1", user)
		_, _ = db.Exec(ctx, "DELETE FROM mcp_servers WHERE tenant_id=$1", tenant)
		_, _ = db.Exec(ctx, "DELETE FROM users WHERE id=$1", user)
		_, _ = db.Exec(ctx, "DELETE FROM tenants WHERE id=$1", tenant)
		db.Close()
	})
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role) VALUES($1,$2,$1,'tenant_admin')`, user, tenant); err != nil {
		t.Fatal(err)
	}
	deps := &Dependencies{MCPServerRepo: repository.NewMCPServersRepository(db), SystemRepo: repository.NewSystemRepository(db)}
	if err := deps.MCPServerRepo.Create(ctx, &repository.MCPServer{ID: server, TenantID: tenant, Name: "safe", ServerURL: "https://mcp.example/rpc", Transport: "streamable_http", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	return db, deps, tenant, user, server
}

func mcpHardeningAdminRequest(method, tenant, user, server string, body []byte) *http.Request {
	r := httptest.NewRequest(method, "/admin/v1/mcp-servers/"+server, strings.NewReader(string(body)))
	ctx := context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: user, TenantID: tenant, Role: "tenant_admin"})
	route := chi.NewRouteContext()
	route.URLParams.Add("id", server)
	ctx = context.WithValue(ctx, chi.RouteCtxKey, route)
	return r.WithContext(ctx)
}

func TestMCPServerHardeningDatabaseRejectsInvalidURLsOnCreateAndUpdate(t *testing.T) {
	_, deps, tenant, user, server := mcpHardeningDatabaseFixture(t)
	for _, url := range []string{"", "file:///etc/passwd", "https://user:password@mcp.example/rpc", "https://mcp.example/rpc#fragment", "http://"} {
		for _, method := range []string{http.MethodPost, http.MethodPut} {
			t.Run(method+url, func(t *testing.T) {
				body, _ := json.Marshal(map[string]interface{}{"name": "invalid", "server_url": url, "transport": "streamable_http"})
				w := httptest.NewRecorder()
				if method == http.MethodPost {
					CreateMCPServer(deps)(w, mcpHardeningAdminRequest(method, tenant, user, server, body))
				} else {
					UpdateMCPServer(deps)(w, mcpHardeningAdminRequest(method, tenant, user, server, body))
				}
				if w.Code != 400 {
					t.Fatalf("invalid MCP URL accepted: %d %s", w.Code, w.Body.String())
				}
			})
		}
	}
	stored, err := deps.MCPServerRepo.Get(context.Background(), tenant, server)
	if err != nil || stored.ServerURL != "https://mcp.example/rpc" {
		t.Fatalf("invalid update persisted: %+v %v", stored, err)
	}
}

func TestMCPServerHardeningDatabasePrivateEgressChangeAlreadyAudited(t *testing.T) {
	db, deps, tenant, user, server := mcpHardeningDatabaseFixture(t)
	for _, allowed := range []bool{true, false} {
		body, _ := json.Marshal(map[string]interface{}{"name": "safe", "server_url": "https://mcp.example/rpc", "transport": "streamable_http", "allow_private_egress": allowed})
		w := httptest.NewRecorder()
		UpdateMCPServer(deps)(w, mcpHardeningAdminRequest(http.MethodPut, tenant, user, server, body))
		if w.Code != 200 {
			t.Fatalf("update=%d %s", w.Code, w.Body.String())
		}
		var count int
		if err := db.QueryRow(context.Background(), `SELECT count(*) FROM audit_operations WHERE user_id=$1 AND target_id=$2 AND action_type='mcp_server.update' AND (action_detail->>'allow_private_egress')::boolean=$3`, user, server, allowed).Scan(&count); err != nil || count != 1 {
			t.Fatalf("private egress mutation lacks persisted audit: allowed=%v count=%d err=%v", allowed, count, err)
		}
	}
}
