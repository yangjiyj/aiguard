package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func ws1CachedRoute(id string) *mcpServerRoute {
	return &mcpServerRoute{ID: id, TenantID: "tenant_test", Status: "active"}
}

func TestWS1ServerCacheInvalidateSingleKey(t *testing.T) {
	h := &MCPProxyHandler{serverCache: &mcpServerCache{entries: map[string]mcpServerCacheEntry{}, ttl: time.Minute}}
	h.serverCache.set("tenant_test\x1fa", ws1CachedRoute("a"))
	h.serverCache.set("tenant_test\x1fb", ws1CachedRoute("b"))
	h.serverCache.set("tenant_other\x1fa", ws1CachedRoute("a"))

	h.handleMCPServerChanged("tenant_test\x1fa")

	if _, ok := h.serverCache.get("tenant_test\x1fa"); ok {
		t.Fatalf("changed server must be evicted")
	}
	if _, ok := h.serverCache.get("tenant_test\x1fb"); !ok {
		t.Fatalf("other server must stay cached")
	}
	if _, ok := h.serverCache.get("tenant_other\x1fa"); !ok {
		t.Fatalf("same id in another tenant must stay cached")
	}
}

func TestWS1ServerCacheMalformedPayloadFlushesAll(t *testing.T) {
	for _, payload := range []string{"", "no-separator", "\x1fid", "tenant\x1f"} {
		h := &MCPProxyHandler{serverCache: &mcpServerCache{entries: map[string]mcpServerCacheEntry{}, ttl: time.Minute}}
		h.serverCache.set("tenant_test\x1fa", ws1CachedRoute("a"))
		h.handleMCPServerChanged(payload)
		if _, ok := h.serverCache.get("tenant_test\x1fa"); ok {
			t.Fatalf("payload %q must flush the whole cache", payload)
		}
	}
}

func TestWS1ServerCacheInvalidatorNoDBIsNoop(t *testing.T) {
	h := NewMCPProxyHandler(nil, nil, false)
	h.StartServerCacheInvalidator(context.Background())
	var nilHandler *MCPProxyHandler
	nilHandler.StartServerCacheInvalidator(context.Background())
	nilHandler.handleMCPServerChanged("t\x1fs")
}

// 真库：server 被禁用后不等 60s TTL，下一次请求即 403；删除后即 404。
func TestWS1DisabledServerRejectedImmediatelyOnRealPostgres(t *testing.T) {
	dsn := os.Getenv("MCP_CONFIRMATION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("MCP_CONFIRMATION_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	serverID := "ws1_inv_srv"
	cleanup := func() { _, _ = pool.Exec(context.Background(), `DELETE FROM mcp_servers WHERE id=$1`, serverID) }
	cleanup()
	t.Cleanup(cleanup)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()
	if _, err := pool.Exec(ctx, `
		INSERT INTO mcp_servers (id, tenant_id, name, server_url, status, allow_private_egress)
		VALUES ($1,'tenant_default','ws1-inv',$2,'active',true)`, serverID, upstream.URL); err != nil {
		t.Fatalf("seed server: %v", err)
	}

	h := NewMCPProxyHandler(pool, nil, false)
	ready := make(chan struct{}, 1)
	h.startServerCacheInvalidator(ctx, ready)
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatalf("invalidator did not start listening")
	}

	resolve := func() int {
		r := httptest.NewRequest(http.MethodPost, "/mcp/"+serverID, strings.NewReader("{}"))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("serverID", serverID)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()
		if h.resolveMCPServer(r.Context(), w, r, &auth.AuthInfo{TenantID: "tenant_default"}) != nil {
			return http.StatusOK
		}
		return w.Code
	}
	if code := resolve(); code != http.StatusOK {
		t.Fatalf("active server should resolve, got %d", code)
	}
	if _, ok := h.serverCache.get("tenant_default\x1f" + serverID); !ok {
		t.Fatalf("route should be cached after first lookup")
	}

	if _, err := pool.Exec(ctx, `UPDATE mcp_servers SET status='disabled' WHERE id=$1`, serverID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if !ws1Eventually(5*time.Second, func() bool { return resolve() == http.StatusForbidden }) {
		t.Fatalf("disabled server still routable within TTL window")
	}

	if _, err := pool.Exec(ctx, `UPDATE mcp_servers SET status='active' WHERE id=$1`, serverID); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if !ws1Eventually(5*time.Second, func() bool { return resolve() == http.StatusOK }) {
		t.Fatalf("re-enabled server not routable")
	}

	// 断线重连：杀掉监听后端，协程应重连（并整表清空），之后的变更仍即时生效。
	if _, err := pool.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
		WHERE application_name=$1 AND datname=current_database()`, mcpServerInvalidatorAppName); err != nil {
		t.Fatalf("terminate listener: %v", err)
	}
	select {
	case <-ready:
	case <-time.After(15 * time.Second):
		t.Fatalf("invalidator did not reconnect")
	}
	if code := resolve(); code != http.StatusOK {
		t.Fatalf("server should resolve after reconnect, got %d", code)
	}
	if _, err := pool.Exec(ctx, `UPDATE mcp_servers SET status='disabled' WHERE id=$1`, serverID); err != nil {
		t.Fatalf("disable after reconnect: %v", err)
	}
	if !ws1Eventually(5*time.Second, func() bool { return resolve() == http.StatusForbidden }) {
		t.Fatalf("disable after reconnect not picked up")
	}

	if _, err := pool.Exec(ctx, `DELETE FROM mcp_servers WHERE id=$1`, serverID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !ws1Eventually(5*time.Second, func() bool { return resolve() == http.StatusNotFound }) {
		t.Fatalf("deleted server still routable within TTL window")
	}
}

func ws1Eventually(limit time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}
