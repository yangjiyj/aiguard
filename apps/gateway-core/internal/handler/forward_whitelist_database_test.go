package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCWhitelistDatabaseGatewayDenialAudit(t *testing.T) {
	dsn := os.Getenv("C_WHITELIST_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("C_WHITELIST_TEST_DATABASE_URL is required: use the disposable migrated PostgreSQL harness")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	t.Setenv("GATEWAY_FORWARD_PROXY_MODE", "deny_unlisted")
	if _, err := db.Exec(context.Background(), `DELETE FROM proxy_whitelist WHERE tenant_id='tenant_default'`); err != nil {
		t.Fatal(err)
	}
	var beforeAccess, beforeEvents int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM request_logs WHERE tenant_id='tenant_default' AND proxy_mode='forward' AND proxy_target_host='unlisted.invalid' AND request_status='blocked'`).Scan(&beforeAccess); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM security_events e JOIN request_logs r ON r.request_id=e.request_id WHERE r.tenant_id='tenant_default' AND r.proxy_target_host='unlisted.invalid' AND e.action_taken='block'`).Scan(&beforeEvents); err != nil {
		t.Fatal(err)
	}
	h := NewForwardProxyHandler(db, "tenant_default", "")
	r := httptest.NewRequest(http.MethodConnect, "http://unlisted.invalid", nil)
	r.Host = "unlisted.invalid:443"
	r.Header.Set("X-Tenant-ID", "tenant_foreign")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var accessCount, eventCount int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM request_logs WHERE tenant_id='tenant_default' AND proxy_mode='forward' AND proxy_target_host='unlisted.invalid' AND request_status='blocked'`).Scan(&accessCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM security_events e JOIN request_logs r ON r.request_id=e.request_id WHERE r.tenant_id='tenant_default' AND r.proxy_target_host='unlisted.invalid' AND e.action_taken='block'`).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if accessCount-beforeAccess != 1 || eventCount-beforeEvents != 1 {
		t.Fatalf("denial must persist tenant-scoped access and event: access=%d event=%d", accessCount, eventCount)
	}
}
