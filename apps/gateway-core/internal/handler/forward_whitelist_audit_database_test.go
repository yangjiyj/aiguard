package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCWhitelistDatabaseGatewayBlindMetadata(t *testing.T) {
	dsn := os.Getenv("C_WHITELIST_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("C_WHITELIST_TEST_DATABASE_URL is required: use disposable PostgreSQL")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var before int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM request_logs r JOIN security_events e ON e.request_id=r.request_id WHERE r.tenant_id='tenant_default' AND r.proxy_mode='forward' AND r.proxy_method='CONNECT' AND r.proxy_tls_inspected=false AND r.proxy_content_retained=false AND r.request_status='success' AND e.event_type='security_check_failed' AND e.matched_summary->>'source'='gateway_forward_proxy' AND e.matched_summary->>'semantic_reason'='forward_proxy_tls_uninspected' AND e.matched_summary->>'counts_as_security_finding'='false'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	h := NewForwardProxyHandler(db, "tenant_default", "")
	r := httptest.NewRequest(http.MethodConnect, "http://api.openai.com:443", nil)
	r.Host = "api.openai.com:443"
	r.Header.Set("X-Tenant-ID", "tenant_foreign")
	gap := securityexit.DecideWithPolicy(securityexit.Protect, "audit", securityexit.DetectionFailure, securityexit.Policy{})
	h.recordForwardAudit(r, "api.openai.com", http.StatusOK, 0, gap, "forward_proxy_tls_uninspected")
	var count int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM request_logs r JOIN security_events e ON e.request_id=r.request_id WHERE r.tenant_id='tenant_default' AND r.proxy_mode='forward' AND r.proxy_method='CONNECT' AND r.proxy_tls_inspected=false AND r.proxy_content_retained=false AND r.request_status='success' AND e.event_type='security_check_failed' AND e.matched_summary->>'source'='gateway_forward_proxy' AND e.matched_summary->>'semantic_reason'='forward_proxy_tls_uninspected' AND e.matched_summary->>'counts_as_security_finding'='false'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count-before != 1 {
		t.Fatalf("gateway blind tunnel must persist metadata and gap event: count=%d", count)
	}
}
