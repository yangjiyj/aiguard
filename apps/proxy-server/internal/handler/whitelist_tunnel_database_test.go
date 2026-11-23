package handler

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCWhitelistDatabaseProxyBlindTunnelAudit(t *testing.T) {
	dsn := os.Getenv("C_WHITELIST_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("C_WHITELIST_TEST_DATABASE_URL is required: use disposable PostgreSQL")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err == nil {
			conn.Close()
		}
	}()
	checker := newCheckerWithRules([]WhitelistRule{{HostPattern: "audit.blob.core.windows.net", Port: 443, TenantID: "tenant_default", AuditEnabled: true}})
	h := NewProxyHandler(checker, nil, nil, NewAuditWriter(db), nil)
	h.egressGuard = redirectGuard(upstream.Addr().String())
	server := httptest.NewServer(http.HandlerFunc(h.Handle))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	conn, err := net.DialTimeout("tcp", parsed.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT audit.blob.core.windows.net:443 HTTP/1.1\r\nHost: audit.blob.core.windows.net:443\r\nX-Tenant-ID: tenant_foreign\r\n\r\n")
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil || line != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatalf("line=%q err=%v", line, err)
	}
	var count int
	deadline := time.Now().Add(3 * time.Second)
	for {
		err = db.QueryRow(context.Background(), `SELECT count(*) FROM request_logs r JOIN security_events e ON e.request_id=r.request_id WHERE r.tenant_id='tenant_default' AND r.proxy_target_host='audit.blob.core.windows.net' AND r.proxy_mode='forward' AND r.proxy_method='CONNECT' AND r.proxy_tls_inspected=false AND r.proxy_content_retained=false AND r.proxy_retention_level='summary' AND e.event_type='security_check_failed' AND e.matched_summary->>'semantic_reason'='forward_proxy_tls_uninspected' AND e.matched_summary->>'counts_as_security_finding'='false'`).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("blind CONNECT must persist metadata and gap event; count=%d", count)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
