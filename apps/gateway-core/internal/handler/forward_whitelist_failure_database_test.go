package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCWhitelistDatabaseGatewayFailureModeAudit(t *testing.T) {
	dsn := os.Getenv("C_WHITELIST_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("C_WHITELIST_TEST_DATABASE_URL is required: use disposable PostgreSQL")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tc := range []struct {
		name, mode, audit string
		allowed           bool
		action            string
	}{
		{"closed", "closed", "false", false, "block"},
		{"open", "open", "false", true, "audit"},
		{"auditonly", "closed", "true", true, "audit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GATEWAY_FORWARD_PROXY_MODE", "deny_unlisted")
			t.Setenv("PROXY_WHITELIST_FAIL_MODE", tc.mode)
			t.Setenv("SECURITY_AUDIT_ONLY", tc.audit)
			h := NewForwardProxyHandler(nil, "tenant_default", "")
			h.auditRecorder = newReverseProxyDBAuditRecorder(db, "")
			host := tc.name + ".gateway-whitelist.invalid"
			r := httptest.NewRequest(http.MethodConnect, "http://"+host+":443", nil)
			r.Header.Set("X-Tenant-ID", "tenant_foreign")
			var before int
			if err := db.QueryRow(context.Background(), `SELECT count(*) FROM security_events e JOIN request_logs r ON r.request_id=e.request_id WHERE r.tenant_id='tenant_default' AND r.proxy_target_host=$1 AND e.event_type='security_check_failed' AND e.action_taken=$2 AND e.matched_summary->>'semantic_reason'='proxy_whitelist_unavailable'`, host, tc.action).Scan(&before); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			if allowed := h.enforceWhitelist(w, r, host, 443); allowed != tc.allowed {
				t.Fatalf("allowed=%v want=%v response=%d", allowed, tc.allowed, w.Code)
			}
			var count int
			if err := db.QueryRow(context.Background(), `SELECT count(*) FROM security_events e JOIN request_logs r ON r.request_id=e.request_id WHERE r.tenant_id='tenant_default' AND r.proxy_target_host=$1 AND e.event_type='security_check_failed' AND e.action_taken=$2 AND e.matched_summary->>'semantic_reason'='proxy_whitelist_unavailable'`, host, tc.action).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count-before != 1 {
				t.Fatalf("whitelist failure must persist gap and effective action: count=%d", count)
			}
		})
	}
}
