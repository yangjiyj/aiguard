package handler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCWhitelistDatabaseProxyFailureAndEmptyAudit(t *testing.T) {
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
	failedStore := &WhitelistChecker{store: &fakeWhitelistStore{err: errors.New("database unavailable")}, tenantID: "tenant_default"}
	for _, tc := range []struct {
		name, mode, audit string
		checker           *WhitelistChecker
		status            int
	}{
		{"closed", "closed", "false", nil, http.StatusForbidden},
		{"open", "open", "false", nil, http.StatusOK},
		{"empty", "closed", "false", successfulEmptyWhitelistChecker(), http.StatusOK},
		{"queryclosed", "closed", "false", failedStore, http.StatusForbidden},
		{"queryopen", "open", "false", failedStore, http.StatusOK},
		{"auditonly", "closed", "true", nil, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PROXY_WHITELIST_FAIL_MODE", tc.mode)
			t.Setenv("SECURITY_AUDIT_ONLY", tc.audit)
			h := NewProxyHandler(tc.checker, nil, nil, NewAuditWriter(db), nil)
			h.transport = fileDLPTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("upstream"))}, nil
			})
			r := httptest.NewRequest(http.MethodGet, "http://"+tc.name+".whitelist.invalid/path", nil)
			r.Header.Set("X-Tenant-ID", "tenant_foreign")
			w := httptest.NewRecorder()
			h.handleHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			var eventCount int
			if err := db.QueryRow(context.Background(), `SELECT count(*) FROM security_events e JOIN request_logs r ON r.request_id=e.request_id WHERE r.tenant_id='tenant_default' AND r.proxy_target_host=$1 AND e.event_type='security_check_failed'`, tc.name+".whitelist.invalid").Scan(&eventCount); err != nil {
				t.Fatal(err)
			}
			if eventCount != 1 {
				t.Fatalf("fail/empty gap must persist security event; count=%d", eventCount)
			}
			var accessCount int
			if err := db.QueryRow(context.Background(), `SELECT count(*) FROM request_logs WHERE tenant_id='tenant_default' AND proxy_target_host=$1`, tc.name+".whitelist.invalid").Scan(&accessCount); err != nil {
				t.Fatal(err)
			}
			if accessCount != 1 {
				t.Fatalf("gate and HTTP audit must share one access row; count=%d", accessCount)
			}
		})
	}
}
