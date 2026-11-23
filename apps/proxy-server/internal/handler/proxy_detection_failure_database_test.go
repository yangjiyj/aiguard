package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

func TestProxyDetectionFailurePolicyDurableQueue(t *testing.T) {
	if os.Getenv("PROXY_INSPECTION_TEST_DSN") == "" {
		t.Fatal("PROXY_INSPECTION_TEST_DSN must point to disposable PostgreSQL")
	}
	for _, storageError := range []bool{false, true} {
		for _, auditOnly := range []bool{false, true} {
			for _, mode := range []string{"open", "closed"} {
				t.Run("storage="+strconv.FormatBool(storageError)+"/record="+strconv.FormatBool(auditOnly)+"/mode="+mode, func(t *testing.T) {
					t.Setenv("PROXY_DETECTION_FAIL_MODE", mode)
					t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", "false")
					db := inspectionDB(t)
					engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						http.Error(w, "detector unavailable", http.StatusServiceUnavailable)
					}))
					defer engine.Close()
					queue := queueForTest(t, db, engine.URL)
					if storageError {
						if _, err := db.Exec(context.Background(), "DROP TABLE proxy_inspection_jobs CASCADE"); err != nil {
							t.Fatal(err)
						}
					}
					action, findings, meta := queue.inspect(context.Background(), "tenant", "ordinary-failure", "host", simplePlan("hello"), auditOnly)
					want := "audit"
					if mode == "closed" && !auditOnly {
						want = "block"
					}
					if action != want || meta == nil || meta.SemanticStatus != "incomplete" || len(findings) != 0 {
						t.Fatalf("durable ordinary failure must consume switch and retain gap: action=%s want=%s meta=%+v findings=%v", action, want, meta, findings)
					}
					if action == "block" {
						if status, code := inputBlockResponse(meta, findings); status != http.StatusServiceUnavailable || code != "inspection_unavailable" {
							t.Fatalf("durable ordinary failure must return503: status=%d code=%s", status, code)
						}
					}
				})
			}
		}
	}
}
