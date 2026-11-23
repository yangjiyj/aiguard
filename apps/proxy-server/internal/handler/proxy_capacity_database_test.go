package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

func TestCapacityProxyQueueBacklogReadsIndependentPolicy(t *testing.T) {
	if os.Getenv("PROXY_INSPECTION_TEST_DSN") == "" {
		t.Fatal("PROXY_INSPECTION_TEST_DSN must point to disposable PostgreSQL")
	}
	for _, auditOnly := range []bool{false, true} {
		for _, closed := range []bool{false, true} {
			t.Run("record="+strconv.FormatBool(auditOnly)+"/closed="+strconv.FormatBool(closed), func(t *testing.T) {
				t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", strconv.FormatBool(closed))
				db := inspectionDB(t)
				engine := quietSecuritySrv(t)
				queue := queueForTest(t, db, engine.URL)
				if err := queue.enqueue(context.Background(), "tenant", "full", "host", "audit", simplePlan("hello")); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(context.Background(), `UPDATE proxy_inspection_jobs SET payload_bytes=512*1024*1024`); err != nil {
					t.Fatal(err)
				}
				action, findings, meta := queue.inspect(context.Background(), "tenant", "next", "host", simplePlan("hello"), auditOnly)
				want := "audit"
				if closed && !auditOnly {
					want = "block"
				}
				if action != want || len(findings) != 0 || meta == nil || meta.SemanticStatus != "incomplete" {
					t.Fatalf("full persisted detector backlog must read capacity policy: action=%s want=%s findings=%v meta=%+v", action, want, findings, meta)
				}
				if action == "block" {
					if status, _ := inputBlockResponse(meta, findings); status != http.StatusServiceUnavailable {
						t.Fatalf("backlog must return 503: status=%d meta=%+v", status, meta)
					}
				}
			})
		}
	}
}

func TestCapacityProxyQueueRetainsEnginePoolFailureCause(t *testing.T) {
	if os.Getenv("PROXY_INSPECTION_TEST_DSN") == "" {
		t.Fatal("PROXY_INSPECTION_TEST_DSN must point to disposable PostgreSQL")
	}
	t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", "true")
	db := inspectionDB(t)
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": "input_capacity_overflow", "inspection_status": "incomplete"}})
	}))
	defer engine.Close()
	queue := queueForTest(t, db, engine.URL)
	action, findings, meta := queue.inspect(context.Background(), "tenant", "pool-full", "host", simplePlan("hello"), false)
	if action != "block" || len(findings) != 0 || meta == nil || meta.SemanticStatus != "incomplete" {
		t.Fatalf("persisted pool capacity must not become a generic fail-open gap: action=%s findings=%v meta=%+v", action, findings, meta)
	}
	if status, _ := inputBlockResponse(meta, findings); status != http.StatusServiceUnavailable {
		t.Fatalf("pool capacity must return 503: status=%d meta=%+v", status, meta)
	}
}
