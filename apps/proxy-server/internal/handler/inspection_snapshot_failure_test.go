package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// 代码审查（2026-09-27）：快照读库出错/分片缺失时 snapshot 返回哨兵 action="block"，
// 防护模式下会在没有任何规则命中的情况下拦截请求——违反"检测本身异常一律放行并记录"。
// 这里让补检引擎在处理分片时把 total_parts 调大，制造真实的"inspection work missing"。
func TestInspectionSnapshotFailureNeverBlocksEvenInProtect(t *testing.T) {
	db := inspectionDB(t)
	var bumped int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.CompareAndSwapInt32(&bumped, 0, 1) {
			if _, err := db.Exec(context.Background(), `UPDATE proxy_inspection_jobs SET total_parts = total_parts + 1 WHERE request_id='snapfail'`); err != nil {
				t.Errorf("bump total_parts: %v", err)
			}
		}
		completedInspection(w, "hello")
	}))
	defer server.Close()
	q := queueForTest(t, db, server.URL)
	action, findings, meta := q.inspect(context.Background(), "tenant", "snapfail", "host", simplePlan("hello"), false)
	if atomic.LoadInt32(&bumped) != 1 {
		t.Fatal("fixture did not reach the inspection engine")
	}
	// 无 findings 时最终应为 audit：放行并记录覆盖缺口（incomplete -> strongerProxyRecordAction）。
	if action != "audit" || len(findings) != 0 {
		t.Fatalf("snapshot failure must be a recorded coverage gap in protect mode, got action=%s findings=%v", action, findings)
	}
	if meta == nil || meta.SemanticStatus != "incomplete" {
		t.Fatalf("snapshot failure must be reported as incomplete inspection: %+v", meta)
	}
}
