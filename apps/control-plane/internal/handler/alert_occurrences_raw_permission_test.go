package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 前端按角色决定是否带 include_raw，与后端的内容证据权限可能不一致（旧 admin 角色、部门管理员等）。
// 列表、命中明细带 include_raw 而无内容证据权限时按不带原文返回，不能整页 404；响应里告诉前端本次能否看证据。
func TestAlertOccurrenceIgnoresRawRequestWithoutEvidencePermission(t *testing.T) {
	for _, tc := range []struct {
		role, query string
	}{
		{"admin", "include_raw=true"},
		{"admin", "include_raw=true&grouping=hits&case_id=ac1_" + "0123456789abcdef0123456789abcdef"},
		{"dept_manager", "include_raw=true&grouping=cases"},
	} {
		stub := &occurrenceReaderStub{}
		w := httptest.NewRecorder()
		ListAlertOccurrences(&Dependencies{AlertOccurrenceRepo: stub}).ServeHTTP(w, occurrenceRequest(tc.role, tc.query))
		if w.Code != 200 || stub.filter.IncludeRaw || stub.filter.CanReadEvidence {
			t.Fatalf("%+v: status=%d filter=%+v body=%s", tc, w.Code, stub.filter, w.Body.String())
		}
		var page repository.AlertOccurrencePage
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if page.EvidenceReadable {
			t.Fatalf("%+v: evidence reported readable", tc)
		}
		for _, item := range page.Items {
			if item.RawEvidence != "" || item.EvidenceContext != "" || item.Reason != "" {
				t.Fatalf("%+v: raw or reason disclosed: %+v", tc, item)
			}
		}
	}
	// 有权限的角色照常拿到原文，并被告知可以看证据。
	stub := &occurrenceReaderStub{}
	w := httptest.NewRecorder()
	ListAlertOccurrences(&Dependencies{AlertOccurrenceRepo: stub}).ServeHTTP(w, occurrenceRequest("platform_admin", "include_raw=true"))
	var page repository.AlertOccurrencePage
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || !page.EvidenceReadable || page.Items[0].RawEvidence == "" {
		t.Fatalf("authorized raw read: status=%d body=%s", w.Code, w.Body.String())
	}
	// 应急模式账号原本就看不到告警（整页 404，与带不带 include_raw 无关），这里只确认 include_raw 不改变结果。
	for _, query := range []string{"", "include_raw=true"} {
		stub := &occurrenceReaderStub{}
		r := occurrenceRequest("platform_admin", query)
		auth.GetUser(r.Context()).DepartmentAssignmentMode = "emergency"
		w := httptest.NewRecorder()
		ListAlertOccurrences(&Dependencies{AlertOccurrenceRepo: stub}).ServeHTTP(w, r)
		if w.Code != 404 || stub.called {
			t.Fatalf("emergency query=%q: status=%d", query, w.Code)
		}
	}
}
