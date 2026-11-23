package handler

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type operationalSummaryStub struct {
	occurrenceReaderStub
	summarized bool
}

func (s *operationalSummaryStub) SummarizeOperational(_ context.Context, f repository.AlertOccurrenceFilter) (*repository.AlertOperationalBreakdown, error) {
	s.called = true
	s.summarized = true
	s.filter = f
	latest := time.Date(2026, 9, 19, 6, 21, 53, 0, time.UTC)
	return &repository.AlertOperationalBreakdown{CountUnit: "security_events", EventCount: 147394, Last24hCount: 1902, BlockedCount: 831, LatestAt: &latest,
		Reasons: []repository.AlertOperationalReasonCount{{Reason: "inspection_invalid_json", EventCount: 2349, Last24hCount: 831, BlockedCount: 831}}}, nil
}

// The breakdown shares the list's tenant/project/identity/time scope, refuses
// attack filters, and never counts as an attack occurrence.
func TestAlertOperationalSummaryScopesAndValidation(t *testing.T) {
	for _, tc := range []struct {
		role, query string
		status      int
		called      bool
	}{
		{"tenant_admin", "request_id=req1&start_time=2026-09-18T00:00:00Z", 200, true},
		{"platform_admin", "", 200, true},
		{"dept_manager", "project_id=foreign-project", 200, false},
		{"tenant_admin", "category=email", 400, false},
		{"tenant_admin", "severity=high", 400, false},
		{"tenant_admin", "reason=judge_capacity_deferred", 400, false},
		{"dept_manager", "include_raw=true", 404, false},
	} {
		s := &operationalSummaryStub{}
		w := httptest.NewRecorder()
		r := occurrenceRequest(tc.role, tc.query)
		r.URL.Path = "/admin/v1/security/alert-occurrences/operational/summary"
		SummarizeAlertOperationalEvents(&Dependencies{AlertOccurrenceRepo: s}).ServeHTTP(w, r)
		if w.Code != tc.status || s.summarized != tc.called {
			t.Fatalf("%+v status=%d stub=%+v body=%s", tc, w.Code, s, w.Body.String())
		}
		var b repository.AlertOperationalBreakdown
		if w.Code == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || b.CountUnit != "security_events" {
				t.Fatalf("summary contract: %s", w.Body.String())
			}
		}
		if tc.called {
			if s.filter.TenantID != "tenant-a" || s.filter.RequestID != r.URL.Query().Get("request_id") || s.filter.Reason != "" {
				t.Fatalf("summary scope: %+v", s.filter)
			}
			if b.EventCount != 147394 || b.Last24hCount != 1902 || b.BlockedCount != 831 || len(b.Reasons) != 1 || b.Reasons[0].Reason != "inspection_invalid_json" || b.LatestAt == nil {
				t.Fatalf("summary payload: %s", w.Body.String())
			}
		} else if w.Code == 200 && (b.EventCount != 0 || len(b.Reasons) != 0) {
			t.Fatalf("empty authorization must be an empty summary: %s", w.Body.String())
		}
	}
	s := &operationalSummaryStub{}
	req := occurrenceRequest("tenant_admin", "")
	req.URL.Path = "/admin/v1/security/alert-occurrences/operational/summary"
	auth.GetSession(req.Context()).TenantID = "foreign"
	w := httptest.NewRecorder()
	SummarizeAlertOperationalEvents(&Dependencies{AlertOccurrenceRepo: s}).ServeHTTP(w, req)
	if w.Code != 401 || s.called {
		t.Fatalf("invalid session reached operational summary: %d", w.Code)
	}
	// A repository without breakdown support degrades explicitly, never as attacks.
	w = httptest.NewRecorder()
	SummarizeAlertOperationalEvents(&Dependencies{AlertOccurrenceRepo: &occurrenceReaderStub{}}).ServeHTTP(w, occurrenceRequest("tenant_admin", ""))
	if w.Code != 503 {
		t.Fatalf("missing summary reader status=%d", w.Code)
	}
}

// Reasons narrow the coverage-gap list only; they are runtime identifiers and
// never reach the attack occurrence query.
func TestAlertOperationalReasonFilter(t *testing.T) {
	s := &occurrenceReaderStub{}
	w := httptest.NewRecorder()
	ListAlertOperationalEvents(&Dependencies{AlertOccurrenceRepo: s}).ServeHTTP(w, occurrenceRequest("tenant_admin", "reason=Judge_Capacity_Deferred"))
	if w.Code != 200 || !s.operational || s.filter.Reason != "judge_capacity_deferred" {
		t.Fatalf("reason filter status=%d filter=%+v", w.Code, s.filter)
	}
	for _, q := range []string{"reason=judge%20capacity", "reason=judge-drop", "reason=judge%2Fdrop", "reason=" + strings.Repeat("a", 65)} {
		s := &occurrenceReaderStub{}
		w := httptest.NewRecorder()
		ListAlertOperationalEvents(&Dependencies{AlertOccurrenceRepo: s}).ServeHTTP(w, occurrenceRequest("tenant_admin", q))
		if w.Code != 400 || s.called {
			t.Fatalf("%s status=%d called=%v", q, w.Code, s.called)
		}
	}
	s = &occurrenceReaderStub{}
	w = httptest.NewRecorder()
	ListAlertOccurrences(&Dependencies{AlertOccurrenceRepo: s}).ServeHTTP(w, occurrenceRequest("tenant_admin", "reason=judge_capacity_deferred"))
	if w.Code != 400 || s.called {
		t.Fatalf("attack list accepted a runtime reason: status=%d called=%v", w.Code, s.called)
	}
}
