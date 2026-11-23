package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"net/http/httptest"
	"testing"
)

type caseSummaryStub struct{ occurrenceReaderStub }

func (s *caseSummaryStub) SummarizeCases(_ context.Context, f repository.AlertOccurrenceFilter) (*repository.AlertCaseSummary, error) {
	s.called = true
	s.filter = f
	return &repository.AlertCaseSummary{CountUnit: "triage_cases", Total: 2, Categories: []repository.AlertCaseCategoryCount{{Category: "pii_email", Count: 2}}}, nil
}
func TestAlertCaseSummaryAuthorizationAndFilters(t *testing.T) {
	for _, tc := range []struct {
		role, query string
		status      int
		called      bool
	}{
		{"tenant_admin", "disposition=pending&start_time=2026-09-19T00:00:00Z&category=email,secret", 200, true},
		{"dept_manager", "project_id=foreign", 200, false},
		{"tenant_admin", "grouping=hits", 400, false},
		{"tenant_admin", "reason=judge_timeout", 400, false},
	} {
		stub := &caseSummaryStub{}
		w := httptest.NewRecorder()
		req := occurrenceRequest(tc.role, tc.query)
		SummarizeAlertCases(&Dependencies{AlertOccurrenceRepo: stub}).ServeHTTP(w, req)
		if w.Code != tc.status || stub.called != tc.called {
			t.Fatalf("case %+v status=%d called=%v body=%s", tc, w.Code, stub.called, w.Body.String())
		}
		if tc.called && (stub.filter.TenantID != "tenant-a" || stub.filter.Grouping != "cases" || stub.filter.IncludeRaw) {
			t.Fatalf("scope lost: %+v", stub.filter)
		}
		if !tc.called && tc.status == 200 {
			var out repository.AlertCaseSummary
			if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil || out.Total != 0 || len(out.Categories) != 0 {
				t.Fatalf("empty authorization leaked: %s", w.Body.String())
			}
		}
	}
}
