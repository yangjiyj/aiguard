package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type occurrenceReaderStub struct {
	called      bool
	operational bool
	filter      repository.AlertOccurrenceFilter
}

func (s *occurrenceReaderStub) ListOperational(_ context.Context, f repository.AlertOccurrenceFilter) (*repository.AlertOperationalPage, error) {
	s.called = true
	s.operational = true
	s.filter = f
	return &repository.AlertOperationalPage{Items: []repository.AlertOperationalEvent{{EventID: "gap", RequestID: f.RequestID, Classification: "operational_gap"}}, Total: 3, Limit: f.Limit, Offset: f.Offset, CountUnit: "security_events"}, nil
}

func (s *occurrenceReaderStub) List(_ context.Context, f repository.AlertOccurrenceFilter) (*repository.AlertOccurrencePage, error) {
	s.called = true
	s.filter = f
	return &repository.AlertOccurrencePage{Items: []repository.AlertOccurrence{{ID: "occurrence", RawEvidence: "private", EvidenceContext: "private context", Reason: "private reason"}}, Total: 1, Limit: f.Limit, Offset: f.Offset, Operational: repository.AlertOperationalSummary{EventCount: 7}}, nil
}

func occurrenceRequest(role, query string) *http.Request {
	r := contentAuditAuthRequest(role)
	r.URL.Path = "/admin/v1/security/alert-occurrences"
	r.URL.RawQuery = query
	return r
}

func TestAlertOccurrenceAuthorization(t *testing.T) {
	cases := []struct {
		name, role, query string
		want              int
		change            func(*http.Request)
	}{
		{"anonymous", "", "", 401, func(r *http.Request) { *r = *r.WithContext(context.Background()) }},
		{"missing session", "tenant_admin", "", 401, func(r *http.Request) {
			*r = *r.WithContext(context.WithValue(r.Context(), auth.SessionKey, (*repository.Session)(nil)))
		}},
		{"mixed tenant", "tenant_admin", "", 401, func(r *http.Request) { auth.GetSession(r.Context()).TenantID = "other" }},
		{"mixed user", "tenant_admin", "", 401, func(r *http.Request) { auth.GetSession(r.Context()).UserID = "other" }},
		{"emergency", "tenant_admin", "", 404, func(r *http.Request) { auth.GetUser(r.Context()).DepartmentAssignmentMode = "emergency" }},
		{"raw department", "dept_manager", "include_raw=true", 200, nil},
		{"department without projects", "dept_manager", "", 200, nil},
		{"department project injection", "dept_manager", "project_id=foreign-project", 200, nil},
		{"department raw false", "dept_manager", "include_raw=false", 200, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &occurrenceReaderStub{}
			req := occurrenceRequest(tc.role, tc.query)
			if tc.change != nil {
				tc.change(req)
			}
			w := httptest.NewRecorder()
			ListAlertOccurrences(&Dependencies{AlertOccurrenceRepo: stub}).ServeHTTP(w, req)
			if w.Code != tc.want || stub.called {
				t.Fatalf("status=%d want=%d called=%v body=%s", w.Code, tc.want, stub.called, w.Body.String())
			}
			if w.Code == 200 {
				var p repository.AlertOccurrencePage
				if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Total != 0 || len(p.Items) != 0 || p.Counts.Total != 0 {
					t.Fatalf("empty scope: %s", w.Body.String())
				}
			}
		})
	}
}

func TestAlertOccurrenceQueryAndRawPermission(t *testing.T) {
	for _, include := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "raw"}[include], func(t *testing.T) {
			stub := &occurrenceReaderStub{}
			query := "limit=1000&offset=2&tenant_id=other&request_id=req1&severity=medium&category=email&include_suppressed=true"
			if include {
				query += "&include_raw=true"
			}
			w := httptest.NewRecorder()
			ListAlertOccurrences(&Dependencies{AlertOccurrenceRepo: stub}).ServeHTTP(w, occurrenceRequest("tenant_admin", query))
			if w.Code != 200 || !stub.called {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			f := stub.filter
			if f.TenantID != "tenant-a" || f.Limit != 100 || f.Offset != 2 || f.RequestID != "req1" || f.Severity != "medium" || f.Category != "email" || !f.IncludeSuppressed || f.IncludeRaw != include || !f.CanReadEvidence {
				t.Fatalf("filter: %+v", f)
			}
			var page repository.AlertOccurrencePage
			if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			if (page.Items[0].RawEvidence != "") != include || (page.Items[0].EvidenceContext != "") != include {
				t.Fatalf("raw disclosure: %+v", page.Items[0])
			}
			link, err := url.Parse(page.Operational.ListURL)
			if err != nil || link.Path != "/admin/v1/security/alert-occurrences/operational" || link.Query().Get("request_id") != "req1" || len(link.Query()) != 1 || page.Operational.EventCount != 7 || page.Operational.CountUnit != "security_events" {
				t.Fatalf("operational link lost scope or inherited raw/attack filters: %+v", page.Operational)
			}
		})
	}
}

func TestAlertOperationalEndpointScopesAndValidation(t *testing.T) {
	for _, tc := range []struct {
		role, query string
		status      int
		called      bool
	}{
		{"tenant_admin", "limit=2&offset=1&request_id=req1", 200, true},
		{"dept_manager", "project_id=foreign-project", 200, false},
		{"tenant_admin", "category=email", 400, false},
		{"tenant_admin", "severity=critical", 400, false},
		{"dept_manager", "include_raw=true", 404, false},
	} {
		s := &occurrenceReaderStub{}
		w := httptest.NewRecorder()
		ListAlertOperationalEvents(&Dependencies{AlertOccurrenceRepo: s}).ServeHTTP(w, occurrenceRequest(tc.role, tc.query))
		if w.Code != tc.status || s.called != tc.called || s.operational != tc.called {
			t.Fatalf("%+v status=%d stub=%+v body=%s", tc, w.Code, s, w.Body.String())
		}
		if tc.called {
			if s.filter.TenantID != "tenant-a" || s.filter.RequestID != "req1" || s.filter.Offset != 1 {
				t.Fatalf("operational scope: %+v", s.filter)
			}
			var p repository.AlertOperationalPage
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Total != 3 || p.CountUnit != "security_events" {
				t.Fatalf("operational contract: %s", w.Body.String())
			}
		}
	}
	s := &occurrenceReaderStub{}
	req := occurrenceRequest("tenant_admin", "")
	auth.GetSession(req.Context()).TenantID = "foreign"
	w := httptest.NewRecorder()
	ListAlertOperationalEvents(&Dependencies{AlertOccurrenceRepo: s}).ServeHTTP(w, req)
	if w.Code != 401 || s.called {
		t.Fatalf("invalid session reached operational reader: %d", w.Code)
	}
}

func TestAlertOccurrenceInvalidQueriesNeverRead(t *testing.T) {
	for _, q := range []string{"recent_limit=100", "grouping=hits&recent_limit=100", "grouping=cases&recent_limit=101", "grouping=cases&recent_limit=-1", "grouping=cases&recent_limit=abc", "limit=0", "limit=-1", "limit=x", "offset=-1", "offset=x", "include_raw=perhaps", "include_suppressed=maybe", "severity=extreme", "start_time=bad", "end_time=bad", "start_time=2026-09-19T00:00:00Z&end_time=2026-09-18T00:00:00Z"} {
		t.Run(q, func(t *testing.T) {
			s := &occurrenceReaderStub{}
			w := httptest.NewRecorder()
			ListAlertOccurrences(&Dependencies{AlertOccurrenceRepo: s}).ServeHTTP(w, occurrenceRequest("tenant_admin", q))
			if w.Code != 400 || s.called {
				t.Fatalf("status=%d called=%v body=%s", w.Code, s.called, w.Body.String())
			}
		})
	}
}

func TestAlertOccurrenceRecentScopeParsing(t *testing.T) {
	f, err := parseAlertOccurrenceFilter(httptest.NewRequest("GET", "/admin/v1/security/alert-occurrences?grouping=cases&recent_limit=100&limit=10&offset=90", nil))
	if err != nil || f.RecentLimit != 100 || f.Limit != 10 || f.Offset != 90 {
		t.Fatalf("wrong recent filter: %+v %v", f, err)
	}
}

func TestAlertOccurrenceLaneParsing(t *testing.T) {
	for lane, want := range map[string]string{"action": "action", "watch": "watch", "eval": "eval", "all": ""} {
		f, err := parseAlertOccurrenceFilter(httptest.NewRequest("GET", "/admin/v1/security/alert-occurrences?grouping=cases&lane="+lane, nil))
		if err != nil || !f.LaneAware || f.Lane != want {
			t.Fatalf("lane=%s parsed as %+v err=%v", lane, f, err)
		}
	}
	// 不带 lane 参数的老客户端：全局口径不变，不启用车道。
	f, err := parseAlertOccurrenceFilter(httptest.NewRequest("GET", "/admin/v1/security/alert-occurrences?grouping=cases", nil))
	if err != nil || f.LaneAware || f.Lane != "" {
		t.Fatalf("legacy request must not enable lanes: %+v err=%v", f, err)
	}
}

func TestAlertOccurrenceInvalidLaneNeverReads(t *testing.T) {
	for _, q := range []string{"grouping=cases&lane=bogus", "grouping=cases&lane=ACTION%27%3B--", "grouping=hits&lane=action"} {
		s := &occurrenceReaderStub{}
		w := httptest.NewRecorder()
		ListAlertOccurrences(&Dependencies{AlertOccurrenceRepo: s}).ServeHTTP(w, occurrenceRequest("tenant_admin", q))
		if w.Code != 400 || s.called {
			t.Fatalf("%s: status=%d called=%v body=%s", q, w.Code, s.called, w.Body.String())
		}
	}
}
