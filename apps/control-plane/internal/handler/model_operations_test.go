package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/modelops"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type modelOperationsServiceStub struct {
	targets           []modelops.Target
	calls             int
	tenant, actor, id string
	err               error
	filter            modelops.ReadFilter
	history           modelops.HistoryFilter
}

func (s *modelOperationsServiceStub) touch(tenant string) { s.calls++; s.tenant = tenant }
func (s *modelOperationsServiceStub) Config(_ context.Context, t string) (modelops.Config, error) {
	s.touch(t)
	return modelops.DefaultConfig(), s.err
}
func (s *modelOperationsServiceStub) UpdateConfig(_ context.Context, t, a string, _ int64, c modelops.Config, _ bool) (modelops.Config, error) {
	s.touch(t)
	s.actor = a
	return c, s.err
}
func (s *modelOperationsServiceStub) Targets(_ context.Context, t string) ([]modelops.Target, error) {
	s.touch(t)
	return s.targets, s.err
}
func (s *modelOperationsServiceStub) Overview(_ context.Context, t string) (modelops.Overview, error) {
	s.touch(t)
	return modelops.Overview{}, s.err
}
func (s *modelOperationsServiceStub) OverviewFiltered(_ context.Context, t string, f modelops.ReadFilter) (modelops.Overview, error) {
	s.touch(t)
	s.filter = f
	return modelops.Overview{}, s.err
}
func (s *modelOperationsServiceStub) History(_ context.Context, t string, f modelops.HistoryFilter) (modelops.HistoryPage, error) {
	s.touch(t)
	s.history = f
	return modelops.HistoryPage{}, s.err
}
func (s *modelOperationsServiceStub) Quality(_ context.Context, t string) (modelops.Quality, error) {
	s.touch(t)
	return modelops.Quality{}, s.err
}
func (s *modelOperationsServiceStub) QualityFiltered(_ context.Context, t string, f modelops.ReadFilter) (modelops.Quality, error) {
	s.touch(t)
	s.filter = f
	return modelops.Quality{}, s.err
}
func (s *modelOperationsServiceStub) Alerts(_ context.Context, t string, _ modelops.AlertFilter) (modelops.AlertPage, error) {
	s.touch(t)
	return modelops.AlertPage{}, s.err
}
func (s *modelOperationsServiceStub) Test(_ context.Context, t, a string, _ modelops.TestRequest) (modelops.TestResult, error) {
	s.touch(t)
	s.actor = a
	return modelops.TestResult{}, s.err
}
func (s *modelOperationsServiceStub) AcknowledgeAlert(_ context.Context, t, id, a string) (modelops.Alert, error) {
	s.touch(t)
	s.id = id
	s.actor = a
	return modelops.Alert{}, s.err
}

func modelOperationsRequest(method, path, body string, user *repository.User) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if user != nil {
		r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, user))
	}
	return r
}

func TestModelOperationsConfigCASPreservesConflictAndRequiresConfirmation(t *testing.T) {
	cfg := `{"version":1,"enabled":true,"interval_seconds":300,"concurrency":2,"timeout_seconds":15,"max_targets":50,"max_output_tokens":128,"protocols":["chat"],"failure_threshold":3,"confirm_cost":true}`
	for _, tc := range []struct {
		err  error
		want int
	}{{nil, 200}, {modelops.ErrConflict, 409}, {modelops.ErrCostConfirmation, 400}} {
		s := &modelOperationsServiceStub{err: tc.err}
		h := NewModelOperationsHandler(&Dependencies{PermissionChecker: newModelBatchDeletePermissionAuthorizer()}, s)
		w := httptest.NewRecorder()
		h.PutConfig(w, modelOperationsRequest("PUT", "/admin/v1/model-operations/config", cfg, &repository.User{ID: "actor", TenantID: "tenant"}))
		if w.Code != tc.want || s.tenant != "tenant" || s.actor != "actor" {
			t.Fatalf("code=%d body=%s stub=%+v", w.Code, w.Body.String(), s)
		}
	}
}

func TestModelOperationsFiltersCarryRealWindowAndBoundPagination(t *testing.T) {
	user := &repository.User{ID: "actor", TenantID: "tenant"}
	s := &modelOperationsServiceStub{}
	h := NewModelOperationsHandler(&Dependencies{PermissionChecker: newModelBatchDeletePermissionAuthorizer()}, s)
	w := httptest.NewRecorder()
	h.GetOverview(w, modelOperationsRequest("GET", "/admin/v1/model-operations/overview?window_hours=72&provider_id=provider-1&model_id=model-1", "", user))
	if w.Code != 200 || s.filter.WindowHours != 72 || s.filter.ModelID != "model-1" || s.filter.ProviderID != "provider-1" {
		t.Fatalf("code=%d filter=%+v", w.Code, s.filter)
	}
	w = httptest.NewRecorder()
	h.GetHistory(w, modelOperationsRequest("GET", "/admin/v1/model-operations/history?window_hours=6&limit=13&cursor=opaque&source=manual", "", user))
	if w.Code != 200 || s.history.WindowHours != 6 || s.history.Limit != 13 || s.history.Cursor != "opaque" {
		t.Fatalf("code=%d history=%+v", w.Code, s.history)
	}
	for _, query := range []string{"?window_hours=169", "?window_hours=0", "?window_hours=6&window_hours=24", "?tenant_id=other", "?window_hours=%xx", "?window_hours=24;tenant_id=other"} {
		before := s.calls
		w = httptest.NewRecorder()
		h.GetQuality(w, modelOperationsRequest("GET", "/admin/v1/model-operations/quality"+query, "", user))
		if w.Code != 400 || s.calls != before {
			t.Fatalf("query=%s code=%d calls=%d", query, w.Code, s.calls)
		}
	}
	for _, raw := range []string{"0", "101", "x"} {
		w = httptest.NewRecorder()
		h.GetHistory(w, modelOperationsRequest("GET", "/admin/v1/model-operations/history?limit="+raw, "", user))
		if w.Code != 400 {
			t.Fatalf("limit=%s code=%d", raw, w.Code)
		}
	}
}

func TestModelOperationsAcknowledgementIsTenantScopedAndEmptyBody(t *testing.T) {
	s := &modelOperationsServiceStub{}
	h := NewModelOperationsHandler(&Dependencies{PermissionChecker: newModelBatchDeletePermissionAuthorizer()}, s)
	for _, body := range []string{"", `{"tenant_id":"other"}`} {
		r := modelOperationsRequest("POST", "/admin/v1/model-operations/alerts/alert-1/ack", body, &repository.User{ID: "actor", TenantID: "tenant"})
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "alert-1")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()
		h.AcknowledgeAlert(w, r)
		if body == "" && (w.Code != 200 || s.tenant != "tenant" || s.actor != "actor" || s.id != "alert-1") {
			t.Fatalf("code=%d stub=%+v", w.Code, s)
		}
		if body != "" && w.Code != 400 {
			t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
		}
	}
}

func TestModelOperationsReadUsesReadPermissionAndNormalizesEmptyTargets(t *testing.T) {
	s := &modelOperationsServiceStub{}
	p := newModelBatchDeletePermissionAuthorizer()
	h := NewModelOperationsHandler(&Dependencies{PermissionChecker: p}, s)
	w := httptest.NewRecorder()
	h.GetTargets(w, modelOperationsRequest("GET", "/admin/v1/model-operations/targets", "", &repository.User{ID: "actor", TenantID: "tenant"}))
	var response struct {
		Items []modelops.Target `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || response.Items == nil || len(p.calls) != 1 || p.calls[0].action != "read" {
		t.Fatalf("code=%d body=%s permission=%+v", w.Code, w.Body.String(), p.calls)
	}
}

func TestModelOperationsSLAReadGuardIsFailClosedAndRejectsMalformedQuery(t *testing.T) {
	for _, tc := range []struct {
		path       string
		permission bool
		want       int
	}{
		{"/admin/v1/model-operations/sla?month=2026-10", false, 403},
		{"/admin/v1/model-operations/sla/export?month=2026-10", false, 403},
		{"/admin/v1/model-operations/sla?month=2026-10&month=2026-09", true, 400},
		{"/admin/v1/model-operations/sla?month=%xx", true, 400},
		{"/admin/v1/model-operations/sla?month=2026-10;tenant_id=foreign", true, 400},
		{"/admin/v1/model-operations/sla?tenant_id=foreign", true, 400},
		{"/admin/v1/model-operations/sla/export?month=2026-10&timezone=Asia%2FShanghai", true, 204},
	} {
		calls := 0
		p := &modelBatchDeletePermissionAuthorizer{allowed: tc.permission}
		h := NewModelOperationsHandler(&Dependencies{PermissionChecker: p}, &modelOperationsServiceStub{})
		guard := h.RequireReadQuery(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }, "month", "timezone", "provider_id", "model_id")
		w := httptest.NewRecorder()
		guard(w, modelOperationsRequest("GET", tc.path, "", &repository.User{ID: "actor", TenantID: "tenant"}))
		if w.Code != tc.want || (calls != 0 && tc.want != 204) || len(p.calls) != 1 || p.calls[0].action != "read" {
			t.Fatalf("path=%s code=%d next_calls=%d perms=%+v", tc.path, w.Code, calls, p.calls)
		}
	}
}

func TestModelOperationsTargetsApplyProviderAndModelFilters(t *testing.T) {
	s := &modelOperationsServiceStub{targets: []modelops.Target{
		{ModelID: "m1", ProviderID: "p1"}, {ModelID: "m2", ProviderID: "p2"}, {ModelID: "m3", ProviderID: "p1"},
	}}
	h := NewModelOperationsHandler(&Dependencies{PermissionChecker: newModelBatchDeletePermissionAuthorizer()}, s)
	for _, tc := range []struct {
		query string
		want  int
		ids   string
	}{
		{"?provider_id=p1", 200, "m1,m3"}, {"?provider_id=p1&model_id=m3", 200, "m3"},
		{"?provider_id=p2&model_id=m1", 200, ""}, {"?provider_id=missing", 200, ""},
		{"?provider_id=p1&provider_id=p2", 400, ""}, {"?tenant_id=other", 400, ""},
		{"?provider_id=bad%2Fid", 400, ""}, {"?limit=25", 400, ""},
	} {
		w := httptest.NewRecorder()
		h.GetTargets(w, modelOperationsRequest("GET", "/admin/v1/model-operations/targets"+tc.query, "", &repository.User{ID: "actor", TenantID: "tenant"}))
		if w.Code != tc.want {
			t.Fatalf("%s: code=%d body=%s", tc.query, w.Code, w.Body.String())
		}
		if tc.want == 200 {
			var result struct {
				Items []modelops.Target `json:"items"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			ids := []string{}
			for _, item := range result.Items {
				ids = append(ids, item.ModelID)
			}
			if result.Items == nil || strings.Join(ids, ",") != tc.ids || s.tenant != "tenant" {
				t.Fatalf("filter leaked or ignored: %+v", result)
			}
		}
	}
}

func (s *modelOperationsServiceStub) ProviderMonitor(_ context.Context, t string, f modelops.ReadFilter) (modelops.ProviderMonitor, error) {
	s.touch(t)
	s.filter = f
	return modelops.ProviderMonitor{Items: []modelops.ProviderStat{}}, s.err
}

func TestModelOperationsProvidersUsesTenantAndFilter(t *testing.T) {
	s := &modelOperationsServiceStub{}
	h := NewModelOperationsHandler(&Dependencies{PermissionChecker: newModelBatchDeletePermissionAuthorizer()}, s)
	user := &repository.User{ID: "actor", TenantID: "tenant"}
	w := httptest.NewRecorder()
	h.GetProviders(w, modelOperationsRequest("GET", "/admin/v1/model-operations/providers?window_hours=72&provider_id=p1", "", user))
	if w.Code != 200 || s.tenant != "tenant" || s.filter.WindowHours != 72 || s.filter.ProviderID != "p1" {
		t.Fatalf("code=%d tenant=%s filter=%+v body=%s", w.Code, s.tenant, s.filter, w.Body.String())
	}
	before := s.calls
	w = httptest.NewRecorder()
	h.GetProviders(w, modelOperationsRequest("GET", "/admin/v1/model-operations/providers?window_hours=5", "", user))
	if w.Code != 400 || s.calls != before {
		t.Fatalf("非法窗口必须在 handler 拒绝: %d", w.Code)
	}
}
