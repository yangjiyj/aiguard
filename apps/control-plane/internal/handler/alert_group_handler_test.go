package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeAlertGroupRepo struct {
	listTenant    string
	listFilter    repository.AlertGroupListFilter
	statusTenant  string
	statusID      string
	status        repository.AlertGroupStatus
	actorID       string
	note          string
	fpEventTenant string
	fpEventID     string
	fpActorID     string
	fpNote        string
	groups        []*repository.AlertGroup
	eventsTenant  string
	eventsGroupID string
	eventsFilter  repository.AlertGroupEventListFilter
}

func (f *fakeAlertGroupRepo) List(ctx context.Context, filter repository.AlertGroupListFilter) ([]*repository.AlertGroup, error) {
	f.listTenant = filter.TenantID
	f.listFilter = filter
	return f.groups, nil
}

func (f *fakeAlertGroupRepo) GetByID(ctx context.Context, tenantID, id string) (*repository.AlertGroup, error) {
	for _, group := range f.groups {
		if group.ID == id && group.TenantID == tenantID {
			return group, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (f *fakeAlertGroupRepo) UpdateStatus(ctx context.Context, tenantID, id string, status repository.AlertGroupStatus, actorID, note string) (*repository.AlertGroup, error) {
	f.statusTenant = tenantID
	f.statusID = id
	f.status = status
	f.actorID = actorID
	f.note = note
	return &repository.AlertGroup{ID: id, TenantID: tenantID, Status: status, Severity: "high", AlertType: "security_event", Title: "已处置", OccurrenceCount: 2, LastSeenAt: time.Now().UTC()}, nil
}

func (f *fakeAlertGroupRepo) MarkFalsePositiveBySecurityEvent(ctx context.Context, tenantID, eventID, actorID, note string) (*repository.AlertGroup, error) {
	f.fpEventTenant = tenantID
	f.fpEventID = eventID
	f.fpActorID = actorID
	f.fpNote = note
	return &repository.AlertGroup{ID: "ag_from_event", TenantID: tenantID, Status: repository.AlertGroupStatusFalsePositive}, nil
}

func (f *fakeAlertGroupRepo) ListGroupEvents(ctx context.Context, tenantID, groupID string, filter repository.AlertGroupEventListFilter) ([]*repository.AlertGroupEvent, int, error) {
	f.eventsTenant = tenantID
	f.eventsGroupID = groupID
	f.eventsFilter = filter
	return []*repository.AlertGroupEvent{{
		RowKey:  "ck_x",
		EventID: "evt_1", RequestID: "req_1", PrincipalKey: "user_1",
		ConversationKey: "ck_x", EventType: "security_check", Severity: "high",
		ActionTaken: "security_audit", CreatedAt: time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC),
		EventCount: 3, FirstSeenAt: time.Date(2026, 7, 1, 7, 0, 0, 0, time.UTC),
		LastSeenAt: time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC),
	}}, 1, nil
}

func alertGroupTestRequest(method, target, tenantID, userID string, body *strings.Reader) *http.Request {
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, body)
	}
	user := &repository.User{ID: userID, TenantID: tenantID, Role: "platform_admin", Status: "active"}
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	ctx = context.WithValue(ctx, auth.SessionKey, &repository.Session{UserID: userID, TenantID: tenantID})
	return req.WithContext(ctx)
}

func TestListAlertGroupsUsesTenantScopeAndDTO(t *testing.T) {
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	repo := &fakeAlertGroupRepo{groups: []*repository.AlertGroup{{ID: "ag_1", TenantID: "tenant_default", GroupKey: "secret|abc", Status: repository.AlertGroupStatusOpen, Severity: "high", AlertType: "security_event", Title: "疑似密钥泄露", OccurrenceCount: 3, FirstSeenAt: now.Add(-time.Hour), LastSeenAt: now, RepresentativeEventID: "sec_1", RequestID: "req_1", PrincipalKey: "user_1"}}}
	deps := &Dependencies{AlertGroupRepo: repo}
	req := alertGroupTestRequest(http.MethodGet, "/admin/v1/alert-groups?status=open&severity=high&limit=10", "tenant_default", "user_1", nil)
	rr := httptest.NewRecorder()

	ListAlertGroups(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if repo.listTenant != "tenant_default" || repo.listFilter.Status != repository.AlertGroupStatusOpen || repo.listFilter.Severity != "high" || repo.listFilter.Limit != 10 {
		t.Fatalf("unexpected list filter: %+v", repo.listFilter)
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	items := resp["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	item := items[0].(map[string]any)
	for _, key := range []string{"id", "severity", "status", "type", "title", "occurrence_count", "first_seen_at", "last_seen_at", "representative_event_id", "request_id"} {
		if _, ok := item[key]; !ok {
			t.Fatalf("response missing %s: %#v", key, item)
		}
	}
	if _, leaked := item["principal_key"]; leaked {
		t.Fatalf("response leaked internal principal_key: %#v", item)
	}
	if _, leaked := item["TenantID"]; leaked {
		t.Fatalf("response leaked Go field names: %#v", item)
	}
}

func TestUpdateAlertGroupStatusUsesTenantAndActor(t *testing.T) {
	repo := &fakeAlertGroupRepo{}
	deps := &Dependencies{AlertGroupRepo: repo}
	req := alertGroupTestRequest(http.MethodPatch, "/admin/v1/alert-groups/ag_1", "tenant_default", "user_1", strings.NewReader(`{"status":"resolved","note":"已确认处理"}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "ag_1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	UpdateAlertGroupStatus(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if repo.statusTenant != "tenant_default" || repo.statusID != "ag_1" || repo.status != repository.AlertGroupStatusResolved || repo.actorID != "user_1" || repo.note != "已确认处理" {
		t.Fatalf("unexpected status update call: tenant=%s id=%s status=%s actor=%s note=%s", repo.statusTenant, repo.statusID, repo.status, repo.actorID, repo.note)
	}
}

func TestListAlertGroupEvents(t *testing.T) {
	repo := &fakeAlertGroupRepo{}
	deps := &Dependencies{AlertGroupRepo: repo}
	req := alertGroupTestRequest(http.MethodGet, "/admin/v1/alert-groups/ag_1/events?view=conversations&limit=20", "tenant_default", "user_1", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "ag_1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	ListAlertGroupEvents(deps)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if repo.eventsTenant != "tenant_default" || repo.eventsGroupID != "ag_1" || repo.eventsFilter.View != repository.AlertGroupEventViewConversations || repo.eventsFilter.Limit != 20 || repo.eventsFilter.Offset != 0 {
		t.Fatalf("unexpected events call: tenant=%s id=%s filter=%+v", repo.eventsTenant, repo.eventsGroupID, repo.eventsFilter)
	}
	var out struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 1 || len(out.Items) != 1 || out.Items[0]["row_key"] != "ck_x" || out.Items[0]["event_count"] != float64(3) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestListAlertGroupEventsRejectsInvalidView(t *testing.T) {
	repo := &fakeAlertGroupRepo{}
	deps := &Dependencies{AlertGroupRepo: repo}
	req := alertGroupTestRequest(http.MethodGet, "/admin/v1/alert-groups/ag_1/events?view=internal", "tenant_default", "user_1", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "ag_1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	ListAlertGroupEvents(deps)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if repo.eventsGroupID != "" {
		t.Fatalf("repository must not be called for invalid view: %+v", repo.eventsFilter)
	}
}

func TestUpsertAuditDispositionUsesRepositoryAtomicAlertGroupUpdate(t *testing.T) {
	dispositionRepo := &fakeLinkedDispositionRepo{}
	groupRepo := &fakeAlertGroupRepo{}
	deps := &Dependencies{AuditDispositionRepo: dispositionRepo, AlertGroupRepo: groupRepo}
	body := bytes.NewBufferString(`{"subject_type":"security_event","subject_id":"sec_1","status":"false_positive","note":"已确认上下文误报"}`)
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/audit/dispositions", body)
	req = withAuditDispositionUser(req, &repository.User{ID: "user_admin", Username: "admin", TenantID: "tenant_a", Role: "platform_admin"})
	w := httptest.NewRecorder()
	UpsertAuditDisposition(deps).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if dispositionRepo.linkedCalls != 1 {
		t.Fatalf("security-event FP must use atomic repository path, calls=%d", dispositionRepo.linkedCalls)
	}
	if groupRepo.fpEventID != "" {
		t.Fatalf("handler must not repeat repository-owned group mutation, event=%q", groupRepo.fpEventID)
	}
	if dispositionRepo.last == nil || dispositionRepo.last.Status != "false_positive" {
		t.Fatalf("audit disposition was not preserved: %#v", dispositionRepo.last)
	}
}
