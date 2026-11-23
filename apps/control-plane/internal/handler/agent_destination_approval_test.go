package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// fakeDestinationApprovalRepo is a minimal in-memory double for
// AgentDestinationApprovalRepo, letting the handler-layer tests assert on
// exactly what tenant/actor/input values reached the repository without a
// real database.
type fakeDestinationApprovalRepo struct {
	tenant       string
	filter       repository.DestinationApprovalRuleFilter
	createInput  repository.DestinationApprovalRuleCreate
	deactivateID string
	actor        string
	calls        int

	listPage *repository.DestinationApprovalRulePage
	created  *repository.DestinationApprovalRule
	deactOK  bool
	err      error
}

func (f *fakeDestinationApprovalRepo) List(_ context.Context, tenant string, filter repository.DestinationApprovalRuleFilter) (*repository.DestinationApprovalRulePage, error) {
	f.tenant, f.filter = tenant, filter
	if f.listPage == nil {
		return &repository.DestinationApprovalRulePage{}, nil
	}
	return f.listPage, f.err
}

func (f *fakeDestinationApprovalRepo) Create(_ context.Context, tenant string, input repository.DestinationApprovalRuleCreate) (*repository.DestinationApprovalRule, error) {
	f.tenant, f.createInput = tenant, input
	f.calls++
	return f.created, f.err
}

func (f *fakeDestinationApprovalRepo) Deactivate(_ context.Context, tenant, id, actor string) (bool, error) {
	f.tenant, f.deactivateID, f.actor = tenant, id, actor
	f.calls++
	return f.deactOK, f.err
}

// TestDestinationApprovalListIsTenantScopedAndFiltersQueryParams asserts the
// admin's authenticated tenant is always used (never a client-supplied
// tenant_id override, matching every other agent admin endpoint), and that
// category/enabled query params reach the repository filter.
func TestDestinationApprovalListIsTenantScopedAndFiltersQueryParams(t *testing.T) {
	repo := &fakeDestinationApprovalRepo{}
	api := NewAgentDestinationApprovalAPI(repo, &Dependencies{})

	rec := httptest.NewRecorder()
	api.List(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/approval-rules?category=official&enabled=true&tenant_id=tenant-b", "tenant_admin", nil))
	if rec.Code != http.StatusOK || repo.tenant != "tenant-a" || strings.Contains(rec.Body.String(), "tenant-b") {
		t.Fatalf("list status=%d tenant=%q body=%s", rec.Code, repo.tenant, rec.Body.String())
	}
	if repo.filter.Category != "official" || repo.filter.Enabled == nil || !*repo.filter.Enabled {
		t.Fatalf("list filter not propagated: %+v", repo.filter)
	}

	rec = httptest.NewRecorder()
	api.List(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/approval-rules?enabled=maybe", "tenant_admin", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid enabled value status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestDestinationApprovalCreateMapsConflictAndInvalidInput asserts the two
// sentinel errors the repository can return (ErrDestinationApprovalRuleInvalid,
// ErrDestinationApprovalRuleConflict) map to the correct HTTP status, and that
// a successful create uses the authenticated user as created_by (never a
// client-supplied value) and is tenant-scoped.
func TestDestinationApprovalCreateMapsConflictAndInvalidInput(t *testing.T) {
	repo := &fakeDestinationApprovalRepo{created: &repository.DestinationApprovalRule{ID: "dar_1", RuleID: "official-1", Enabled: true}}
	api := NewAgentDestinationApprovalAPI(repo, &Dependencies{})

	rec := httptest.NewRecorder()
	api.Create(rec, agentAdminRequest(http.MethodPost, "/admin/v1/agent/approval-rules", "tenant_admin",
		[]byte(`{"rule_id":"official-1","match_type":"host","match_value":"api.anthropic.com","category":"official"}`)))
	if rec.Code != http.StatusCreated || repo.tenant != "tenant-a" || repo.createInput.CreatedBy != "user-a" {
		t.Fatalf("create status=%d tenant=%q createdBy=%q body=%s", rec.Code, repo.tenant, repo.createInput.CreatedBy, rec.Body.String())
	}

	// created_by is never accepted from the client body at all (strict
	// decoding rejects the unknown field outright) — created_by always
	// comes from the authenticated session, never client input.
	repo.calls = 0
	rec = httptest.NewRecorder()
	api.Create(rec, agentAdminRequest(http.MethodPost, "/admin/v1/agent/approval-rules", "tenant_admin",
		[]byte(`{"rule_id":"official-1b","match_type":"host","match_value":"api.anthropic.com","category":"official","created_by":"someone-else"}`)))
	if rec.Code != http.StatusBadRequest || repo.calls != 0 {
		t.Fatalf("client-supplied created_by must be rejected as an unknown field: status=%d calls=%d body=%s", rec.Code, repo.calls, rec.Body.String())
	}

	repo.err = repository.ErrDestinationApprovalRuleConflict
	rec = httptest.NewRecorder()
	api.Create(rec, agentAdminRequest(http.MethodPost, "/admin/v1/agent/approval-rules", "tenant_admin",
		[]byte(`{"rule_id":"official-2","match_type":"host","match_value":"api.anthropic.com","category":"official"}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d body=%s", rec.Code, rec.Body.String())
	}

	repo.err = repository.ErrDestinationApprovalRuleInvalid
	rec = httptest.NewRecorder()
	api.Create(rec, agentAdminRequest(http.MethodPost, "/admin/v1/agent/approval-rules", "tenant_admin",
		[]byte(`{"rule_id":"bad rule id","match_type":"host","match_value":"x","category":"official"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid input status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	api.Create(rec, agentAdminRequest(http.MethodPost, "/admin/v1/agent/approval-rules", "tenant_admin", []byte(`{"rule_id":"missing-fields"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing required fields status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestDestinationApprovalDeactivateIsNeverDeleteAndIsTenantScoped asserts a
// deactivate call never targets another tenant's rule id and that a
// not-found repository result maps to 404, never a silent 200.
func TestDestinationApprovalDeactivateIsNeverDeleteAndIsTenantScoped(t *testing.T) {
	repo := &fakeDestinationApprovalRepo{deactOK: true}
	api := NewAgentDestinationApprovalAPI(repo, &Dependencies{})
	router := chi.NewRouter()
	router.Post("/admin/v1/agent/approval-rules/{id}/deactivate", api.Deactivate)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPost, "/admin/v1/agent/approval-rules/dar_1/deactivate", "tenant_admin", nil))
	if rec.Code != http.StatusOK || repo.tenant != "tenant-a" || repo.deactivateID != "dar_1" || repo.actor != "user-a" {
		t.Fatalf("deactivate status=%d tenant=%q id=%q actor=%q body=%s", rec.Code, repo.tenant, repo.deactivateID, repo.actor, rec.Body.String())
	}

	repo.err = repository.ErrDestinationApprovalRuleNotFound
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPost, "/admin/v1/agent/approval-rules/does-not-exist/deactivate", "tenant_admin", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("not-found deactivate status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestDestinationApprovalAPIReadyGuardsUnconfiguredRepo mirrors the
// AgentUnifiedAssetAPI convention: a nil repo must fail closed with 503, not
// panic and not silently behave as an empty catalog.
func TestDestinationApprovalAPIReadyGuardsUnconfiguredRepo(t *testing.T) {
	api := NewAgentDestinationApprovalAPI(nil, &Dependencies{})
	rec := httptest.NewRecorder()
	api.List(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/approval-rules", "tenant_admin", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured repo status=%d body=%s", rec.Code, rec.Body.String())
	}
}
