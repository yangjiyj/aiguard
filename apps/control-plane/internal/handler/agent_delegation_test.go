package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type fakeDelegationAuthorizer struct {
	principal repository.TrustedAgentPrincipal
	request   repository.AgentAuthorizationRequest
	decision  *repository.AgentAuthorizationDecision
	err       error
	calls     int
}

func (f *fakeDelegationAuthorizer) Authorize(_ context.Context, p repository.TrustedAgentPrincipal, r repository.AgentAuthorizationRequest) (*repository.AgentAuthorizationDecision, error) {
	f.principal = p
	f.request = r
	f.calls++
	return f.decision, f.err
}

type fakeDelegationStore struct {
	parent                               repository.TrustedAgentPrincipal
	createCalls                          int
	revokeTenant, revokeParent, revokeID string
	revokeFound                          bool
	listTenant, listParent, listID       string
	listLimit                            int
}

func (f *fakeDelegationStore) Create(_ context.Context, p repository.TrustedAgentPrincipal, input repository.AgentDelegationCreate) (*repository.AgentDelegationCreated, error) {
	f.parent = p
	f.createCalls++
	return &repository.AgentDelegationCreated{Delegation: repository.AgentDelegation{ID: "delegation-1", TenantID: p.TenantID, ParentPrincipalID: p.ID, ChildPrincipalID: "child-1", ProjectID: input.ProjectID, Status: "active", ExpiresAt: input.ExpiresAt}, Credential: strings.Repeat("a", 64), Grants: input.Grants}, nil
}
func (f *fakeDelegationStore) Revoke(_ context.Context, tenant, parent, id string) (bool, error) {
	f.revokeTenant, f.revokeParent, f.revokeID = tenant, parent, id
	return f.revokeFound, nil
}
func (f *fakeDelegationStore) ListCalls(_ context.Context, tenant, parent, id string, limit int) ([]repository.AgentDelegationCall, error) {
	f.listTenant, f.listParent, f.listID, f.listLimit = tenant, parent, id, limit
	return []repository.AgentDelegationCall{}, nil
}

func TestAgentDelegationCreateBindsServerPrincipalProjectAndT13Grant(t *testing.T) {
	principal := repository.TrustedAgentPrincipal{ID: "parent-1", TenantID: "tenant-a", CredentialHash: strings.Repeat("b", 64)}
	authz := &fakeDelegationAuthorizer{decision: &repository.AgentAuthorizationDecision{Allowed: true, Reason: "allowed", PrincipalID: principal.ID, Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a", IdempotencyKey: "authorize-delegate-0001", GrantID: "grant-1"}}
	store := &fakeDelegationStore{}
	api := NewAgentDelegationAPI(authz, store)
	body := `{"name":"child","project_id":"project-a","expires_at":"2026-09-27T12:00:00Z","grants":[{"action":"tickets.update","resource_type":"ticket","resource_id":"ticket-7","conditions":{"project_id":"project-a"},"expires_at":"2026-09-26T18:00:00Z","quota_max":2,"quota_window_seconds":60}],"authorization_idempotency_key":"authorize-delegate-0001","idempotency_key":"create-delegate-0001"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/agent/delegations", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), trustedAgentAuthorizationContextKey{}, &principal))
	rec := httptest.NewRecorder()
	api.Create(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("delegation request failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if authz.calls != 1 || authz.principal.ID != principal.ID || authz.request.Action != "agents.delegate" ||
		authz.request.ResourceType != "project" || authz.request.ResourceID != "project-a" ||
		authz.request.Context["project_id"] != "project-a" || authz.request.IdempotencyKey != "authorize-delegate-0001" {
		t.Fatalf("T13 delegation authority was not exact: %+v calls=%d", authz.request, authz.calls)
	}
	if store.createCalls != 1 || store.parent.ID != "parent-1" || store.parent.TenantID != "tenant-a" {
		t.Fatalf("store did not receive trusted parent identity: %+v", store)
	}
	if rec.Header().Get("Cache-Control") == "" {
		t.Fatal("one-time child credential response must be non-cacheable")
	}
}

func TestAgentDelegationCreateDeniedBeforeChildCreation(t *testing.T) {
	principal := repository.TrustedAgentPrincipal{ID: "parent-1", TenantID: "tenant-a", CredentialHash: strings.Repeat("b", 64)}
	authz := &fakeDelegationAuthorizer{decision: &repository.AgentAuthorizationDecision{Allowed: false, Reason: "no_matching_grant"}}
	store := &fakeDelegationStore{}
	api := NewAgentDelegationAPI(authz, store)
	body := `{"name":"child","project_id":"project-a","expires_at":"2026-09-27T12:00:00Z","grants":[{"action":"tickets.update","resource_type":"ticket","resource_id":"ticket-7","conditions":{"project_id":"project-a"},"expires_at":"2026-09-26T18:00:00Z","quota_max":2,"quota_window_seconds":60}],"authorization_idempotency_key":"authorize-delegate-0001","idempotency_key":"create-delegate-0001"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/agent/delegations", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), trustedAgentAuthorizationContextKey{}, &principal))
	rec := httptest.NewRecorder()
	api.Create(rec, req)
	if rec.Code != http.StatusForbidden || store.createCalls != 0 {
		t.Fatalf("denied T13 request created child: status=%d calls=%d", rec.Code, store.createCalls)
	}
}

func TestAgentDelegationInvestigationIsOwnedByTrustedParent(t *testing.T) {
	principal := repository.TrustedAgentPrincipal{ID: "parent-1", TenantID: "tenant-a", CredentialHash: strings.Repeat("b", 64)}
	store := &fakeDelegationStore{}
	api := NewAgentDelegationAPI(nil, store)
	route := chi.NewRouteContext()
	route.URLParams.Add("id", "delegation-1")
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/agent/delegations/delegation-1/calls?limit=25", nil)
	ctx := context.WithValue(req.Context(), trustedAgentAuthorizationContextKey{}, &principal)
	req = req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, route))
	rec := httptest.NewRecorder()
	api.ListCalls(rec, req)
	if rec.Code != http.StatusOK || store.listTenant != "tenant-a" || store.listParent != "parent-1" || store.listID != "delegation-1" || store.listLimit != 25 {
		t.Fatalf("investigation query escaped trusted parent scope: status=%d store=%+v", rec.Code, store)
	}
}
