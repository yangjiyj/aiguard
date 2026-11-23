package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeDelegationInvestigator struct {
	tenant, root string
	limit, calls int
	result       *repository.AgentDelegationInvestigation
	err          error
}

func (f *fakeDelegationInvestigator) InvestigateTree(_ context.Context, tenant, root string, limit int) (*repository.AgentDelegationInvestigation, error) {
	f.tenant, f.root, f.limit = tenant, root, limit
	f.calls++
	return f.result, f.err
}

func t22DevInvestigationRequest(target string, user *repository.User) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	ctx := req.Context()
	if user != nil {
		ctx = context.WithValue(ctx, auth.UserKey, user)
		ctx = context.WithValue(ctx, auth.SessionKey, &repository.Session{UserID: user.ID, TenantID: user.TenantID})
	}
	return req.WithContext(ctx)
}

func t22DevInvestigationServe(api *AgentDelegationInvestigationAPI, req *http.Request) *httptest.ResponseRecorder {
	router := chi.NewRouter()
	router.Get("/admin/v1/agent/principals/{id}/delegation-tree", api.Tree)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestAgentDelegationInvestigationUsesAdminTenantAndReturnsTree(t *testing.T) {
	store := &fakeDelegationInvestigator{result: &repository.AgentDelegationInvestigation{
		RootPrincipalID: "00000000-0000-0000-0000-000000000001",
		Delegations:     []repository.AgentDelegationTreeNode{{DelegationID: "d1", Depth: 1, EffectiveStatus: "active"}},
		Calls:           []repository.AgentDelegationInvestigationCall{{Depth: 1, PrincipalChain: []string{"root", "child"}}},
	}}
	api := NewAgentDelegationInvestigationAPI(store)
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a"}
	rec := t22DevInvestigationServe(api, t22DevInvestigationRequest(
		"/admin/v1/agent/principals/00000000-0000-0000-0000-000000000001/delegation-tree?limit=20&tenant_id=tenant-b", user))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if store.tenant != "tenant-a" || store.root != "00000000-0000-0000-0000-000000000001" || store.limit != 20 {
		t.Fatalf("repository scope: tenant=%q root=%q limit=%d", store.tenant, store.root, store.limit)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"root_principal_id", "delegations", "calls", "observed_at"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("response missing %q: %s", key, rec.Body.String())
		}
	}
}

func TestAgentDelegationInvestigationRejectsUnauthenticatedBadLimitAndMapsNotFound(t *testing.T) {
	store := &fakeDelegationInvestigator{}
	api := NewAgentDelegationInvestigationAPI(store)
	if rec := t22DevInvestigationServe(api, t22DevInvestigationRequest("/admin/v1/agent/principals/p1/delegation-tree", nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", rec.Code)
	}
	user := &repository.User{ID: "admin-1", TenantID: "tenant-a"}
	for _, limit := range []string{"0", "501", "x"} {
		if rec := t22DevInvestigationServe(api, t22DevInvestigationRequest("/admin/v1/agent/principals/p1/delegation-tree?limit="+limit, user)); rec.Code != http.StatusBadRequest {
			t.Fatalf("limit=%s status=%d", limit, rec.Code)
		}
	}
	if store.calls != 0 {
		t.Fatalf("repository called %d times for rejected requests", store.calls)
	}
	store.err = repository.ErrAgentDelegationRootNotFound
	if rec := t22DevInvestigationServe(api, t22DevInvestigationRequest("/admin/v1/agent/principals/p1/delegation-tree", user)); rec.Code != http.StatusNotFound {
		t.Fatalf("not found status=%d", rec.Code)
	}
	store.err = repository.ErrAgentAuthorizationInvalid
	if rec := t22DevInvestigationServe(api, t22DevInvestigationRequest("/admin/v1/agent/principals/p1/delegation-tree", user)); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid status=%d", rec.Code)
	}
}
