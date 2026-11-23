package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func withAgentGuardTenantUser(r *http.Request, tenantID string) *http.Request {
	user := &repository.User{ID: "user-" + tenantID, TenantID: tenantID, Role: "platform_admin", Status: "active"}
	return r.WithContext(context.WithValue(r.Context(), auth.UserKey, user))
}

func TestCreateAgentGuardPolicyIgnoresClientSuppliedID(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: &agentGuardAuditSystemRepo{}}
	body := []byte(`{"id":"agp_client_controlled","name":"租户策略","scope_type":"tenant","mode":"audit","default_action":"audit","fail_policy":"fail_closed","enabled":true}`)
	req := withAgentGuardTenantUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/policies", bytes.NewReader(body)), "tenant-a")
	rr := httptest.NewRecorder()

	CreateAgentGuardPolicy(deps)(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rr.Code, rr.Body.String())
	}
	if _, exists := repo.policies["agp_client_controlled"]; exists {
		t.Fatal("create must ignore client-supplied policy id")
	}
	if len(repo.policies) != 1 {
		t.Fatalf("created policies = %d, want 1", len(repo.policies))
	}
	for id := range repo.policies {
		if id == "" || id == "agp_client_controlled" {
			t.Fatalf("server-generated policy id = %q", id)
		}
	}
}

func TestCreateAgentGuardPolicyPreservesDefaults(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: &agentGuardAuditSystemRepo{}}
	body := []byte("{\"name\":\"默认策略\",\"scope_type\":\"tenant\",\"enabled\":true}")
	req := withAgentGuardTenantUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/policies", bytes.NewReader(body)), "tenant-a")
	rr := httptest.NewRecorder()

	CreateAgentGuardPolicy(deps)(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rr.Code, rr.Body.String())
	}
	for _, policy := range repo.policies {
		if policy.Mode != repository.AgentGuardModeAudit || policy.DefaultAction != repository.AgentGuardActionAudit || policy.FailPolicy != repository.AgentGuardFailClosed {
			t.Fatalf("policy defaults = mode:%q action:%q fail:%q", policy.Mode, policy.DefaultAction, policy.FailPolicy)
		}
	}
}

func TestProjectPolicyRequiresScopeRef(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: &agentGuardAuditSystemRepo{}}
	body := []byte(`{"name":"项目策略","scope_type":"project","scope_ref":"","mode":"audit","default_action":"audit","fail_policy":"fail_closed","enabled":true}`)
	req := withAgentGuardTenantUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/policies", bytes.NewReader(body)), "tenant-a")
	rr := httptest.NewRecorder()

	CreateAgentGuardPolicy(deps)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rr.Code, rr.Body.String())
	}
	if len(repo.policies) != 0 {
		t.Fatalf("invalid scoped policy persisted: %#v", repo.policies)
	}
}

func TestAgentGuardPolicyTenantUpdateCannotOverwriteAnotherTenant(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	original := &repository.AgentGuardPolicy{
		ID: "agp_tenant_a", TenantID: "tenant-a", Name: "租户 A 策略",
		ScopeType: "tenant", Mode: "audit", DefaultAction: "audit",
		FailPolicy: "fail_closed", Enabled: true,
	}
	repo.policies[original.ID] = original
	version, err := repository.NewAgentGuardPolicyVersion(original, "user-a")
	if err != nil {
		t.Fatalf("seed version: %v", err)
	}
	repo.versions[original.ID] = []*repository.AgentGuardPolicyVersion{version}
	beforeVersionCount := len(repo.versions[original.ID])

	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: &agentGuardAuditSystemRepo{}}
	body := []byte(`{"name":"租户 B 覆盖","scope_type":"tenant","mode":"strict","default_action":"block","fail_policy":"fail_closed","enabled":true}`)
	req := withAgentGuardTenantUser(httptest.NewRequest(http.MethodPut, "/admin/v1/agentguard/policies/agp_tenant_a", bytes.NewReader(body)), "tenant-b")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", original.ID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	UpdateAgentGuardPolicy(deps)(rr, req)

	if rr.Code != http.StatusNotFound && rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 404/403, body=%s", rr.Code, rr.Body.String())
	}
	if got := repo.policies[original.ID]; got.Name != "租户 A 策略" || got.TenantID != "tenant-a" || got.Mode != "audit" {
		t.Fatalf("tenant A policy changed: %#v", got)
	}
	if got := len(repo.versions[original.ID]); got != beforeVersionCount {
		t.Fatalf("tenant A version count = %d, want %d", got, beforeVersionCount)
	}
}

func TestConnectorAgentGuardPolicyCannotOverwriteAnotherTenant(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	original := &repository.AgentGuardPolicy{
		ID: "agp_tenant_a", TenantID: "tenant-a", Name: "租户 A 策略",
		ScopeType: "tenant", Mode: "audit", DefaultAction: "audit",
		FailPolicy: "fail_closed", Enabled: true,
	}
	repo.policies[original.ID] = original
	version, err := repository.NewAgentGuardPolicyVersion(original, "user-a")
	if err != nil {
		t.Fatalf("seed version: %v", err)
	}
	repo.versions[original.ID] = []*repository.AgentGuardPolicyVersion{version}
	beforeVersionCount := len(repo.versions[original.ID])

	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: &agentGuardAuditSystemRepo{}}
	body := []byte(`{"name":"租户 B 覆盖","scope_type":"tenant","mode":"strict","default_action":"block","fail_policy":"fail_closed","enabled":true}`)
	req := withAgentGuardTenantUser(httptest.NewRequest(http.MethodPut, "/admin/v1/agentguard/policies/agp_tenant_a", bytes.NewReader(body)), "tenant-b")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", original.ID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	user := auth.GetUser(req.Context())
	user.Role = "platform_connector"
	UpdateAgentGuardPolicy(deps)(rr, req)

	if rr.Code != http.StatusNotFound && rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 404/403, body=%s", rr.Code, rr.Body.String())
	}
	if got := repo.policies[original.ID]; got.Name != "租户 A 策略" || got.TenantID != "tenant-a" || got.Mode != "audit" {
		t.Fatalf("tenant A policy changed: %#v", got)
	}
	if got := len(repo.versions[original.ID]); got != beforeVersionCount {
		t.Fatalf("tenant A version count = %d, want %d", got, beforeVersionCount)
	}
}
