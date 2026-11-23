package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeAgentOperationRepo struct {
	policy      *repository.AgentOperationPolicy
	event       *repository.AgentOperationEvent
	saved       repository.AgentOperationPolicyMutation
	gotTenantID string
}

func (f *fakeAgentOperationRepo) GetPolicy(_ context.Context, tenantID, _ string, _ string) (*repository.AgentOperationPolicy, error) {
	f.gotTenantID = tenantID
	return f.policy, nil
}
func (f *fakeAgentOperationRepo) SavePolicy(_ context.Context, mutation repository.AgentOperationPolicyMutation) (*repository.AgentOperationPolicy, error) {
	f.saved = mutation
	return f.policy, nil
}
func (f *fakeAgentOperationRepo) GetEvent(context.Context, string, string) (*repository.AgentOperationEvent, error) {
	return f.event, nil
}
func (f *fakeAgentOperationRepo) ListEvents(context.Context, string, repository.AgentOperationEventFilter) ([]repository.AgentOperationEvent, int, error) {
	if f.event == nil {
		return nil, 0, nil
	}
	return []repository.AgentOperationEvent{*f.event}, 1, nil
}
func (f *fakeAgentOperationRepo) ListChannels(context.Context, string, []string) ([]repository.AgentOperationChannel, error) {
	return []repository.AgentOperationChannel{{ID: "channel-a", Type: "webhook", Name: "Ops", Enabled: true}}, nil
}

func (f *fakeAgentOperationRepo) ResolveEffectivePolicy(context.Context, string, repository.AgentOperationEffectivePolicyInput) (*repository.AgentOperationEffectivePolicy, error) {
	return &repository.AgentOperationEffectivePolicy{
		Mode: "audit", Action: "record", ConfigSource: "system_default",
	}, nil
}
func agentOperationRequest(t *testing.T, method, path, body string, user *repository.User) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
	return httptest.NewRecorder(), req
}

type fakeAgentOperationTenantLookup struct {
	tenantIDs map[string]bool
}

func (f *fakeAgentOperationTenantLookup) GetByID(_ context.Context, tenantID string) (*repository.Tenant, error) {
	if !f.tenantIDs[tenantID] || tenantID == repository.SystemTenantID {
		return nil, nil
	}
	return &repository.Tenant{ID: tenantID, Status: "active"}, nil
}

func TestPutAgentOperationProtectionReliesOnPermissionMiddleware(t *testing.T) {
	repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "application", ScopeRef: "app-a", Mode: "strict", Action: "block", CurrentAction: "block", ModeDefaultAction: "block", ConfigSource: "application", Version: 2}}
	deps := &Dependencies{AgentOperationRepo: repo}
	body := `{"scope_type":"application","scope_ref":"app-a","mode":"strict","action":"block","version":1}`
	member := &repository.User{ID: "member", TenantID: "tenant-a", Role: "team_member", Status: "active"}
	rec, req := agentOperationRequest(t, http.MethodPut, "/admin/v1/agent-operation-protection", body, member)
	PutAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("member status=%d body=%s", rec.Code, rec.Body.String())
	}
	if repo.saved.TenantID != "tenant-a" || repo.saved.ActorID != "member" || repo.saved.Source != "admin_api" {
		t.Fatalf("mutation=%+v", repo.saved)
	}
}

func TestAgentOperationResponsesExposeOnlyCustomerProjection(t *testing.T) {
	policy := &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "audit", Action: "record", CurrentAction: "record", ModeDefaultAction: "record", ConfigSource: "tenant", NotifyChannelIDs: []string{"channel-a"}, Version: 1, UpdatedBy: "internal-db-user"}
	event := &repository.AgentOperationEvent{
		PublicEventID: "evt_public", OperationID: "op-1", RequestID: "req-1", TraceID: "trace-1",
		ApplicationID: "app-a", AgentType: "codex", Model: "gpt-5", Protocol: "responses",
		ToolName: "shell_command", ToolCallID: "call-1", TargetSummary: "file_delete:1-target",
		CategoryCode: "destructive_operation", CategoryLabel: "destructive", SubcategoryCode: "file_delete",
		BasisCode: "deterministic_detection", Confidence: 0.99, StatusCode: "blocked", StatusLabel: "blocked",
		CurrentAction: "block", NotificationCode: "delivered", CreatedAt: time.Now(),
	}
	deps := &Dependencies{AgentOperationRepo: &fakeAgentOperationRepo{policy: policy, event: event}}
	user := &repository.User{ID: "auditor", TenantID: "tenant-a", Role: "auditor", Status: "active"}
	rec, req := agentOperationRequest(t, http.MethodGet, "/admin/v1/agent-operation-protection", "", user)
	GetAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"mode_default_action":"record"`) ||
		!strings.Contains(rec.Body.String(), `"id":"channel-a"`) || strings.Contains(rec.Body.String(), `"ID"`) || strings.Contains(rec.Body.String(), "internal-db-user") {
		t.Fatalf("policy response=%d %s", rec.Code, rec.Body.String())
	}

	rec, req = agentOperationRequest(t, http.MethodGet, "/admin/v1/agent-operation-events/evt_public", "", user)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("public_event_id", "evt_public")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	GetAgentOperationEvent(deps).ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "evt_public") || !strings.Contains(body, "execution_intent_not_deletion") {
		t.Fatalf("event response=%d %s", rec.Code, body)
	}
	for _, forbidden := range []string{"internal-db-id", "matched_policy_id", "parameters", "result", "config_json", "raw_decision", "event_type"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, body)
		}
	}
}

func TestListAgentOperationEventsRejectsUnboundedFilters(t *testing.T) {
	deps := &Dependencies{AgentOperationRepo: &fakeAgentOperationRepo{}}
	user := &repository.User{ID: "auditor", TenantID: "tenant-a", Role: "auditor", Status: "active"}
	invalid := []string{
		"/admin/v1/agent-operation-events?limit=0",
		"/admin/v1/agent-operation-events?limit=101",
		"/admin/v1/agent-operation-events?offset=10001",
		"/admin/v1/agent-operation-events?action=allow",
		"/admin/v1/agent-operation-events?from=2025-01-01T00:00:00Z&to=2026-01-01T00:00:00Z",
	}
	for _, path := range invalid {
		rec, req := agentOperationRequest(t, http.MethodGet, path, "", user)
		ListAgentOperationEvents(deps).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestGetAgentOperationProtectionPlatformAdminDefaultsToGlobal(t *testing.T) {
	repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{
		ScopeType: "agent", ScopeRef: "*", Mode: "light", Action: "alert_allow",
		CurrentAction: "alert_allow", ModeDefaultAction: "alert_allow", Version: 1,
	}}
	deps := &Dependencies{AgentOperationRepo: repo}
	user := &repository.User{ID: "platform", TenantID: "tenant-a", Role: "platform_admin", Status: "active"}
	rec, req := agentOperationRequest(t, http.MethodGet, "/admin/v1/agent-operation-protection", "", user)
	GetAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || repo.gotTenantID != "" {
		t.Fatalf("status=%d target=%q body=%s", rec.Code, repo.gotTenantID, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "\"tenant_scope\":\"all\"") || strings.Contains(rec.Body.String(), "\"channels\":[{\"id\":\"channel-a\"") {
		t.Fatalf("missing global tenant scope: %s", rec.Body.String())
	}
}

func TestGetAgentOperationProtectionResolvesExplicitTenant(t *testing.T) {
	repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "strict", Action: "block", Version: 2}}
	lookup := &fakeAgentOperationTenantLookup{tenantIDs: map[string]bool{"tenant-b": true}}
	deps := &Dependencies{AgentOperationRepo: repo, TenantLookup: lookup}
	user := &repository.User{ID: "platform", TenantID: "tenant-a", Role: "platform_admin", Status: "active"}
	rec, req := agentOperationRequest(t, http.MethodGet, "/admin/v1/agent-operation-protection?tenant_scope=tenant&tenant_id=tenant-b", "", user)
	GetAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || repo.gotTenantID != "tenant-b" || !strings.Contains(rec.Body.String(), "\"tenant_scope\":\"tenant\"") || !strings.Contains(rec.Body.String(), "\"tenant_id\":\"tenant-b\"") {
		t.Fatalf("status=%d target=%q body=%s", rec.Code, repo.gotTenantID, rec.Body.String())
	}
}

func TestGetAgentOperationProtectionRejectsNonPlatformGlobalScope(t *testing.T) {
	deps := &Dependencies{AgentOperationRepo: &fakeAgentOperationRepo{}}
	user := &repository.User{ID: "member", TenantID: "tenant-a", Role: "tenant_admin", Status: "active"}
	rec, req := agentOperationRequest(t, http.MethodGet, "/admin/v1/agent-operation-protection?tenant_scope=all", "", user)
	GetAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPutAgentOperationProtectionEnforcesTenantTargetRole(t *testing.T) {
	body := `{"tenant_scope":"all","scope_type":"agent","scope_ref":"*","mode":"light","action":"alert_allow","version":1}`
	for _, role := range []string{"tenant_admin", "auditor"} {
		t.Run(role, func(t *testing.T) {
			repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "agent", ScopeRef: "*", Version: 1}}
			deps := &Dependencies{AgentOperationRepo: repo}
			user := &repository.User{ID: "member", TenantID: "tenant-a", Role: role, Status: "active"}
			rec, req := agentOperationRequest(t, http.MethodPut, "/admin/v1/agent-operation-protection", body, user)
			PutAgentOperationProtection(deps).ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPutAgentOperationProtectionPlatformAdminCanTargetTenant(t *testing.T) {
	repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "strict", Action: "block", Version: 2}}
	deps := &Dependencies{AgentOperationRepo: repo, TenantLookup: &fakeAgentOperationTenantLookup{tenantIDs: map[string]bool{"tenant-b": true}}}
	user := &repository.User{ID: "platform", TenantID: "tenant-a", Role: "platform_admin", Status: "active"}
	body := `{"tenant_scope":"tenant","tenant_id":"tenant-b","scope_type":"tenant","mode":"strict","action":"block","version":1}`
	rec, req := agentOperationRequest(t, http.MethodPut, "/admin/v1/agent-operation-protection", body, user)
	PutAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || repo.saved.TenantID != "tenant-b" {
		t.Fatalf("status=%d mutation=%+v body=%s", rec.Code, repo.saved, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"tenant_scope":"tenant"`) {
		t.Fatalf("missing tenant scope: %s", rec.Body.String())
	}
}

func TestPutAgentOperationProtectionRejectsMissingOrSystemTenant(t *testing.T) {
	for _, tenantID := range []string{"tenant-missing", repository.SystemTenantID} {
		t.Run(tenantID, func(t *testing.T) {
			repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "tenant", Version: 1}}
			deps := &Dependencies{AgentOperationRepo: repo, TenantLookup: &fakeAgentOperationTenantLookup{tenantIDs: map[string]bool{"tenant-b": true}}}
			user := &repository.User{ID: "platform", TenantID: "tenant-a", Role: "platform_admin", Status: "active"}
			body := "{\"tenant_scope\":\"tenant\",\"tenant_id\":\"" + tenantID + "\",\"scope_type\":\"tenant\",\"mode\":\"strict\",\"action\":\"block\",\"version\":1}"
			rec, req := agentOperationRequest(t, http.MethodPut, "/admin/v1/agent-operation-protection", body, user)
			PutAgentOperationProtection(deps).ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPutAgentOperationProtectionRejectsNonPlatformCrossTenantTarget(t *testing.T) {
	repo := &fakeAgentOperationRepo{policy: &repository.AgentOperationPolicy{ScopeType: "tenant", Mode: "strict", Action: "block", Version: 2}}
	deps := &Dependencies{AgentOperationRepo: repo}
	user := &repository.User{ID: "member", TenantID: "tenant-a", Role: "tenant_admin", Status: "active"}
	body := `{"tenant_scope":"tenant","tenant_id":"tenant-b","scope_type":"tenant","mode":"strict","action":"block","version":1}`
	rec, req := agentOperationRequest(t, http.MethodPut, "/admin/v1/agent-operation-protection", body, user)
	PutAgentOperationProtection(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
