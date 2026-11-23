package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeAgentAuthorizationRepo struct {
	registerTenant string
	registerInput  repository.AgentAuthorizationPrincipalCreate
	registerCalls  int
	principal      repository.TrustedAgentPrincipal
	request        repository.AgentAuthorizationRequest
	authorizeCalls int
}

func (f *fakeAgentAuthorizationRepo) RegisterPrincipal(_ context.Context, tenant string, input repository.AgentAuthorizationPrincipalCreate) (*repository.AgentAuthorizationPrincipalCreated, error) {
	f.registerTenant, f.registerInput = tenant, input
	f.registerCalls++
	return &repository.AgentAuthorizationPrincipalCreated{
		Principal:  repository.AgentAuthorizationPrincipal{ID: "server-generated", TenantID: tenant, Name: input.Name, Status: "active", ExpiresAt: input.ExpiresAt},
		Credential: "only-returned-on-create",
		Grants:     input.Grants,
	}, nil
}

func (f *fakeAgentAuthorizationRepo) ListPrincipals(context.Context, string) ([]repository.AgentAuthorizationPrincipal, error) {
	return nil, nil
}
func (f *fakeAgentAuthorizationRepo) RevokePrincipal(context.Context, string, string) (bool, error) {
	return true, nil
}
func (f *fakeAgentAuthorizationRepo) RotatePrincipalCredential(context.Context, string, string, string) (string, bool, error) {
	return "rotated-once", true, nil
}
func (f *fakeAgentAuthorizationRepo) ResolvePrincipalCredential(context.Context, string) (*repository.TrustedAgentPrincipal, error) {
	return &f.principal, nil
}
func (f *fakeAgentAuthorizationRepo) Authorize(_ context.Context, principal repository.TrustedAgentPrincipal, request repository.AgentAuthorizationRequest) (*repository.AgentAuthorizationDecision, error) {
	f.principal = principal
	f.request = request
	f.authorizeCalls++
	return &repository.AgentAuthorizationDecision{Allowed: true, Reason: "allowed", PrincipalID: principal.ID, Action: request.Action, ResourceType: request.ResourceType, ResourceID: request.ResourceID, IdempotencyKey: request.IdempotencyKey}, nil
}

func TestAgentAuthorizationBearerCredentialMustBeHex256BitToken(t *testing.T) {
	valid := strings.Repeat("a", 64)
	hash, ok := agentAuthorizationBearerHash("Bearer " + valid)
	if !ok || hash != repository.HashAgentToken(valid) {
		t.Fatal("valid bearer token did not produce the credential hash")
	}
	for _, header := range []string{"", "Basic " + valid, "Bearer short", "Bearer " + strings.Repeat("z", 64), "Bearer " + valid + " extra"} {
		if _, ok := agentAuthorizationBearerHash(header); ok {
			t.Errorf("accepted invalid authorization header %q", header)
		}
	}
}

func TestAuthorizeRejectsCallerSuppliedIdentityAndUsesTrustedContext(t *testing.T) {
	fake := &fakeAgentAuthorizationRepo{}
	api := NewAgentAuthorizationAPI(fake, nil)
	principal := repository.TrustedAgentPrincipal{ID: "server-principal", TenantID: "tenant-a", CredentialHash: strings.Repeat("a", 64)}
	base := httptest.NewRequest(http.MethodPost, "/admin/v1/agent/authorize", nil)
	base = base.WithContext(context.WithValue(base.Context(), trustedAgentAuthorizationContextKey{}, &principal))

	forged := base.Clone(base.Context())
	forged.Body = http.NoBody
	forged = httptest.NewRequest(http.MethodPost, "/admin/v1/agent/authorize", strings.NewReader(`{"action":"records.read","resource_type":"record","resource_id":"r1","idempotency_key":"request-000000001","agent_id":"attacker"}`))
	forged = forged.WithContext(base.Context())
	rec := httptest.NewRecorder()
	api.Authorize(rec, forged)
	if rec.Code != http.StatusBadRequest || fake.authorizeCalls != 0 {
		t.Fatalf("forged caller identity was accepted: status=%d calls=%d body=%s", rec.Code, fake.authorizeCalls, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/agent/authorize", strings.NewReader(`{"action":"records.read","resource_type":"record","resource_id":"r1","context":{"environment":"staging"},"idempotency_key":"request-000000001"}`))
	req = req.WithContext(base.Context())
	rec = httptest.NewRecorder()
	api.Authorize(rec, req)
	if rec.Code != http.StatusOK || fake.authorizeCalls != 1 {
		t.Fatalf("valid authorize request failed: status=%d calls=%d body=%s", rec.Code, fake.authorizeCalls, rec.Body.String())
	}
	if fake.principal.ID != "server-principal" || fake.principal.TenantID != "tenant-a" || fake.request.ResourceID != "r1" {
		t.Fatalf("authorization did not use trusted context: principal=%+v request=%+v", fake.principal, fake.request)
	}
	var decision repository.AgentAuthorizationDecision
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil || decision.PrincipalID != "server-principal" {
		t.Fatalf("unexpected decision response: %+v err=%v", decision, err)
	}
}

func TestRegisterPrincipalDerivesTenantAndActorFromSession(t *testing.T) {
	fake := &fakeAgentAuthorizationRepo{}
	api := NewAgentAuthorizationAPI(fake, nil)
	user := &repository.User{ID: "admin-a", TenantID: "tenant-a", Status: "active"}
	session := &repository.Session{ID: "session-a", UserID: user.ID, TenantID: user.TenantID}
	ctx := context.WithValue(context.Background(), auth.UserKey, user)
	ctx = context.WithValue(ctx, auth.SessionKey, session)

	forged := httptest.NewRequest(http.MethodPost, "/admin/v1/agent/principals", strings.NewReader(`{"name":"worker","tenant_id":"tenant-b","agent_id":"victim","expires_at":"2026-10-01T00:00:00Z","grants":[]}`))
	forged = forged.WithContext(ctx)
	rec := httptest.NewRecorder()
	api.RegisterPrincipal(rec, forged)
	if rec.Code != http.StatusBadRequest || fake.registerCalls != 0 {
		t.Fatalf("caller tenant or agent id accepted: status=%d calls=%d", rec.Code, fake.registerCalls)
	}

	body := `{"name":"worker","expires_at":"2026-10-01T00:00:00Z","grants":[]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/agent/principals?tenant_id=tenant-b", strings.NewReader(body))
	req = req.WithContext(ctx)
	rec = httptest.NewRecorder()
	api.RegisterPrincipal(rec, req)
	if rec.Code != http.StatusCreated || fake.registerCalls != 1 {
		t.Fatalf("valid registration failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if fake.registerTenant != "tenant-a" || fake.registerInput.CreatedBy != "admin-a" {
		t.Fatalf("registration tenant/actor was not server-derived: tenant=%s actor=%s", fake.registerTenant, fake.registerInput.CreatedBy)
	}
	if rec.Header().Get("Cache-Control") == "" {
		t.Fatal("one-time credential response must be non-cacheable")
	}
	if fake.registerInput.ExpiresAt.Before(time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("unexpected expiry decode")
	}
}

func TestAgentAuthorizationBodyLimitRejectsOversizedJSONAndTrailingWhitespace(t *testing.T) {
	registerJSON := `{"name":"worker","expires_at":"2026-10-01T00:00:00Z","grants":[]}`
	authorizeJSON := `{"action":"records.read","resource_type":"record","resource_id":"r1","idempotency_key":"request-000000001"}`
	oversizedAuthorizationJSON := `{"action":"records.read","resource_type":"record","resource_id":"` + strings.Repeat("x", agentAuthorizationBodyLimit) + `","idempotency_key":"request-000000001"}`

	register := func(body string) (int, int) {
		fake := &fakeAgentAuthorizationRepo{}
		api := NewAgentAuthorizationAPI(fake, nil)
		user := &repository.User{ID: "admin-a", TenantID: "tenant-a", Status: "active"}
		session := &repository.Session{ID: "session-a", UserID: user.ID, TenantID: user.TenantID}
		ctx := context.WithValue(context.Background(), auth.UserKey, user)
		ctx = context.WithValue(ctx, auth.SessionKey, session)
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/agent/principals", strings.NewReader(body)).WithContext(ctx)
		rec := httptest.NewRecorder()
		api.RegisterPrincipal(rec, req)
		return rec.Code, fake.registerCalls
	}

	authorize := func(body string) (int, int) {
		fake := &fakeAgentAuthorizationRepo{}
		api := NewAgentAuthorizationAPI(fake, nil)
		principal := repository.TrustedAgentPrincipal{ID: "server-principal", TenantID: "tenant-a", CredentialHash: strings.Repeat("a", 64)}
		ctx := context.WithValue(context.Background(), trustedAgentAuthorizationContextKey{}, &principal)
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/agent/authorize", strings.NewReader(body)).WithContext(ctx)
		rec := httptest.NewRecorder()
		api.Authorize(rec, req)
		return rec.Code, fake.authorizeCalls
	}

	cases := []struct {
		name   string
		body   string
		invoke func(string) (int, int)
	}{
		{name: "principal registration with oversized trailing whitespace", body: registerJSON + strings.Repeat(" ", agentAuthorizationBodyLimit+1), invoke: register},
		{name: "authorization with oversized trailing whitespace", body: authorizeJSON + strings.Repeat(" ", agentAuthorizationBodyLimit+1), invoke: authorize},
		{name: "oversized authorization JSON payload", body: oversizedAuthorizationJSON, invoke: authorize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, calls := tc.invoke(tc.body)
			if status != http.StatusBadRequest || calls != 0 {
				t.Fatalf("oversized body was not rejected before repository access: status=%d calls=%d", status, calls)
			}
		})
	}
}
