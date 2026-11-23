package handler

import (
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

type fakeAgentAuthorizationApprovalRepo struct {
	decision        *repository.AgentAuthorizationDecision
	authorizeCalls  int
	principal       repository.TrustedAgentPrincipal
	authRequest     repository.AgentAuthorizationRequest
	createdInput    repository.AgentAuthorizationApprovalInput
	createCalls     int
	claimInput      repository.AgentAuthorizationApprovalClaimInput
	claimCalls      int
	claim           *repository.AgentAuthorizationApprovalClaim
	exceptionInput  repository.AgentAuthorizationApprovalExceptionInput
	exceptionTenant string
	exceptionActor  string
	exceptionCalls  int
	resolveTenant   string
	resolveActor    string
	resolveStatus   string
	resolveCalls    int
}

func (f *fakeAgentAuthorizationApprovalRepo) Authorize(_ context.Context, p repository.TrustedAgentPrincipal, req repository.AgentAuthorizationRequest) (*repository.AgentAuthorizationDecision, error) {
	f.authorizeCalls++
	f.principal, f.authRequest = p, req
	if f.decision != nil {
		return f.decision, nil
	}
	return &repository.AgentAuthorizationDecision{Allowed: true, GrantID: "grant-server", PrincipalID: p.ID}, nil
}
func (f *fakeAgentAuthorizationApprovalRepo) CreateAgentAuthorizationApproval(_ context.Context, p repository.TrustedAgentPrincipal, grant string, input repository.AgentAuthorizationApprovalInput) (*repository.AgentAuthorizationApproval, bool, error) {
	f.createCalls++
	f.createdInput = input
	return &repository.AgentAuthorizationApproval{ID: "agap_12345678", PrincipalID: p.ID, GrantID: grant, Status: "pending", ExpiresAt: time.Now().Add(time.Minute)}, true, nil
}
func (f *fakeAgentAuthorizationApprovalRepo) ClaimAgentAuthorizationApproval(_ context.Context, p repository.TrustedAgentPrincipal, grant, id string, input repository.AgentAuthorizationApprovalClaimInput) (*repository.AgentAuthorizationApprovalClaim, error) {
	f.claimCalls++
	f.claimInput = input
	return f.claim, nil
}
func (f *fakeAgentAuthorizationApprovalRepo) ListAgentAuthorizationApprovals(context.Context, string, string, int) ([]*repository.AgentAuthorizationApproval, error) {
	return nil, nil
}
func (f *fakeAgentAuthorizationApprovalRepo) ResolveAgentAuthorizationApproval(_ context.Context, tenant, id, status, actor, note string) (*repository.AgentAuthorizationApproval, bool, error) {
	f.resolveCalls++
	f.resolveTenant, f.resolveActor, f.resolveStatus = tenant, actor, status
	return &repository.AgentAuthorizationApproval{ID: id, Status: status}, true, nil
}
func (f *fakeAgentAuthorizationApprovalRepo) RevokeAgentAuthorizationApproval(context.Context, string, string, string, string) (*repository.AgentAuthorizationApproval, bool, error) {
	return &repository.AgentAuthorizationApproval{ID: "agap_12345678", Status: "revoked"}, true, nil
}
func (f *fakeAgentAuthorizationApprovalRepo) CreateAgentAuthorizationApprovalException(_ context.Context, tenant, actor string, input repository.AgentAuthorizationApprovalExceptionInput) (*repository.AgentAuthorizationApprovalException, bool, error) {
	f.exceptionCalls++
	f.exceptionTenant, f.exceptionActor, f.exceptionInput = tenant, actor, input
	return &repository.AgentAuthorizationApprovalException{ID: "exception-id", PrincipalID: input.PrincipalID, GrantID: input.GrantID, CreatedBy: actor, Active: true}, true, nil
}
func (f *fakeAgentAuthorizationApprovalRepo) ListAgentAuthorizationApprovalExceptions(context.Context, string, int) ([]*repository.AgentAuthorizationApprovalException, error) {
	return nil, nil
}
func (f *fakeAgentAuthorizationApprovalRepo) RevokeAgentAuthorizationApprovalException(context.Context, string, string, string) (*repository.AgentAuthorizationApprovalException, bool, error) {
	return &repository.AgentAuthorizationApprovalException{ID: "exception-id"}, true, nil
}

func trustedT15AgentRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/agent/approval-requests", strings.NewReader(body))
	principal := &repository.TrustedAgentPrincipal{ID: "principal-server", TenantID: "tenant-server", CredentialHash: "credential-hash"}
	return req.WithContext(context.WithValue(req.Context(), trustedAgentAuthorizationContextKey{}, principal))
}

func withT15AdminUser(req *http.Request, role string) *http.Request {
	user := &repository.User{ID: "admin-actor", TenantID: "tenant-admin", Role: role, Status: "active"}
	session := &repository.Session{ID: "session-id", UserID: user.ID, TenantID: user.TenantID}
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	ctx = context.WithValue(ctx, auth.SessionKey, session)
	return req.WithContext(ctx)
}

func TestT15RequestRequiresTrustedBearerPrincipal(t *testing.T) {
	fake := &fakeAgentAuthorizationApprovalRepo{}
	api := NewAgentAuthorizationApprovalAPI(fake, &Dependencies{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/agent/approval-requests", strings.NewReader("{}"))
	api.RequestApproval(rr, req)
	if rr.Code != http.StatusUnauthorized || fake.authorizeCalls != 0 || fake.createCalls != 0 {
		t.Fatalf("missing principal was accepted: status=%d calls=%d/%d", rr.Code, fake.authorizeCalls, fake.createCalls)
	}
	if rr.Header().Get("Cache-Control") != "no-store,max-age=0" {
		t.Fatalf("approval response is cacheable: %q", rr.Header().Get("Cache-Control"))
	}
}

func TestT15RequestReauthorizesBeforeCreatingExactPendingApproval(t *testing.T) {
	const args = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const reqKey = "t15:req:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	body := `{"action":"tool_execute","resource_type":"tool","resource_id":"ticket.update","arguments_sha256":"` + args + `","authorization_idempotency_key":"t13-request-key-000001","approval_idempotency_key":"` + reqKey + `","run_id":"run-123","instance_id":"instance-456","tool_call_id":"call-789"}`
	fake := &fakeAgentAuthorizationApprovalRepo{decision: &repository.AgentAuthorizationDecision{Allowed: true, GrantID: "server-grant", PrincipalID: "principal-server"}}
	api := NewAgentAuthorizationApprovalAPI(fake, &Dependencies{})
	rr := httptest.NewRecorder()
	api.RequestApproval(rr, trustedT15AgentRequest(body))
	if rr.Code != http.StatusCreated || fake.authorizeCalls != 1 || fake.createCalls != 1 {
		t.Fatalf("status=%d authorize=%d create=%d body=%s", rr.Code, fake.authorizeCalls, fake.createCalls, rr.Body.String())
	}
	if fake.principal.ID != "principal-server" || fake.authRequest.ResourceID != "ticket.update" ||
		fake.authRequest.Context["run_id"] != "run-123" || fake.authRequest.Context["instance_id"] != "instance-456" ||
		fake.authRequest.Context["tool_call_id"] != "call-789" ||
		fake.createdInput.ArgumentsSHA256 != args || fake.createdInput.ApprovalIdempotencyKey != reqKey {
		t.Fatalf("request did not preserve trusted identity and exact binding: %+v %+v %+v", fake.principal, fake.authRequest, fake.createdInput)
	}
	if strings.Contains(rr.Body.String(), "credential") || strings.Contains(rr.Body.String(), "authorization_idempotency_key") {
		t.Fatalf("response leaked credentials or request keys: %s", rr.Body.String())
	}
}

func TestT15RequestDenialAndClientIdentityAreFailClosed(t *testing.T) {
	const args = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	valid := `{"action":"tool_execute","resource_type":"tool","resource_id":"ticket.update","arguments_sha256":"` + args + `","authorization_idempotency_key":"t13-request-key-000001","approval_idempotency_key":"t15:req:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`
	fake := &fakeAgentAuthorizationApprovalRepo{decision: &repository.AgentAuthorizationDecision{Allowed: false, Reason: "no_matching_grant"}}
	api := NewAgentAuthorizationApprovalAPI(fake, &Dependencies{})
	rr := httptest.NewRecorder()
	api.RequestApproval(rr, trustedT15AgentRequest(valid))
	if rr.Code != http.StatusForbidden || fake.createCalls != 0 {
		t.Fatalf("T13 denial did not block approval creation: status=%d creates=%d", rr.Code, fake.createCalls)
	}
	forged := strings.TrimSuffix(valid, "}") + `,"principal_id":"attacker"}`
	fake = &fakeAgentAuthorizationApprovalRepo{}
	api = NewAgentAuthorizationApprovalAPI(fake, &Dependencies{})
	rr = httptest.NewRecorder()
	api.RequestApproval(rr, trustedT15AgentRequest(forged))
	if rr.Code != http.StatusBadRequest || fake.authorizeCalls != 0 || fake.createCalls != 0 {
		t.Fatalf("client identity field was accepted: status=%d calls=%d/%d", rr.Code, fake.authorizeCalls, fake.createCalls)
	}
}

func TestT15ClaimRequiresFreshT13AllowAndReturnsOneUseDecision(t *testing.T) {
	const args = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	body := `{"approval_id":"agap_12345678","action":"tool_execute","resource_type":"tool","resource_id":"ticket.update","arguments_sha256":"` + args + `","authorization_idempotency_key":"t13-request-key-000001","claim_idempotency_key":"t15:claim:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`
	fake := &fakeAgentAuthorizationApprovalRepo{
		decision: &repository.AgentAuthorizationDecision{Allowed: true, GrantID: "server-grant", PrincipalID: "principal-server"},
		claim:    &repository.AgentAuthorizationApprovalClaim{ApprovalID: "agap_12345678", Status: "claimed", Allowed: true, Reason: "approved_once", ClaimID: "agcl_stable"},
	}
	api := NewAgentAuthorizationApprovalAPI(fake, &Dependencies{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/agent/approval-claims", strings.NewReader(body))
	principal := &repository.TrustedAgentPrincipal{ID: "principal-server", TenantID: "tenant-server"}
	req = req.WithContext(context.WithValue(req.Context(), trustedAgentAuthorizationContextKey{}, principal))
	api.ClaimApproval(rr, req)
	if rr.Code != http.StatusOK || fake.authorizeCalls != 1 || fake.claimCalls != 1 ||
		fake.claimInput.ClaimIdempotencyKey != "t15:claim:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" {
		t.Fatalf("claim flow status=%d auth=%d claim=%d body=%s", rr.Code, fake.authorizeCalls, fake.claimCalls, rr.Body.String())
	}
	var got repository.AgentAuthorizationApprovalClaim
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil || !got.Allowed || got.ClaimID != "agcl_stable" {
		t.Fatalf("claim response=%+v err=%v", got, err)
	}
	fake.claim = &repository.AgentAuthorizationApprovalClaim{
		ApprovalID: "agap_12345678", Status: "claimed", Allowed: false,
		Reason: "approval_already_claimed", ClaimID: "agcl_stable",
	}
	req = httptest.NewRequest(http.MethodPost, "/admin/v1/agent/approval-claims", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), trustedAgentAuthorizationContextKey{}, principal))
	rr = httptest.NewRecorder()
	api.ClaimApproval(rr, req)
	var retry repository.AgentAuthorizationApprovalClaim
	if rr.Code != http.StatusForbidden || json.Unmarshal(rr.Body.Bytes(), &retry) != nil ||
		retry.Allowed || retry.ClaimID != "agcl_stable" {
		t.Fatalf("claim retry was not denied with stable id: status=%d response=%+v body=%s", rr.Code, retry, rr.Body.String())
	}
	fake.decision = &repository.AgentAuthorizationDecision{Allowed: false}
	fake.claimCalls = 0
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/v1/agent/approval-claims", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), trustedAgentAuthorizationContextKey{}, principal))
	api.ClaimApproval(rr, req)
	if rr.Code != http.StatusForbidden || fake.claimCalls != 0 {
		t.Fatalf("T13 denial did not block claim: status=%d claim calls=%d", rr.Code, fake.claimCalls)
	}
}

func TestT15AdminExceptionAndResolutionUseAuthenticatedTenantActor(t *testing.T) {
	const args = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fake := &fakeAgentAuthorizationApprovalRepo{}
	api := NewAgentAuthorizationApprovalAPI(fake, &Dependencies{})
	body := `{"principal_id":"02ac6a21-4090-4e45-a6f1-7057bd9a0440","grant_id":"e1bfc491-2d53-417b-bb09-86c9a3c9e82a","action":"tool_execute","resource_type":"tool","resource_id":"ticket.update","arguments_sha256":"` + args + `","reason":"bounded maintenance","ttl_seconds":60,"idempotency_key":"t15:exception:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`
	req := withT15AdminUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agent/approval-exceptions", strings.NewReader(body)), "tenant_admin")
	rr := httptest.NewRecorder()
	api.CreateException(rr, req)
	if rr.Code != http.StatusCreated || fake.exceptionCalls != 1 ||
		fake.exceptionTenant != "tenant-admin" || fake.exceptionActor != "admin-actor" {
		t.Fatalf("exception create status=%d tenant=%s actor=%s body=%s", rr.Code, fake.exceptionTenant, fake.exceptionActor, rr.Body.String())
	}
	fake.exceptionCalls = 0
	req = withT15AdminUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agent/approval-exceptions", strings.NewReader(body)), "team_owner")
	rr = httptest.NewRecorder()
	api.CreateException(rr, req)
	if rr.Code != http.StatusForbidden || fake.exceptionCalls != 0 {
		t.Fatalf("non-admin exception creator was accepted: status=%d calls=%d", rr.Code, fake.exceptionCalls)
	}
	resolveBody := `{"status":"approved","note":"reviewed"}`
	req = withT15AdminUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agent/approvals/agap_12345678/resolve", strings.NewReader(resolveBody)), "tenant_admin")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "agap_12345678")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr = httptest.NewRecorder()
	api.ResolveApproval(rr, req)
	if rr.Code != http.StatusOK || fake.resolveCalls != 1 || fake.resolveTenant != "tenant-admin" ||
		fake.resolveActor != "admin-actor" || fake.resolveStatus != "approved" {
		t.Fatalf("resolution ignored authenticated actor/tenant: status=%d fake=%+v body=%s", rr.Code, fake, rr.Body.String())
	}
}

func TestT15ClaimPreservesExactT13ContextAndRejectsPartialContext(t *testing.T) {
	const args = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const claimKey = "t15:claim:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	body := `{"approval_id":"agap_12345678","action":"tool_execute","resource_type":"tool","resource_id":"ticket.update","arguments_sha256":"` + args + `","authorization_idempotency_key":"t13-request-key-000001","claim_idempotency_key":"` + claimKey + `","run_id":"run-123","instance_id":"instance-456","tool_call_id":"call-789"}`
	fake := &fakeAgentAuthorizationApprovalRepo{decision: &repository.AgentAuthorizationDecision{Allowed: true, GrantID: "server-grant"}, claim: &repository.AgentAuthorizationApprovalClaim{ApprovalID: "agap_12345678", Status: "claimed", Allowed: true, ClaimID: "claim-123"}}
	api := NewAgentAuthorizationApprovalAPI(fake, &Dependencies{})
	rr := httptest.NewRecorder()
	api.ClaimApproval(rr, trustedT15AgentRequest(body))
	if rr.Code != http.StatusOK || fake.authorizeCalls != 1 || fake.claimCalls != 1 ||
		fake.authRequest.Context["run_id"] != "run-123" || fake.authRequest.Context["instance_id"] != "instance-456" ||
		fake.authRequest.Context["tool_call_id"] != "call-789" {
		t.Fatalf("claim dropped or changed T13 context: status=%d auth=%+v calls=%d/%d body=%s", rr.Code, fake.authRequest, fake.authorizeCalls, fake.claimCalls, rr.Body.String())
	}

	partial := `{"approval_id":"agap_12345678","action":"tool_execute","resource_type":"tool","resource_id":"ticket.update","arguments_sha256":"` + args + `","authorization_idempotency_key":"t13-request-key-000001","claim_idempotency_key":"` + claimKey + `","run_id":"run-123"}`
	fake = &fakeAgentAuthorizationApprovalRepo{decision: &repository.AgentAuthorizationDecision{Allowed: true, GrantID: "server-grant"}}
	api = NewAgentAuthorizationApprovalAPI(fake, &Dependencies{})
	rr = httptest.NewRecorder()
	api.ClaimApproval(rr, trustedT15AgentRequest(partial))
	if rr.Code != http.StatusBadRequest || fake.authorizeCalls != 0 || fake.claimCalls != 0 {
		t.Fatalf("partial T13 context reached authorization: status=%d calls=%d/%d", rr.Code, fake.authorizeCalls, fake.claimCalls)
	}
}
