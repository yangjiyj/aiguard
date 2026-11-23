package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

func managedEmployeeFixture(t *testing.T) (*consoleLoginEnv, consoleTestUser, string) {
	t.Helper()
	e, u, dept := chatLoginFixture(t)
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "synthetic-managed-employee-test-secret")
	e.deps.EmployeeKeyRepo = repository.NewEmployeeAPIKeyRepository(e.pool)
	e.deps.ProjectRepo = repository.NewProjectRepository(e.pool)
	e.deps.ProjectUserRepo = repository.NewProjectUserRepository(e.pool)
	e.deps.TeamRepo = repository.NewTeamRepository(e.pool)
	e.deps.KeyRepo = repository.NewInternalKeyRepository(e.pool)
	e.deps.TeamModelRepo = repository.NewTeamModelRepository(e.pool)
	e.deps.UserIdentityLinkLookup = repository.NewUserIdentityLinkRepository(e.pool)
	project := u.ID + "-project"
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO projects(id,tenant_id,name,team_id,status,code,environment) VALUES($1,$2,'managed-employee-test',$3,'active','employee','production')`, project, e.tenantID, dept); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		e.pool.Exec(ctx, "DELETE FROM audit_operations WHERE tenant_id=$1", e.tenantID)
		e.pool.Exec(ctx, "DELETE FROM employee_api_keys WHERE tenant_id=$1", e.tenantID)
		e.pool.Exec(ctx, "DELETE FROM internal_keys WHERE tenant_id=$1", e.tenantID)
		e.pool.Exec(ctx, "DELETE FROM project_users WHERE user_id IN (SELECT id FROM users WHERE tenant_id=$1)", e.tenantID)
		e.pool.Exec(ctx, "DELETE FROM projects WHERE tenant_id=$1", e.tenantID)
	})
	return e, u, project
}
func employeeKeyHTTP(e *consoleLoginEnv, action string, req employeeKeyRequest, tenant string) *httptest.ResponseRecorder {
	var request *http.Request
	if action == "metadata" || action == "credential" {
		values := url.Values{"user_id": {req.UserID}, "login_mode": {req.LoginMode}, "external_subject": {req.ExternalSubject}, "local_credential_version": {strconv.FormatInt(req.LocalCredentialVersion, 10)}}
		request = httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/employee-key?"+values.Encode(), nil)
	} else {
		raw, _ := json.Marshal(req)
		request = httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/employee-key/"+action, strings.NewReader(string(raw)))
	}
	request.Header.Set(portalIntegrationTenantHeader, tenant)
	request.Header.Set("X-NewAPI-Internal-Token", "synthetic-managed-secret")
	response := httptest.NewRecorder()
	PortalIntegrationAPIMiddleware("synthetic-managed-secret", e.deps)(EmployeeKeyEndpoint(e.deps, action)).ServeHTTP(response, request)
	return response
}
func employeeKeyReply(t *testing.T, response *httptest.ResponseRecorder) (*repository.EmployeeAPIKey, string) {
	t.Helper()
	var reply struct {
		Key        *repository.EmployeeAPIKey `json:"key"`
		Full       string                     `json:"full_key"`
		Credential string                     `json:"credential"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &reply) != nil || reply.Key == nil {
		t.Fatalf("credential response status=%d", response.Code)
	}
	if response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("credential response permits caching")
	}
	if reply.Full != "" {
		return reply.Key, reply.Full
	}
	return reply.Key, reply.Credential
}
func TestEmployeeManagedKeyLoginClaimResetAndServerCredential(t *testing.T) {
	e, u, project := managedEmployeeFixture(t)
	req := employeeKeyRequest{UserID: u.ID, LoginMode: "local", ExternalSubject: "trusted-local-subject", LocalCredentialVersion: 1}
	ticket := chatFixtureTicket(t, e, u)
	redeemed := redeemFixtureTicket(e, e.tenantID, ticket, "", true)
	if redeemed.Code != 200 {
		t.Fatalf("login redeem status=%d", redeemed.Code)
	}
	metadata, raw := employeeKeyReply(t, employeeKeyHTTP(e, "metadata", req, e.tenantID))
	if metadata.UserID != u.ID || metadata.ProjectID != project || metadata.FirstClaimAt != nil || raw != "" {
		t.Fatal("login metadata invalid or secret exposed")
	}
	current, serverRaw := employeeKeyReply(t, employeeKeyHTTP(e, "credential", req, e.tenantID))
	if serverRaw == "" || current.FirstClaimAt != nil {
		t.Fatal("trusted server credential consumed first browser claim")
	}
	req.ExpectedKeyID = metadata.ID
	req.ExpectedGeneration = metadata.Generation
	claimed, claimedRaw := employeeKeyReply(t, employeeKeyHTTP(e, "claim", req, e.tenantID))
	if claimedRaw != serverRaw || claimed.FirstClaimAt == nil {
		t.Fatal("first claim invalid")
	}
	repeat := employeeKeyHTTP(e, "claim", req, e.tenantID)
	if repeat.Code != 409 || decodeConsoleError(t, repeat).Error.Code != "employee_key_already_claimed" {
		t.Fatalf("repeated claim status=%d", repeat.Code)
	}
	route := chi.NewRouter()
	route.Post("/admin/v1/portal-integration/customer-keys/{id}/reveal", RevealPortalCustomerKey(e.deps))
	revealReq := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/customer-keys/"+claimed.ID+"/reveal?user_id="+u.ID, nil)
	revealReq.Header.Set(portalIntegrationTenantHeader, e.tenantID)
	reveal := httptest.NewRecorder()
	route.ServeHTTP(reveal, revealReq)
	// 员工在门户随时可复制自己的个人 Key：只限本人、需在线、记审计。
	var revealed struct {
		FullKey string `json:"full_key"`
	}
	if reveal.Code != 200 || json.Unmarshal(reveal.Body.Bytes(), &revealed) != nil || revealed.FullKey != claimedRaw {
		t.Fatalf("personal key reveal status=%d body=%s", reveal.Code, reveal.Body.String())
	}
	otherReq := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/customer-keys/"+claimed.ID+"/reveal?user_id=someone-else", nil)
	otherReq.Header.Set(portalIntegrationTenantHeader, e.tenantID)
	other := httptest.NewRecorder()
	route.ServeHTTP(other, otherReq)
	if other.Code != 404 {
		t.Fatalf("other user reveal status=%d", other.Code)
	}
	reset, resetRaw := employeeKeyReply(t, employeeKeyHTTP(e, "reset", req, e.tenantID))
	if reset.ID == claimed.ID || reset.Generation != claimed.Generation+1 || resetRaw == claimedRaw || reset.FirstClaimAt == nil {
		t.Fatal("reset did not atomically rotate and claim")
	}
	old, err := e.deps.KeyRepo.GetByID(context.Background(), e.tenantID, claimed.ID)
	if err != nil || old == nil || old.Status != "revoked" {
		t.Fatal("old credential still valid after reset")
	}
	_, currentRaw := employeeKeyReply(t, employeeKeyHTTP(e, "credential", req, e.tenantID))
	if currentRaw != resetRaw {
		t.Fatal("server used stale credential after reset")
	}
	if stale := employeeKeyHTTP(e, "reset", req, e.tenantID); stale.Code != 409 {
		t.Fatalf("stale reset status=%d", stale.Code)
	}
}
func TestEmployeeManagedKeyRequiresCurrentBoundIdentityAndMachineAuthenticator(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	req := employeeKeyRequest{UserID: u.ID, LoginMode: "local", ExternalSubject: "trusted-local-subject", LocalCredentialVersion: 1}
	employeeKeyReply(t, employeeKeyHTTP(e, "ensure", req, e.tenantID))
	bad := req
	bad.ExternalSubject = "forged-subject"
	if got := employeeKeyHTTP(e, "metadata", bad, e.tenantID); got.Code != 403 {
		t.Fatalf("forged subject status=%d", got.Code)
	}
	if got := employeeKeyHTTP(e, "metadata", req, "another-tenant"); got.Code != 403 {
		t.Fatalf("cross-tenant status=%d", got.Code)
	}
	if _, err := e.pool.Exec(context.Background(), "UPDATE users SET role='developer' WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	if got := employeeKeyHTTP(e, "credential", req, e.tenantID); got.Code != 403 {
		t.Fatalf("changed role must reject credential status=%d", got.Code)
	}
	if _, err := e.pool.Exec(context.Background(), "UPDATE users SET role='chat_user',status='disabled' WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	if got := employeeKeyHTTP(e, "credential", req, e.tenantID); got.Code != 403 {
		t.Fatalf("disabled user status=%d", got.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/employee-key/credential", nil)
	request.Header.Set(portalIntegrationTenantHeader, e.tenantID)
	response := httptest.NewRecorder()
	PortalIntegrationAPIMiddleware("synthetic-managed-secret", e.deps)(EmployeeKeyEndpoint(e.deps, "credential")).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("browser credential access status=%d", response.Code)
	}
}
func TestEmployeeManagedKeyConcurrentBrowserClaimHasOneWinner(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	req := employeeKeyRequest{UserID: u.ID, LoginMode: "local", ExternalSubject: "trusted-local-subject", LocalCredentialVersion: 1}
	metadata, _ := employeeKeyReply(t, employeeKeyHTTP(e, "ensure", req, e.tenantID))
	req.ExpectedKeyID = metadata.ID
	req.ExpectedGeneration = metadata.Generation
	var successes, conflicts atomic.Int64
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			response := employeeKeyHTTP(e, "claim", req, e.tenantID)
			switch response.Code {
			case 200:
				successes.Add(1)
			case 409:
				conflicts.Add(1)
			default:
				t.Errorf("claim status=%d", response.Code)
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 || conflicts.Load() != 11 {
		t.Fatalf("claim winners=%d conflicts=%d", successes.Load(), conflicts.Load())
	}
}
func TestEmployeeManagedKeySSOSubjectCannotAssignAdministratorOrOtherIdentity(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	if _, err := e.pool.Exec(context.Background(), "UPDATE user_identity_links SET source_type='oidc' WHERE user_id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	req := employeeKeyRequest{UserID: u.ID, LoginMode: "oidc", ExternalSubject: "trusted-local-subject"}
	metadata, _ := employeeKeyReply(t, employeeKeyHTTP(e, "ensure", req, e.tenantID))
	if metadata.UserID != u.ID {
		t.Fatal("SSO employee key bound to another identity")
	}
	var role string
	if err := e.pool.QueryRow(context.Background(), "SELECT role FROM users WHERE id=$1", u.ID).Scan(&role); err != nil || role != "chat_user" {
		t.Fatal("SSO credential creation changed role")
	}
	req.ExternalSubject = "other-subject"
	if response := employeeKeyHTTP(e, "credential", req, e.tenantID); response.Code != 403 {
		t.Fatalf("SSO subject mismatch status=%d", response.Code)
	}
}

func TestEmployeeSSOLoginAutomaticallyPreparesKeyWithoutClaimPrivileges(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	e.deps.IdentityBindingService = identitybinding.NewService(repository.NewUserIdentityLinkRepository(e.pool))
	if _, err := e.pool.Exec(context.Background(), "UPDATE user_identity_links SET source_type='oidc' WHERE user_id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"issuer": e.deps.IdentityRuntimeConfig.IssuerURL, "source_type": "oidc", "external_subject": "trusted-local-subject", "username": u.Username, "email": u.ID + "@test.invalid", "groups": []string{"platform_admin", "tenant_admin"}, "role": "platform_admin"})
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/users", strings.NewReader(string(payload)))
	request.Header.Set(portalIntegrationTenantHeader, e.tenantID)
	response := httptest.NewRecorder()
	EnsurePortalUser(e.deps)(response, request)
	if response.Code != 200 {
		t.Fatalf("SSO login status=%d", response.Code)
	}
	current, err := e.deps.EmployeeKeyRepo.Current(context.Background(), e.tenantID, u.ID)
	if err != nil || current == nil || current.FirstClaimAt != nil {
		t.Fatal("SSO sign-in did not prepare unclaimed managed Key")
	}
	var role string
	if err := e.pool.QueryRow(context.Background(), "SELECT role FROM users WHERE id=$1", u.ID).Scan(&role); err != nil || role != "chat_user" {
		t.Fatal("SSO privileged claim changed employee role")
	}
}

func TestEmployeePasswordVersionRevokesOldTicketAndSignedIdentityAtomically(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	ctx := context.Background()
	req := employeeKeyRequest{UserID: u.ID, LoginMode: "local", ExternalSubject: "trusted-local-subject", LocalCredentialVersion: 1}
	employeeKeyReply(t, employeeKeyHTTP(e, "ensure", req, e.tenantID))
	oldTicket := chatFixtureTicket(t, e, u)
	// Simulate password storage completing while subsequent cache/ticket
	// revocation is unavailable. The version changes in the same UPDATE.
	if err := e.deps.UserRepo.UpdatePassword(ctx, u.ID, "synthetic-updated-hash", false); err != nil {
		t.Fatal(err)
	}
	if old := redeemFixtureTicket(e, e.tenantID, oldTicket, "", true); old.Code != 401 {
		t.Fatalf("old pre-password ticket status=%d", old.Code)
	}
	identity, err := e.deps.ChatLoginTickets.CurrentIdentity(ctx, e.tenantID, u.ID, e.deps.IdentityRuntimeConfig.IssuerURL)
	if err != nil || identity == nil || identity.LocalCredentialVersion != 2 {
		t.Fatal("password update did not change credential version")
	}
	if old := employeeKeyHTTP(e, "credential", req, e.tenantID); old.Code != 403 {
		t.Fatalf("old signed identity status=%d", old.Code)
	}
	req.LocalCredentialVersion = 2
	employeeKeyReply(t, employeeKeyHTTP(e, "credential", req, e.tenantID))
	router := chi.NewRouter()
	router.Get("/admin/v1/portal-integration/users/{id}/authorization-context", GetPortalUserAuthorizationContext(e.deps))
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/users/"+u.ID+"/authorization-context?login_mode=local&external_subject=trusted-local-subject", nil)
	request.Header.Set(portalIntegrationTenantHeader, e.tenantID)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	var current struct {
		Data struct {
			Version int64 `json:"local_credential_version"`
		} `json:"data"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &current) != nil || current.Data.Version != 2 {
		t.Fatalf("current authorization version status=%d", response.Code)
	}
	request.URL.RawQuery += "&local_credential_version=1"
	stale := httptest.NewRecorder()
	router.ServeHTTP(stale, request)
	if stale.Code != 403 {
		t.Fatalf("stale authorization version status=%d", stale.Code)
	}
}

func TestEmployeeManagedKeyNeverChangesExistingApplicationMembershipRole(t *testing.T) {
	for _, existingRole := range []string{"viewer", "owner"} {
		t.Run(existingRole, func(t *testing.T) {
			e, u, project := managedEmployeeFixture(t)
			ctx := context.Background()
			if err := e.deps.ProjectUserRepo.BindUserWithRole(ctx, project, u.ID, existingRole); err != nil {
				t.Fatal(err)
			}
			assertRole := func() {
				t.Helper()
				var role string
				if err := e.pool.QueryRow(ctx, "SELECT role FROM project_users WHERE project_id=$1 AND user_id=$2", project, u.ID).Scan(&role); err != nil || role != existingRole {
					t.Fatal("employee credential altered administrator-managed application role")
				}
			}
			req := employeeKeyRequest{UserID: u.ID, LoginMode: "local", ExternalSubject: "trusted-local-subject", LocalCredentialVersion: 1}
			metadata, _ := employeeKeyReply(t, employeeKeyHTTP(e, "ensure", req, e.tenantID))
			assertRole()
			req.ExpectedKeyID = metadata.ID
			req.ExpectedGeneration = metadata.Generation
			employeeKeyReply(t, employeeKeyHTTP(e, "reset", req, e.tenantID))
			assertRole()
			e.deps.IdentityBindingService = identitybinding.NewService(repository.NewUserIdentityLinkRepository(e.pool))
			if _, err := e.pool.Exec(ctx, "UPDATE user_identity_links SET source_type='oidc' WHERE user_id=$1", u.ID); err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(map[string]any{"issuer": e.deps.IdentityRuntimeConfig.IssuerURL, "source_type": "oidc", "external_subject": "trusted-local-subject", "username": u.Username, "email": u.ID + "@test.invalid"})
			request := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/users", strings.NewReader(string(payload)))
			request.Header.Set(portalIntegrationTenantHeader, e.tenantID)
			response := httptest.NewRecorder()
			EnsurePortalUser(e.deps)(response, request)
			if response.Code != 200 {
				t.Fatalf("SSO role-preserving login status=%d", response.Code)
			}
			assertRole()
		})
	}
}

func TestPersonalEmployeeCredentialSupportsAuthorizedHumanRoles(t *testing.T) {
	for _, role := range []string{"developer", "viewer", "dept_manager", "auditor", "security_officer", "tenant_admin"} {
		t.Run(role, func(t *testing.T) {
			e, u, _ := managedEmployeeFixture(t)
			if _, err := e.pool.Exec(context.Background(), "UPDATE users SET role=$2 WHERE id=$1", u.ID, role); err != nil {
				t.Fatal(err)
			}
			var version int64
			if err := e.pool.QueryRow(context.Background(), "SELECT local_credential_version FROM users WHERE id=$1", u.ID).Scan(&version); err != nil {
				t.Fatal(err)
			}
			req := employeeKeyRequest{UserID: u.ID, LoginMode: "local", ExternalSubject: "trusted-local-subject", LocalCredentialVersion: version}
			response := employeeKeyHTTP(e, "metadata", req, e.tenantID)
			if response.Code != 404 {
				t.Fatalf("read-only authorized role=%s metadata=%d", role, response.Code)
			}
		})
	}
}

func TestReviewEmployeeKeyMetadataGETNeverIssues(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	req := employeeKeyRequest{UserID: u.ID, LoginMode: "local", ExternalSubject: "trusted-local-subject", LocalCredentialVersion: 1}
	response := employeeKeyHTTP(e, "metadata", req, e.tenantID)
	if response.Code != 404 {
		t.Errorf("missing metadata status=%d", response.Code)
	}
	var count int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM internal_keys WHERE tenant_id=$1 AND user_id=$2", e.tenantID, u.ID).Scan(&count); err != nil || count != 0 {
		t.Errorf("GET issued %d credentials err=%v", count, err)
	}
}
func TestReviewEmployeeKeyAuthorizedHumanRoleScope(t *testing.T) {
	for _, role := range []string{"developer", "viewer", "dept_manager", "auditor", "security_officer", "tenant_admin", "platform_admin"} {
		t.Run(role, func(t *testing.T) {
			e, u, _ := managedEmployeeFixture(t)
			if _, err := e.pool.Exec(context.Background(), "UPDATE users SET role=$2 WHERE id=$1", u.ID, role); err != nil {
				t.Fatal(err)
			}
			req := employeeKeyRequest{UserID: u.ID, LoginMode: "local", ExternalSubject: "trusted-local-subject", LocalCredentialVersion: 1}
			if w := employeeKeyHTTP(e, "ensure", req, e.tenantID); w.Code != 200 {
				t.Fatalf("role=%s status=%d", role, w.Code)
			}
		})
	}
}

func TestReviewEmployeeKeyRoleChangeRejectsOldCredentialUntilPOSTEnsure(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	req := employeeKeyRequest{UserID: u.ID, LoginMode: "local", ExternalSubject: "trusted-local-subject", LocalCredentialVersion: 1}
	original, _ := employeeKeyReply(t, employeeKeyHTTP(e, "ensure", req, e.tenantID))
	if _, err := e.pool.Exec(context.Background(), "UPDATE users SET role='developer' WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	if w := employeeKeyHTTP(e, "credential", req, e.tenantID); w.Code != 403 {
		t.Fatalf("old role credential status=%d", w.Code)
	}
	next, _ := employeeKeyReply(t, employeeKeyHTTP(e, "ensure", req, e.tenantID))
	if next.ID == original.ID {
		t.Fatal("role change reused old credential")
	}
	if w := employeeKeyHTTP(e, "metadata", req, e.tenantID); w.Code != 200 {
		t.Fatalf("fresh developer metadata=%d", w.Code)
	}
}

func TestReviewDeveloperFirstLoginCreatesCredentialBeforeReadOnlyChatBootstrap(t *testing.T) {
	e, u, project := managedEmployeeFixture(t)
	ctx := context.Background()
	dept := ensureDepartment(t, e.pool, e.tenantID, "developer first login")
	mustExec(t, e.pool, "UPDATE users SET role='developer',department_id=$2 WHERE id=$1", u.ID, dept)
	mustExec(t, e.pool, "UPDATE projects SET team_id=$2 WHERE id=$1", project, dept)
	var before int
	if err := e.pool.QueryRow(ctx, "SELECT count(*) FROM employee_api_keys WHERE tenant_id=$1 AND user_id=$2", e.tenantID, u.ID).Scan(&before); err != nil || before != 0 {
		t.Fatal("first-login fixture already has credential")
	}
	ticket := chatFixtureTicket(t, e, u)
	redeemed := redeemFixtureTicket(e, e.tenantID, ticket, "", true)
	if redeemed.Code != 200 {
		t.Fatalf("developer first redemption=%d", redeemed.Code)
	}
	req := employeeKeyRequest{UserID: u.ID, LoginMode: "local", ExternalSubject: "trusted-local-subject", LocalCredentialVersion: 1}
	key, _ := employeeKeyReply(t, employeeKeyHTTP(e, "metadata", req, e.tenantID))
	_, credential := employeeKeyReply(t, employeeKeyHTTP(e, "credential", req, e.tenantID))
	if key.UserID != u.ID || key.ProjectID != project || credential == "" {
		t.Fatal("first login did not provision a bound model credential")
	}
	var after int
	e.pool.QueryRow(ctx, "SELECT count(*) FROM employee_api_keys WHERE tenant_id=$1 AND user_id=$2", e.tenantID, u.ID).Scan(&after)
	if after != 1 {
		t.Fatalf("read-only bootstrap created %d credentials", after)
	}
}

func TestReviewMergedSourceCannotLoginEndToEnd(t *testing.T){
 e,u,_:=managedEmployeeFixture(t);ctx:=context.Background()
 actor,target:=u.ID+"_merge_admin",u.ID+"_merge_target"
 for _,item:=range []struct{id,role string}{{actor,"platform_admin"},{target,"chat_user"}}{
  mustExec(t,e.pool,"INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode) SELECT $1,tenant_id,$1,$2,'active',department_id,'manual' FROM users WHERE id=$3",item.id,item.role,u.ID)
 }
 repo:=repository.NewUserAccountMergeRepository(e.pool)
 req:=employeeKeyRequest{UserID:u.ID,LoginMode:"local",ExternalSubject:"trusted-local-subject",LocalCredentialVersion:1}
 employeeKeyReply(t,employeeKeyHTTP(e,"ensure",req,e.tenantID))
 preview,err:=repo.Preview(ctx,e.tenantID,u.ID,target,actor);if err!=nil {t.Fatal(err)}
 t.Cleanup(func(){e.pool.Exec(ctx,"DELETE FROM user_account_merges WHERE tenant_id=$1",e.tenantID)})
 if _,err:=repo.Merge(ctx,e.tenantID,u.ID,target,actor,repository.AccountMergeInput{PreviewVersion:preview.Version,Choices:map[string]string{"api_keys":"revoke_source","employee_key":"revoke_both"}});err!=nil {t.Fatal(err)}
 response:=e.employeeLogin(u.Username,u.Password,"192.0.2.15",nil)
 if response.Code!=401 || decodeConsoleError(t,response).Error.Code!="invalid_credentials" {t.Fatalf("merged source still logged in: status=%d",response.Code)}
}
