package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

const handlerTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeIdentityTester struct {
	discovery *identity.DiscoveryDocument
	err       error
}

func (f *fakeIdentityTester) TestConnection(_ context.Context, _ identity.TestConfig) *identity.TestConnectionResult {
	if f.err != nil {
		return &identity.TestConnectionResult{Error: "身份源验证失败"}
	}
	return &identity.TestConnectionResult{Success: true}
}

func (f *fakeIdentityTester) ResolveDiscovery(_ context.Context, _ identity.TestConfig) (*identity.DiscoveryDocument, error) {
	return f.discovery, f.err
}

type fakeIdentityRuntime struct {
	publishCalls int
	disableCalls int
	statusCalls  int
	restoreCalls int
	desired      identityruntime.DesiredIdentitySource
	publication  identityruntime.Publication
	snapshot     identityruntime.RuntimeSnapshot
	status       identityruntime.RuntimeStatus
	publishErr   error
	disableErr   error
	statusErr    error
	restoreErr   error
	forceDigest  bool
	onPublish    func()
	onDisable    func()
	observed     identityruntime.ObservedSettings
	observeErr   error
	observeCalls int
	onObserve    func()
}

func (f *fakeIdentityRuntime) Publish(_ context.Context, desired identityruntime.DesiredIdentitySource) (identityruntime.Publication, error) {
	f.publishCalls++
	f.desired = desired
	if f.onPublish != nil {
		f.onPublish()
	}
	publication := f.publication
	if !f.forceDigest {
		publication.Digest = desired.Digest
	}
	return publication, f.publishErr
}

func (f *fakeIdentityRuntime) Disable(_ context.Context, desired identityruntime.DesiredIdentitySource) (identityruntime.RuntimeSnapshot, error) {
	f.disableCalls++
	f.desired = desired
	if f.onDisable != nil {
		f.onDisable()
	}
	return f.snapshot, f.disableErr
}

func (f *fakeIdentityRuntime) Status(_ context.Context, desired identityruntime.DesiredIdentitySource) (identityruntime.RuntimeStatus, error) {
	f.statusCalls++
	f.desired = desired
	return f.status, f.statusErr
}

func (f *fakeIdentityRuntime) Observe(_ context.Context, desired identityruntime.DesiredIdentitySource) (identityruntime.ObservedSettings, error) {
	f.observeCalls++
	f.desired = desired
	if f.onObserve != nil {
		f.onObserve()
	}
	return f.observed, f.observeErr
}

func (f *fakeIdentityRuntime) Restore(_ context.Context, _ identityruntime.RuntimeSnapshot) error {
	f.restoreCalls++
	return f.restoreErr
}

func buildRuntimeIdentityDeps(t *testing.T, pool *pgxpool.Pool, runtime *fakeIdentityRuntime) *Dependencies {
	t.Helper()
	deps := buildIdentityDeps(pool)
	deps.UserRepo = repository.NewUserRepository(pool)
	deps.OIDCTester = &fakeIdentityTester{discovery: &identity.DiscoveryDocument{
		Issuer: "https://idp.example.com", AuthorizationEndpoint: "https://idp.example.com/auth",
		TokenEndpoint: "https://idp.example.com/token", JWKSURI: "https://idp.example.com/jwks",
		UserInfoEndpoint: "https://idp.example.com/userinfo", EndSessionEndpoint: "https://idp.example.com/logout",
	}}
	if runtime != nil {
		deps.IdentityRuntime = runtime
	}
	deps.IdentityRuntimeConfig = IdentityRuntimeConfig{
		CallbackURL: "https://sso.example.com/sso/realms/jjdguard/broker/enterprise/endpoint",
	}
	return deps
}

func seedTestedIdentitySource(t *testing.T, deps *Dependencies, tenantID string) *repository.IdentitySource {
	t.Helper()
	setupIdentitySecretKey(t)
	secretEnc, _, err := secrets.EncryptProviderSecret("source-secret")
	if err != nil {
		t.Fatal(err)
	}
	src := &repository.IdentitySource{
		TenantID: tenantID, DisplayName: "企业 IdP", IssuerURL: "https://idp.example.com",
		ClientID: "client-a", ClientSecretEnc: secretEnc, Scopes: "openid profile email",
		SubjectClaim: "sub", UsernameClaim: "preferred_username", NameClaim: "name", EmailClaim: "email",
		PhoneClaim: "phone_number", DeptCodeClaim: "department_code",
		DeptNameClaim: "department_name", GroupsClaim: "groups",
	}
	if err := deps.IdentitySourceRepo.UpsertDraft(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	if err := deps.IdentitySourceRepo.UpdateTestResult(
		context.Background(), tenantID, src.ID, src.Version, &repository.TestResult{Success: true},
	); err != nil {
		t.Fatal(err)
	}
	got, err := deps.IdentitySourceRepo.GetTested(context.Background(), tenantID)
	if err != nil || got == nil {
		t.Fatalf("seed tested source: %#v %v", got, err)
	}
	return got
}

func seedActiveIdentitySource(t *testing.T, deps *Dependencies, tenantID, userID string) *repository.IdentitySource {
	t.Helper()
	src := seedTestedIdentitySource(t, deps, tenantID)
	if err := deps.IdentitySourceRepo.MarkPublishing(context.Background(), tenantID, src.ID, src.Version); err != nil {
		t.Fatal(err)
	}
	if err := deps.IdentitySourceRepo.CommitPublication(context.Background(), repository.PublicationCommit{
		TenantID: tenantID, SourceID: src.ID, ExpectedVersion: src.Version,
		RuntimeAlias: identityruntime.ProviderAlias, ConfigDigest: handlerTestDigest, PublishedBy: userID,
	}); err != nil {
		t.Fatal(err)
	}
	active, err := deps.IdentitySourceRepo.GetActive(context.Background(), tenantID)
	if err != nil || active == nil {
		t.Fatalf("seed active source: %#v %v", active, err)
	}
	return active
}

func TestActivatePublishesBeforeDatabaseCommit(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{publication: identityruntime.Publication{
		Digest: handlerTestDigest,
		Previous: identityruntime.RuntimeSnapshot{
			Realm: identityruntime.RealmName, Alias: identityruntime.ProviderAlias, Exists: true,
		},
	}}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	tested := seedTestedIdentitySource(t, deps, tenantID)

	req := withOrgUserCtx(httptest.NewRequest(
		http.MethodPost, "/admin/v1/identity/sources/activate", nil,
	), tenantID, userID)
	rr := httptest.NewRecorder()
	ActivateIdentitySource(deps)(rr, req)
	if rr.Code != http.StatusOK || runtime.publishCalls != 1 {
		t.Fatalf("activate=%d publishCalls=%d body=%s", rr.Code, runtime.publishCalls, rr.Body.String())
	}
	active, err := deps.IdentitySourceRepo.GetActive(context.Background(), tenantID)
	if err != nil || active == nil || active.AppliedVersion != tested.Version ||
		active.ConfigDigest != runtime.desired.Digest {
		t.Fatalf("database publication not committed: %#v %v", active, err)
	}
	if runtime.desired.Realm != identityruntime.RealmName ||
		runtime.desired.Alias != identityruntime.ProviderAlias ||
		runtime.desired.Endpoints.Token == "" || runtime.desired.ClientSecret != "source-secret" {
		t.Fatal("runtime desired source was not constructed from validated configuration")
	}
	if strings.Contains(rr.Body.String(), "source-secret") ||
		regexp.MustCompile("(?i)keycloak|chat-idp|master realm|client mapper").MatchString(rr.Body.String()) {
		t.Fatalf("internal or secret data leaked: %s", rr.Body.String())
	}
}

func TestActivateRestoresRuntimeWhenDatabaseCommitFails(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{publication: identityruntime.Publication{
		Digest: handlerTestDigest,
		Previous: identityruntime.RuntimeSnapshot{
			Realm: identityruntime.RealmName, Alias: identityruntime.ProviderAlias, Exists: true,
		},
	}}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	tested := seedTestedIdentitySource(t, deps, tenantID)
	runtime.onPublish = func() {
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM identity_sources WHERE tenant_id=$1 AND id=$2", tenantID, tested.ID)
	}

	req := withOrgUserCtx(httptest.NewRequest(
		http.MethodPost, "/admin/v1/identity/sources/activate", nil,
	), tenantID, userID)
	rr := httptest.NewRecorder()
	ActivateIdentitySource(deps)(rr, req)
	if rr.Code == http.StatusOK || runtime.restoreCalls != 1 {
		t.Fatalf("database failure must restore runtime: code=%d restores=%d body=%s",
			rr.Code, runtime.restoreCalls, rr.Body.String())
	}
}

func TestActivateReturnsStableUnavailableWithoutStoppingLocalAdmin(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildRuntimeIdentityDeps(t, pool, nil)
	seedTestedIdentitySource(t, deps, tenantID)
	req := withOrgUserCtx(httptest.NewRequest(
		http.MethodPost, "/admin/v1/identity/sources/activate", nil,
	), tenantID, userID)
	rr := httptest.NewRecorder()
	ActivateIdentitySource(deps)(rr, req)
	if rr.Code != http.StatusServiceUnavailable ||
		!strings.Contains(rr.Body.String(), "identity_runtime_unavailable") {
		t.Fatalf("unexpected unavailable response: %d %s", rr.Code, rr.Body.String())
	}
}

func TestDisableRequiresRealEmergencyAdmin(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	seedActiveIdentitySource(t, deps, tenantID, userID)
	if _, err := pool.Exec(context.Background(), "UPDATE users SET password_hash='' WHERE id=$1", userID); err != nil {
		t.Fatal(err)
	}

	req := withOrgUserCtx(httptest.NewRequest(
		http.MethodPost, "/admin/v1/identity/sources/disable",
		bytes.NewReader([]byte("{\"confirm\":true}")),
	), tenantID, userID)
	rr := httptest.NewRecorder()
	DisableIdentitySource(deps)(rr, req)
	if rr.Code != http.StatusConflict || runtime.disableCalls != 0 ||
		!strings.Contains(rr.Body.String(), "emergency_admin_required") {
		t.Fatalf("code=%d disableCalls=%d body=%s", rr.Code, runtime.disableCalls, rr.Body.String())
	}
}

func TestDisableRestoresRuntimeWhenDatabaseWriteFails(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{snapshot: identityruntime.RuntimeSnapshot{
		Realm: identityruntime.RealmName, Alias: identityruntime.ProviderAlias, Exists: true,
	}}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	active := seedActiveIdentitySource(t, deps, tenantID, userID)
	runtime.onDisable = func() {
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM identity_sources WHERE tenant_id=$1 AND id=$2", tenantID, active.ID)
	}

	req := withOrgUserCtx(httptest.NewRequest(
		http.MethodPost, "/admin/v1/identity/sources/disable",
		bytes.NewReader([]byte("{\"confirm\":true}")),
	), tenantID, userID)
	rr := httptest.NewRecorder()
	DisableIdentitySource(deps)(rr, req)
	if rr.Code == http.StatusOK || runtime.restoreCalls != 1 {
		t.Fatalf("database failure must restore runtime: code=%d restores=%d body=%s",
			rr.Code, runtime.restoreCalls, rr.Body.String())
	}
}

func TestStatusReportsRuntimeDriftWithoutInternalTerms(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{status: identityruntime.RuntimeStatus{
		Exists: true, Enabled: true,
		Digest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Drifted: true,
	}}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	seedActiveIdentitySource(t, deps, tenantID, userID)

	req := withOrgUserCtx(httptest.NewRequest(
		http.MethodGet, "/admin/v1/identity/status", nil,
	), tenantID, userID)
	rr := httptest.NewRecorder()
	GetIdentityStatus(deps)(rr, req)
	body := rr.Body.String()
	if rr.Code != http.StatusOK ||
		!strings.Contains(body, "\"publish_status\":\"drifted\"") ||
		!strings.Contains(body, "\"drift\":true") {
		t.Fatalf("unexpected drift response: %d %s", rr.Code, body)
	}
	if !strings.Contains(body, "https://sso.example.com/sso/") ||
		regexp.MustCompile("(?i)keycloak|chat-idp|master realm|client mapper").MatchString(body) {
		t.Fatalf("public status leaked internal implementation: %s", body)
	}
}

func TestReconcileIsTenantScoped(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	seedActiveIdentitySource(t, deps, tenantID, userID)

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/reconcile", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "other-admin", TenantID: "other-tenant", Role: "tenant_owner", Status: "active",
	}))
	rr := httptest.NewRecorder()
	ReconcileIdentitySource(deps)(rr, req)
	if rr.Code != http.StatusNotFound || runtime.publishCalls != 0 {
		t.Fatalf("cross-tenant reconcile: code=%d publishCalls=%d body=%s",
			rr.Code, runtime.publishCalls, rr.Body.String())
	}
}

func TestReconcileRepublishesDriftedActiveSource(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{publication: identityruntime.Publication{
		Digest: handlerTestDigest,
		Previous: identityruntime.RuntimeSnapshot{
			Realm: identityruntime.RealmName, Alias: identityruntime.ProviderAlias, Exists: true,
		},
	}}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	active := seedActiveIdentitySource(t, deps, tenantID, userID)
	if err := deps.IdentitySourceRepo.MarkRuntimeStatus(
		context.Background(), tenantID, active.ID, "drifted",
	); err != nil {
		t.Fatal(err)
	}

	req := withOrgUserCtx(httptest.NewRequest(
		http.MethodPost, "/admin/v1/identity/sources/reconcile", nil,
	), tenantID, userID)
	rr := httptest.NewRecorder()
	ReconcileIdentitySource(deps)(rr, req)
	if rr.Code != http.StatusOK || runtime.publishCalls != 1 {
		t.Fatalf("reconcile=%d calls=%d body=%s", rr.Code, runtime.publishCalls, rr.Body.String())
	}
}

func TestActivateRestoresOnPublicationDigestMismatch(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{
		forceDigest: true,
		publication: identityruntime.Publication{
			Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Previous: identityruntime.RuntimeSnapshot{
				Realm: identityruntime.RealmName, Alias: identityruntime.ProviderAlias, Exists: true,
			},
		},
	}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	tested := seedTestedIdentitySource(t, deps, tenantID)

	req := withOrgUserCtx(httptest.NewRequest(
		http.MethodPost, "/admin/v1/identity/sources/activate", nil,
	), tenantID, userID)
	rr := httptest.NewRecorder()
	ActivateIdentitySource(deps)(rr, req)
	if rr.Code != http.StatusBadGateway || runtime.restoreCalls != 1 ||
		!strings.Contains(rr.Body.String(), "identity_publish_failed") {
		t.Fatalf("digest mismatch must restore: code=%d restores=%d body=%s",
			rr.Code, runtime.restoreCalls, rr.Body.String())
	}
	current, err := deps.IdentitySourceRepo.GetByID(context.Background(), tenantID, tested.ID)
	if err != nil || current == nil || current.Status != "tested" || current.PublishStatus != "error" {
		t.Fatalf("digest mismatch must not activate database source: %#v %v", current, err)
	}
}

func TestReconcileRejectsDeveloperBeforeRepositoryAccess(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/reconcile", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "developer", TenantID: "tenant-a", Role: "developer", Status: "active",
	}))
	rr := httptest.NewRecorder()
	ReconcileIdentitySource(&Dependencies{})(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("developer reconcile must be forbidden: %d %s", rr.Code, rr.Body.String())
	}
}

func TestDisabledIdentitySourceCanBeReactivated(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	runtime := &fakeIdentityRuntime{snapshot: identityruntime.RuntimeSnapshot{
		Realm: identityruntime.RealmName, Alias: identityruntime.ProviderAlias, Exists: true,
	}}
	deps := buildRuntimeIdentityDeps(t, pool, runtime)
	seedActiveIdentitySource(t, deps, tenantID, userID)

	disableResponse := httptest.NewRecorder()
	DisableIdentitySource(deps)(disableResponse, withOrgUserCtx(httptest.NewRequest(
		http.MethodPost, "/admin/v1/identity/sources/disable",
		bytes.NewReader([]byte("{\x22confirm\x22:true}")),
	), tenantID, userID))
	if disableResponse.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", disableResponse.Code, disableResponse.Body.String())
	}

	activateResponse := httptest.NewRecorder()
	ActivateIdentitySource(deps)(activateResponse, withOrgUserCtx(httptest.NewRequest(
		http.MethodPost, "/admin/v1/identity/sources/activate", nil,
	), tenantID, userID))
	if activateResponse.Code != http.StatusOK || runtime.publishCalls != 1 {
		t.Fatalf("reactivate status=%d publish=%d body=%s", activateResponse.Code, runtime.publishCalls, activateResponse.Body.String())
	}
}
