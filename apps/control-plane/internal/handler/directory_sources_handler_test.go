package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryldap"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

type recordingDirectoryTester struct{ testCalls, listCalls int }

func (tester *recordingDirectoryTester) TestConnection(context.Context, directoryldap.TestRequest) (directoryldap.TestResult, error) {
	tester.testCalls++
	return directoryldap.TestResult{Connected: true}, nil
}

func (tester *recordingDirectoryTester) ListUsers(context.Context, directoryldap.SyncRequest) ([]directoryldap.DirectoryUser, error) {
	tester.listCalls++
	return nil, nil
}

type approvedDirectoryResolver struct{}

func (approvedDirectoryResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("10.20.30.40")}}, nil
}

func approvedDirectoryPolicy(t *testing.T) directoryldap.TargetPolicy {
	t.Helper()
	policy, err := directoryldap.ParseTargetPolicy("ldap-sim.jjdguard.test:636", "10.20.0.0/16")
	if err != nil {
		t.Fatalf("parse target policy: %v", err)
	}
	return policy.WithResolver(approvedDirectoryResolver{})
}
func TestSaveDirectoryDraftNeverReturnsBindPassword(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildIdentityDeps(pool)
	deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
	deps.DirectoryTargetPolicy = approvedDirectoryPolicy(t)

	body := bytes.NewReader([]byte(`{"kind":"ldap","display_name":"Simulated LDAP","connection_url":"ldaps://ldap-sim.jjdguard.test:636","bind_dn":"cn=admin,dc=jjdguard,dc=test","bind_password":"directory-secret","base_dn":"dc=jjdguard,dc=test","users_dn":"ou=People,dc=jjdguard,dc=test"}`))
	request := httptest.NewRequest(http.MethodPut, "/admin/v1/directory/sources/draft", body)
	request = withOrgUserCtx(request, tenantID, userID)
	response := httptest.NewRecorder()

	SaveDirectoryDraft(deps)(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("save draft failed: %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "directory-secret") {
		t.Fatalf("bind password leaked in save response: %s", response.Body.String())
	}

	readRequest := httptest.NewRequest(http.MethodGet, "/admin/v1/directory/sources/draft", nil)
	readRequest = withOrgUserCtx(readRequest, tenantID, userID)
	readResponse := httptest.NewRecorder()
	GetDirectoryDraft(deps)(readResponse, readRequest)
	if strings.Contains(readResponse.Body.String(), "directory-secret") {
		t.Fatalf("bind password leaked in read response: %s", readResponse.Body.String())
	}
	for _, sensitive := range []string{"ldaps://ldap-sim.jjdguard.test:636", "cn=admin,dc=jjdguard,dc=test", "dc=jjdguard,dc=test", "ou=People,dc=jjdguard,dc=test", "directory-secret"} {
		if strings.Contains(response.Body.String(), sensitive) || strings.Contains(readResponse.Body.String(), sensitive) {
			t.Fatalf("directory configuration leaked in save/get response: %q", sensitive)
		}
	}

	draft, err := deps.DirectorySourceRepo.GetDraft(context.Background(), tenantID)
	if err != nil || draft == nil {
		t.Fatalf("draft missing before test result update: %v", err)
	}
	if err := deps.DirectorySourceRepo.UpdateTestResult(context.Background(), tenantID, draft.ID, draft.Version, &repository.TestResult{Success: true}); err != nil {
		t.Fatalf("mark directory source tested: %v", err)
	}

	testedRequest := httptest.NewRequest(http.MethodGet, "/admin/v1/directory/sources/draft", nil)
	testedRequest = withOrgUserCtx(testedRequest, tenantID, userID)
	testedResponse := httptest.NewRecorder()
	GetDirectoryDraft(deps)(testedResponse, testedRequest)
	if !strings.Contains(testedResponse.Body.String(), `"status":"tested"`) {
		t.Fatalf("tested source missing from read response: %s", testedResponse.Body.String())
	}
}

func TestSaveDirectoryDraftReturnsConflictWhileActivationClaimIsHeld(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	repo := repository.NewDirectorySourceRepository(pool)
	encrypted, _, err := secrets.EncryptProviderSecret("directory-secret")
	if err != nil {
		t.Fatal(err)
	}
	source := &repository.DirectorySource{
		TenantID: tenantID, Kind: repository.DirectoryKindLDAP, DisplayName: "Original LDAP",
		ConnectionURL:   "ldaps://ldap-sim.jjdguard.test:636",
		BindDN:          "cn=admin,dc=jjdguard,dc=test",
		BindPasswordEnc: encrypted,
		BaseDN:          "dc=jjdguard,dc=test",
		UsersDN:         "ou=People,dc=jjdguard,dc=test",
	}
	if err := repo.UpsertDraft(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	claimedVersion := source.Version
	claim, err := repo.ClaimActivation(context.Background(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = claim.Release(context.Background()) }()

	payload, err := json.Marshal(map[string]any{
		"kind":           "ldap",
		"display_name":   "Concurrent LDAP",
		"connection_url": "ldaps://ldap-sim.jjdguard.test:636",
		"bind_dn":        "cn=admin,dc=jjdguard,dc=test",
		"base_dn":        "dc=jjdguard,dc=test",
		"users_dn":       "ou=People,dc=jjdguard,dc=test",
		"version":        claimedVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	deps := buildIdentityDeps(pool)
	deps.DirectorySourceRepo = repo
	deps.DirectoryTargetPolicy = approvedDirectoryPolicy(t)
	response := httptest.NewRecorder()
	request := withOrgUserCtx(httptest.NewRequest(
		http.MethodPut, "/admin/v1/directory/sources/draft", bytes.NewReader(payload),
	), tenantID, userID)
	SaveDirectoryDraft(deps)(response, request)

	current, readErr := repo.GetByID(context.Background(), tenantID, source.ID)
	if response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), "directory_activation_in_progress") ||
		readErr != nil || current == nil || current.Version != claimedVersion ||
		current.DisplayName != source.DisplayName {
		t.Fatalf("status=%d current=%#v err=%v body=%s", response.Code, current, readErr, response.Body.String())
	}
}

func TestSaveDirectoryDraftHonorsValidatedUserFilterLengthBoundary(t *testing.T) {
	for _, filterLength := range []int{1024, 4095, 4096, 4097} {
		t.Run(fmt.Sprintf("%d bytes", filterLength), func(t *testing.T) {
			pool, tenantID, userID := setupOrgHandlerPool(t)
			setupIdentitySecretKey(t)
			deps := buildIdentityDeps(pool)
			deps.DirectorySourceRepo = repository.NewDirectorySourceRepository(pool)
			deps.DirectoryTargetPolicy = approvedDirectoryPolicy(t)

			filter := "(uid=" + strings.Repeat("a", filterLength-6) + ")"
			body, err := json.Marshal(map[string]any{
				"kind": "ldap", "display_name": "Boundary LDAP",
				"connection_url": "ldaps://ldap-sim.jjdguard.test:636", "bind_dn": "cn=admin,dc=jjdguard,dc=test",
				"bind_password": "directory-secret", "base_dn": "dc=jjdguard,dc=test", "users_dn": "ou=People,dc=jjdguard,dc=test",
				"user_filter": filter,
			})
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			response := httptest.NewRecorder()
			SaveDirectoryDraft(deps)(response, withOrgUserCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/directory/sources/draft", bytes.NewReader(body)), tenantID, userID))

			if filterLength == 4097 {
				if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_request") {
					t.Fatalf("oversized filter status=%d body=%s, want stable invalid_request", response.Code, response.Body.String())
				}
				return
			}
			if response.Code != http.StatusOK {
				t.Fatalf("filter length %d save status=%d body=%s", filterLength, response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), filter) {
				t.Fatalf("save response reflected user filter")
			}

			readResponse := httptest.NewRecorder()
			GetDirectoryDraft(deps)(readResponse, withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/directory/sources/draft", nil), tenantID, userID))
			if readResponse.Code != http.StatusOK || strings.Contains(readResponse.Body.String(), filter) {
				t.Fatalf("get draft status=%d body=%s", readResponse.Code, readResponse.Body.String())
			}
			draft, err := deps.DirectorySourceRepo.GetDraft(context.Background(), tenantID)
			if err != nil || draft == nil || len(draft.UserFilter) != filterLength {
				t.Fatalf("stored filter length=%d err=%v, want %d", len(draft.UserFilter), err, filterLength)
			}
		})
	}
}

func TestSaveDirectoryDraftPreservesOmittedRawConfigAndUpdatesExplicitFields(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	repo := repository.NewDirectorySourceRepository(pool)
	password, _, err := secrets.EncryptProviderSecret("directory-secret")
	if err != nil {
		t.Fatalf("encrypt bind password: %v", err)
	}
	seed := &repository.DirectorySource{
		TenantID: tenantID, Kind: repository.DirectoryKindLDAP, DisplayName: "Custom LDAP",
		ConnectionURL: "ldaps://ldap-sim.jjdguard.test:636", BindDN: "cn=custom-reader,dc=example,dc=test", BindPasswordEnc: password,
		CACertPEM: "custom-ca", BaseDN: "dc=example,dc=test", UsersDN: "ou=people,dc=example,dc=test", UserFilter: "(uid=custom)",
		StableIDAttribute: "customEntryID", UsernameAttribute: "customUID", EmailAttribute: "customMail", NameAttribute: "customName",
	}
	if err := repo.UpsertDraft(context.Background(), seed); err != nil {
		t.Fatalf("seed draft: %v", err)
	}
	if err := repo.UpdateTestResult(context.Background(), tenantID, seed.ID, seed.Version, &repository.TestResult{Success: true}); err != nil {
		t.Fatalf("mark seed tested: %v", err)
	}
	draft, err := repo.GetDraft(context.Background(), tenantID)
	if err != nil || draft == nil {
		t.Fatalf("load seeded draft: %v", err)
	}
	deps := buildIdentityDeps(pool)
	deps.DirectorySourceRepo = repo
	deps.DirectoryTargetPolicy = approvedDirectoryPolicy(t)
	save := func(body map[string]any) (*repository.DirectorySource, string) {
		payload, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			t.Fatalf("marshal request: %v", marshalErr)
		}
		response := httptest.NewRecorder()
		SaveDirectoryDraft(deps)(response, withOrgUserCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/directory/sources/draft", bytes.NewReader(payload)), tenantID, userID))
		if response.Code != http.StatusOK {
			t.Fatalf("save status=%d body=%s", response.Code, response.Body.String())
		}
		current, getErr := repo.GetDraft(context.Background(), tenantID)
		if getErr != nil || current == nil {
			t.Fatalf("load saved draft: %v", getErr)
		}
		return current, response.Body.String()
	}
	baseRequest := map[string]any{
		"kind": "ldap", "display_name": "Updated LDAP", "connection_url": "ldaps://ldap-sim.jjdguard.test:636",
		"bind_dn": "cn=custom-reader,dc=example,dc=test", "base_dn": "dc=example,dc=test", "users_dn": "ou=people,dc=example,dc=test", "version": draft.Version,
	}
	preserved, responseBody := save(baseRequest)
	if preserved.UserFilter != "(uid=custom)" || preserved.StableIDAttribute != "customEntryID" || preserved.UsernameAttribute != "customUID" || preserved.EmailAttribute != "customMail" || preserved.NameAttribute != "customName" {
		t.Fatalf("omitted fields overwritten: %#v", preserved)
	}
	for _, raw := range []string{seed.ConnectionURL, seed.BindDN, seed.BaseDN, seed.UsersDN, seed.UserFilter, seed.CACertPEM, "directory-secret"} {
		if strings.Contains(responseBody, raw) {
			t.Fatalf("save response leaked raw directory configuration: %q", raw)
		}
	}
	baseRequest["version"] = preserved.Version
	baseRequest["user_filter"] = "(uid=updated)"
	baseRequest["stable_id_attribute"] = "updatedEntryID"
	baseRequest["username_attribute"] = "updatedUID"
	baseRequest["email_attribute"] = "updatedMail"
	baseRequest["name_attribute"] = "updatedName"
	updated, _ := save(baseRequest)
	if updated.UserFilter != "(uid=updated)" || updated.StableIDAttribute != "updatedEntryID" || updated.UsernameAttribute != "updatedUID" || updated.EmailAttribute != "updatedMail" || updated.NameAttribute != "updatedName" {
		t.Fatalf("explicit fields not updated: %#v", updated)
	}
}

func TestSaveDirectoryDraftKeepsExistingCAWhenEmpty(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	repo := repository.NewDirectorySourceRepository(pool)
	password, _, err := secrets.EncryptProviderSecret("directory-secret")
	if err != nil {
		t.Fatalf("encrypt password: %v", err)
	}
	seed := &repository.DirectorySource{TenantID: tenantID, Kind: repository.DirectoryKindLDAP, DisplayName: "LDAP", ConnectionURL: "ldaps://ldap-sim.jjdguard.test:636", BindDN: "cn=sync", BindPasswordEnc: password, CACertPEM: "existing-private-ca", BaseDN: "dc=example,dc=test", UsersDN: "ou=people,dc=example,dc=test", UserFilter: "(uid=custom)", StableIDAttribute: "entryUUID", UsernameAttribute: "uid"}
	if err := repo.UpsertDraft(context.Background(), seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	deps := buildIdentityDeps(pool)
	deps.DirectorySourceRepo = repo
	deps.DirectoryTargetPolicy = approvedDirectoryPolicy(t)
	body, err := json.Marshal(map[string]any{"kind": "ldap", "display_name": "LDAP", "connection_url": seed.ConnectionURL, "bind_dn": seed.BindDN, "base_dn": seed.BaseDN, "users_dn": seed.UsersDN, "ca_cert_pem": "", "version": seed.Version})
	if err != nil {
		t.Fatalf("marshal update: %v", err)
	}
	response := httptest.NewRecorder()
	SaveDirectoryDraft(deps)(response, withOrgUserCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/directory/sources/draft", bytes.NewReader(body)), tenantID, userID))
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
	}
	updated, err := repo.GetDraft(context.Background(), tenantID)
	if err != nil || updated == nil || updated.CACertPEM != seed.CACertPEM {
		t.Fatalf("empty CA must preserve existing CA: draft=%#v err=%v", updated, err)
	}
	if strings.Contains(response.Body.String(), seed.CACertPEM) {
		t.Fatal("response leaked CA")
	}
	_, newTenantID, newUserID := setupOrgHandlerPool(t)
	newBody, err := json.Marshal(map[string]any{"kind": "ldap", "display_name": "New LDAP", "connection_url": "ldaps://ldap-sim.jjdguard.test:636", "bind_dn": "cn=new", "bind_password": "directory-secret", "base_dn": "dc=example,dc=test", "users_dn": "ou=people,dc=example,dc=test", "ca_cert_pem": ""})
	if err != nil {
		t.Fatalf("marshal create: %v", err)
	}
	newResponse := httptest.NewRecorder()
	SaveDirectoryDraft(deps)(newResponse, withOrgUserCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/directory/sources/draft", bytes.NewReader(newBody)), newTenantID, newUserID))
	if newResponse.Code != http.StatusOK {
		t.Fatalf("new empty CA status=%d body=%s", newResponse.Code, newResponse.Body.String())
	}
	created, err := repo.GetDraft(context.Background(), newTenantID)
	if err != nil || created == nil || created.CACertPEM != "" {
		t.Fatalf("new empty CA not allowed: draft=%#v err=%v", created, err)
	}
}

func TestDirectoryAuditDetailRedactsDirectoryConfiguration(t *testing.T) {
	source := &repository.DirectorySource{
		ID: "source-1", ConnectionURL: "ldaps://directory.internal.test:636",
		BindDN:          "cn=directory-reader,dc=internal,dc=test",
		BindPasswordEnc: "encrypted-password", UserFilter: "(uid=alice)",
		Version: 7,
	}

	detail := directoryAuditDetail(source, map[string]any{"success": true})
	for _, forbidden := range []string{"connection_url", "host", "bind_dn", "bind_password", "bind_password_enc", "user_filter"} {
		if _, found := detail[forbidden]; found {
			t.Fatalf("directory audit detail leaked %q: %#v", forbidden, detail)
		}
	}
	if detail["source_id"] != source.ID || detail["config_version"] != source.Version {
		t.Fatalf("directory audit detail missing stable metadata: %#v", detail)
	}
}

// Existing drafts can predate a target-policy change. Every LDAP operation must
// re-check the approved deployment target before decrypting credentials or
// reaching the directory client.
func TestDirectoryOperationsRejectTargetOutsideApprovedPolicy(t *testing.T) {
	for _, operation := range []struct {
		name string
		h    func(*Dependencies) http.HandlerFunc
	}{
		{name: "connection test", h: TestDirectoryConnection},
	} {
		t.Run(operation.name, func(t *testing.T) {
			pool, tenantID, userID := setupOrgHandlerPool(t)
			setupIdentitySecretKey(t)
			sourceRepo := repository.NewDirectorySourceRepository(pool)
			encryptedPassword, _, err := secrets.EncryptProviderSecret("directory-secret")
			if err != nil {
				t.Fatalf("encrypt bind password: %v", err)
			}
			source := &repository.DirectorySource{
				TenantID: tenantID, Kind: repository.DirectoryKindLDAP, DisplayName: "unapproved LDAP",
				ConnectionURL: "ldaps://unapproved.example.test:636", BindDN: "cn=reader",
				BindPasswordEnc: encryptedPassword, BaseDN: "dc=example,dc=test", UsersDN: "ou=people,dc=example,dc=test",
				StableIDAttribute: "entryUUID", UsernameAttribute: "uid",
			}
			if err := sourceRepo.UpsertDraft(context.Background(), source); err != nil {
				t.Fatalf("seed source: %v", err)
			}

			tester := &recordingDirectoryTester{}
			deps := buildIdentityDeps(pool)
			deps.DirectorySourceRepo = sourceRepo
			deps.DirectoryTester = tester
			deps.DirectoryTargetPolicy = approvedDirectoryPolicy(t)
			deps.UserRepo = repository.NewUserRepository(pool)
			request := withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/directory/sources/operation", nil), tenantID, userID)
			response := httptest.NewRecorder()

			operation.h(deps)(response, request)

			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_request") {
				t.Fatalf("status=%d body=%s, want stable invalid_request", response.Code, response.Body.String())
			}
			if tester.testCalls != 0 || tester.listCalls != 0 {
				t.Fatalf("unapproved target reached LDAP client: test=%d list=%d", tester.testCalls, tester.listCalls)
			}
		})
	}
}

type recordingDirectorySystemRepo struct {
	orgTestSystemRepo
	last *repository.AuditOperation
}

func (repo *recordingDirectorySystemRepo) CreateAuditOperation(_ context.Context, operation *repository.AuditOperation) error {
	repo.last = operation
	return nil
}

func TestDirectoryConnectionDoesNotReflectDirectoryConfiguration(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	sourceRepo := repository.NewDirectorySourceRepository(pool)
	encryptedPassword, _, err := secrets.EncryptProviderSecret("directory-secret")
	if err != nil {
		t.Fatalf("encrypt bind password: %v", err)
	}
	source := &repository.DirectorySource{
		TenantID: tenantID, Kind: repository.DirectoryKindLDAP, DisplayName: "LDAP",
		ConnectionURL: "ldaps://ldap-sim.jjdguard.test:636", BindDN: "cn=restricted-reader,dc=jjdguard,dc=test",
		BindPasswordEnc: encryptedPassword, BaseDN: "dc=jjdguard,dc=test", UsersDN: "ou=people,dc=jjdguard,dc=test",
		UserFilter: "(uid=restricted-reader)", StableIDAttribute: "entryUUID", UsernameAttribute: "uid",
	}
	if err := sourceRepo.UpsertDraft(context.Background(), source); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	tester := &recordingDirectoryTester{}
	auditRepo := &recordingDirectorySystemRepo{}
	deps := buildIdentityDeps(pool)
	deps.DirectorySourceRepo = sourceRepo
	deps.DirectoryTester = tester
	deps.DirectoryTargetPolicy = approvedDirectoryPolicy(t)
	deps.SystemRepo = auditRepo
	request := withOrgUserCtx(httptest.NewRequest(http.MethodPost, "/admin/v1/directory/sources/test", nil), tenantID, userID)
	response := httptest.NewRecorder()

	TestDirectoryConnection(deps)(response, request)

	if response.Code != http.StatusOK || tester.testCalls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, tester.testCalls, response.Body.String())
	}
	if auditRepo.last == nil {
		t.Fatal("directory connection test did not write audit entry")
	}
	auditJSON, err := json.Marshal(auditRepo.last.ActionDetail)
	if err != nil {
		t.Fatalf("marshal audit detail: %v", err)
	}
	for _, secret := range []string{source.ConnectionURL, source.BindDN, source.UserFilter, "directory-secret", source.BindPasswordEnc} {
		if strings.Contains(response.Body.String(), secret) || strings.Contains(string(auditJSON), secret) {
			t.Fatalf("directory configuration reflected in response or audit detail: %q", secret)
		}
	}
}

func testApprovedDirectoryPolicy() (directoryldap.TargetPolicy, error) {
	policy, err := directoryldap.ParseTargetPolicy("ldap-sim.jjdguard.test:636", "10.20.0.0/16")
	if err != nil {
		return directoryldap.TargetPolicy{}, err
	}
	return policy.WithResolver(approvedDirectoryResolver{}), nil
}

func TestSaveDirectoryDraftReportsUnapprovedTargetSeparately(t *testing.T) {
	policy := approvedDirectoryPolicy(t)
	source := &repository.DirectorySource{
		Kind:          repository.DirectoryKindLDAP,
		DisplayName:   "模拟目录",
		ConnectionURL: "ldaps://dc-sim.ad.jjdguard.test:636",
		BindDN:        "cn=reader,dc=example,dc=test",
		BaseDN:        "dc=example,dc=test",
		UsersDN:       "ou=people,dc=example,dc=test",
	}

	err := (saveDirectoryDraftRequest{}).validate(context.Background(), policy, source)
	if err == nil || err.Error() != "目录连接地址未被当前部署批准" {
		t.Fatalf("validate error=%v, want unapproved-target message", err)
	}
}
