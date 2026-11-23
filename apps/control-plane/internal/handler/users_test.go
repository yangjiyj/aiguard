package handler

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type handlerLocalIdentityClient struct {
	events    *[]string
	createOut string
	createErr error
	deleteErr error
}

func (c *handlerLocalIdentityClient) CreateUser(_ context.Context, _ localidentity.CreateUserInput) (string, error) {
	*c.events = append(*c.events, "keycloak.create.disabled")
	return c.createOut, c.createErr
}

func (c *handlerLocalIdentityClient) SetEnabled(_ context.Context, _ string, enabled bool) error {
	if enabled {
		*c.events = append(*c.events, "keycloak.enable")
	} else {
		*c.events = append(*c.events, "keycloak.disable")
	}
	return nil
}

func (c *handlerLocalIdentityClient) ResetPassword(context.Context, string, string, bool) error {
	return nil
}

func (c *handlerLocalIdentityClient) DeleteUser(_ context.Context, _ string) error {
	*c.events = append(*c.events, "keycloak.delete")
	return c.deleteErr
}

type handlerIdentityLinkLookup struct {
	events *[]string
	err    error
}

func (l *handlerIdentityLinkLookup) HasExternalCredentialOwner(context.Context, string, string) (bool, error) {
	return false, l.err
}

func (l *handlerIdentityLinkLookup) BindLoginSources(_ context.Context, _, _, _, _ string) error {
	*l.events = append(*l.events, "database.bind_login_sources")
	return l.err
}

type handlerLocalIdentityProvisioner struct {
	events         *[]string
	provisioned    localidentity.ProvisionInput
	reconciliation *localidentity.ReconciliationInput
	provisionErr   error
	markErr        error
}

func (p *handlerLocalIdentityProvisioner) Provision(_ context.Context, in localidentity.ProvisionInput) error {
	*p.events = append(*p.events, "database.provision")
	p.provisioned = in
	return p.provisionErr
}

func (p *handlerLocalIdentityProvisioner) Activate(_ context.Context, _, _ string) error {
	*p.events = append(*p.events, "database.activate")
	return nil
}

func (p *handlerLocalIdentityProvisioner) MarkReconciliationRequired(
	_ context.Context,
	in localidentity.ReconciliationInput,
) error {
	*p.events = append(*p.events, "database.reconciliation_required")
	p.reconciliation = &in
	return p.markErr
}

func (p *handlerLocalIdentityProvisioner) DeleteProvisioned(context.Context, string, string) error {
	return nil
}

func (p *handlerLocalIdentityProvisioner) ExternalSubject(context.Context, string, string) (string, error) {
	return "", localidentity.ErrNotFound
}

func (p *handlerLocalIdentityProvisioner) UpdatePasswordHash(context.Context, string, string, string, bool) error {
	return nil
}

type handlerDepartmentStore struct {
	departments map[string]*repository.Team
}

func (s *handlerDepartmentStore) GetByID(_ context.Context, id string) (*repository.Team, error) {
	return s.departments[id], nil
}

func createUserRequest(body string) *http.Request {
	return platformAdminContext(httptest.NewRequest(http.MethodPost, "/admin/v1/users", strings.NewReader(body)))
}

func TestCreateUserRequiresDepartmentForBusinessUser(t *testing.T) {
	events := []string{}
	deps := &Dependencies{
		LocalIdentityClient: &handlerLocalIdentityClient{events: &events, createOut: "subject-1"},
	}
	w := httptest.NewRecorder()

	CreateUser(deps).ServeHTTP(w, createUserRequest(`{"username":"alice","password":"initial-password","role":"viewer"}`))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if len(events) != 0 {
		t.Fatalf("side effects before department validation: %v", events)
	}
}

func TestCreateUserHidesCrossTenantDepartment(t *testing.T) {
	events := []string{}
	deps := &Dependencies{
		DepartmentStore: &handlerDepartmentStore{departments: map[string]*repository.Team{
			"dept-other": {ID: "dept-other", TenantID: "tenant-other", Name: "??????"},
		}},
		LocalIdentityClient: &handlerLocalIdentityClient{events: &events, createOut: "subject-1"},
	}
	w := httptest.NewRecorder()

	CreateUser(deps).ServeHTTP(w, createUserRequest(`{"username":"alice","password":"initial-password","role":"viewer","department_id":"dept-other"}`))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "??????") || strings.Contains(w.Body.String(), "tenant-other") {
		t.Fatalf("cross-tenant department leaked: %s", w.Body.String())
	}
}

func TestCreateUserAllowsEmergencyAdminWithoutDepartment(t *testing.T) {
	events := []string{}
	provisioner := &handlerLocalIdentityProvisioner{events: &events}
	deps := &Dependencies{LocalIdentityProvisioner: provisioner}
	w := httptest.NewRecorder()

	CreateUser(deps).ServeHTTP(w, createUserRequest(`{"username":"breakglass","password":"initial-password","role":"platform_admin"}`))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if provisioner.provisioned.AssignmentMode != "emergency" || provisioner.provisioned.DepartmentID != "" {
		t.Fatalf("provisioned emergency assignment = %+v", provisioner.provisioned)
	}
	if len(events) != 1 || events[0] != "database.provision" {
		t.Fatalf("emergency admin must not reach Keycloak: %v", events)
	}
}

func TestCreateUserActivatesIdentityOnlyAfterDatabaseProvision(t *testing.T) {
	events := []string{}
	client := &handlerLocalIdentityClient{events: &events, createOut: "subject-1"}
	provisioner := &handlerLocalIdentityProvisioner{events: &events}
	deps := &Dependencies{
		DepartmentStore: &handlerDepartmentStore{departments: map[string]*repository.Team{
			"dept-1": {ID: "dept-1", TenantID: "tenant-1", Name: "???"},
		}},
		LocalIdentityClient: client, LocalIdentityProvisioner: provisioner,
		UserIdentityLinkLookup: &handlerIdentityLinkLookup{events: &events},
		IdentityRuntimeConfig:  IdentityRuntimeConfig{IssuerURL: "https://sso.example.test/sso/realms/jjdguard"},
	}
	w := httptest.NewRecorder()

	CreateUser(deps).ServeHTTP(w, createUserRequest(`{"username":"alice","password":"initial-password","role":"viewer","department_id":"dept-1"}`))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	want := []string{"keycloak.create.disabled", "database.provision", "keycloak.enable", "database.activate", "database.bind_login_sources"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", events, want)
	}
	if provisioner.provisioned.ExternalSubject != "subject-1" ||
		provisioner.provisioned.DepartmentID != "dept-1" ||
		provisioner.provisioned.AssignmentMode != "manual" ||
		provisioner.provisioned.Status != "provisioning" {
		t.Fatalf("provision input = %+v", provisioner.provisioned)
	}
	for _, forbidden := range []string{"initial-password", "subject-1", "credential"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, w.Body.String())
		}
	}
}

func TestCreateUserDeletesDisabledIdentityWhenDatabaseProvisionFails(t *testing.T) {
	events := []string{}
	client := &handlerLocalIdentityClient{events: &events, createOut: "subject-1"}
	provisioner := &handlerLocalIdentityProvisioner{events: &events, provisionErr: errors.New("database unavailable")}
	deps := &Dependencies{
		DepartmentStore: &handlerDepartmentStore{departments: map[string]*repository.Team{
			"dept-1": {ID: "dept-1", TenantID: "tenant-1", Name: "???"},
		}},
		LocalIdentityClient: client, LocalIdentityProvisioner: provisioner,
	}
	w := httptest.NewRecorder()

	CreateUser(deps).ServeHTTP(w, createUserRequest(`{"username":"alice","password":"initial-password","role":"viewer","department_id":"dept-1"}`))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", w.Code, w.Body.String())
	}
	want := []string{"keycloak.create.disabled", "database.provision", "keycloak.delete"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestCreateUserMarksReconciliationWhenCompensationFails(t *testing.T) {
	events := []string{}
	client := &handlerLocalIdentityClient{
		events: &events, createOut: "subject-sensitive",
		deleteErr: errors.New("runtime body admin-token credential-id"),
	}
	provisioner := &handlerLocalIdentityProvisioner{events: &events, provisionErr: errors.New("database unavailable")}
	deps := &Dependencies{
		DepartmentStore: &handlerDepartmentStore{departments: map[string]*repository.Team{
			"dept-1": {ID: "dept-1", TenantID: "tenant-1", Name: "???"},
		}},
		LocalIdentityClient: client, LocalIdentityProvisioner: provisioner,
	}
	w := httptest.NewRecorder()

	CreateUser(deps).ServeHTTP(w, createUserRequest(`{"username":"alice","password":"initial-password","role":"viewer","department_id":"dept-1"}`))

	if provisioner.reconciliation == nil || provisioner.reconciliation.UserID == "" {
		t.Fatalf("reconciliation marker missing: events=%v", events)
	}
	for _, forbidden := range []string{"initial-password", "subject-sensitive", "admin-token", "credential-id"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, w.Body.String())
		}
	}
}

func TestCreateUserReturnsSafeErrorWhenReconciliationMarkerFails(t *testing.T) {
	events := []string{}
	client := &handlerLocalIdentityClient{
		events: &events, createOut: "subject-sensitive",
		deleteErr: errors.New("runtime secret"),
	}
	provisioner := &handlerLocalIdentityProvisioner{
		events: &events, provisionErr: errors.New("database secret"),
		markErr: errors.New("marker secret"),
	}
	deps := &Dependencies{
		DepartmentStore: &handlerDepartmentStore{departments: map[string]*repository.Team{
			"dept-1": {ID: "dept-1", TenantID: "tenant-1", Name: "Engineering"},
		}},
		LocalIdentityClient: client, LocalIdentityProvisioner: provisioner,
	}
	w := httptest.NewRecorder()

	CreateUser(deps).ServeHTTP(w, createUserRequest(`{"username":"alice","password":"initial-password","role":"viewer","department_id":"dept-1"}`))

	if w.Code != http.StatusServiceUnavailable || decodeErrorCode(t, w.Body.String()) != "reconciliation_persistence_failed" {
		t.Fatalf("status=%d body=%s events=%v", w.Code, w.Body.String(), events)
	}
	wantFingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte("tenant-1|subject-sensitive")))
	got := provisioner.reconciliation
	if got == nil || got.SubjectFingerprint != wantFingerprint || got.Operation != "provision" ||
		got.Stage != "database_provision_failed_identity_delete_failed" ||
		got.Provider != "keycloak" || got.Source != "local" {
		t.Fatalf("reconciliation=%+v want fingerprint=%s", got, wantFingerprint)
	}
	for _, secret := range []string{"database secret", "runtime secret", "marker secret", "subject-sensitive", "initial-password"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("response leaked %q: %s", secret, w.Body.String())
		}
	}
}

func TestCreateUserFailsClosedWhenLocalIdentityIsNotConfigured(t *testing.T) {
	events := []string{}
	deps := &Dependencies{
		DepartmentStore: &handlerDepartmentStore{departments: map[string]*repository.Team{
			"dept-1": {ID: "dept-1", TenantID: "tenant-1", Name: "???"},
		}},
		LocalIdentityProvisioner: &handlerLocalIdentityProvisioner{events: &events},
	}
	w := httptest.NewRecorder()

	CreateUser(deps).ServeHTTP(w, createUserRequest(`{"username":"alice","password":"initial-password","role":"viewer","department_id":"dept-1"}`))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "local_identity_unavailable") ||
		!strings.Contains(w.Body.String(), "本地身份服务尚未就绪") ||
		!strings.Contains(w.Body.String(), "重新执行身份初始化") {
		t.Fatalf("response is not actionable Chinese guidance: %s", w.Body.String())
	}
}

func TestCreateConnectorUsesNativeIdentityOnly(t *testing.T) {
	events := []string{}
	provisioner := &handlerLocalIdentityProvisioner{events: &events}
	deps := &Dependencies{NativeServiceProvisioner: provisioner}
	w := httptest.NewRecorder()
	CreateUser(deps).ServeHTTP(w, createUserRequest(`{"username":"connector","password":"test-only-random-password","role":"platform_connector"}`))
	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	in := provisioner.provisioned
	if in.Role != "platform_connector" || in.Status != "active" || in.AssignmentMode != "service" || in.DepartmentID != "" || in.ExternalSubject != "" || in.TenantID != "tenant-1" {
		t.Fatalf("unexpected service provision input: role=%s mode=%s tenant=%s", in.Role, in.AssignmentMode, in.TenantID)
	}
	if len(events) != 1 || events[0] != "database.provision" {
		t.Fatalf("machine identity contacted human SSO: %v", events)
	}
}
func TestCreateConnectorRejectsForeignTenantOrHumanDepartment(t *testing.T) {
	for _, body := range []string{`{"username":"connector","password":"test-only","role":"platform_connector","tenant_id":"foreign"}`, `{"username":"connector","password":"test-only","role":"platform_connector","department_id":"dept-1"}`} {
		events := []string{}
		w := httptest.NewRecorder()
		CreateUser(&Dependencies{NativeServiceProvisioner: &handlerLocalIdentityProvisioner{events: &events}}).ServeHTTP(w, createUserRequest(body))
		if w.Code != 403 || len(events) != 0 {
			t.Fatalf("invalid service scope status=%d side-effects=%v", w.Code, events)
		}
	}
}
