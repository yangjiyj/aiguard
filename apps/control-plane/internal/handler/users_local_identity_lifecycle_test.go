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
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type lifecycleUserStore struct {
	events    *[]string
	user      *repository.User
	updateErr error
}

func (s *lifecycleUserStore) GetByID(context.Context, string) (*repository.User, error) {
	copy := *s.user
	return &copy, nil
}
func (s *lifecycleUserStore) ListAllWithStats(context.Context) ([]*repository.UserWithStats, error) {
	return nil, nil
}
func (s *lifecycleUserStore) Create(context.Context, *repository.User) error { return nil }
func (s *lifecycleUserStore) Update(_ context.Context, user *repository.User) error {
	*s.events = append(*s.events, "database.status_fallback."+user.Status)
	if s.updateErr != nil {
		return s.updateErr
	}
	*s.user = *user
	return nil
}

type lifecycleIdentityClient struct {
	events    *[]string
	setErr    error
	setErrors []error
	resetErr  error
	resetSeen bool
	resetTemp bool
	createOut string
	createErr error
	created   localidentity.CreateUserInput
}

func (c *lifecycleIdentityClient) CreateUser(_ context.Context, in localidentity.CreateUserInput) (string, error) {
	*c.events = append(*c.events, "keycloak.create.disabled")
	c.created = in
	return c.createOut, c.createErr
}
func (c *lifecycleIdentityClient) SetEnabled(_ context.Context, _ string, enabled bool) error {
	if enabled {
		*c.events = append(*c.events, "keycloak.enable")
	} else {
		*c.events = append(*c.events, "keycloak.disable")
	}
	if len(c.setErrors) > 0 {
		err := c.setErrors[0]
		c.setErrors = c.setErrors[1:]
		return err
	}
	return c.setErr
}
func (c *lifecycleIdentityClient) ResetPassword(_ context.Context, _, _ string, temporary bool) error {
	*c.events = append(*c.events, "keycloak.reset_password")
	c.resetSeen = true
	c.resetTemp = temporary
	return c.resetErr
}
func (c *lifecycleIdentityClient) DeleteUser(context.Context, string) error {
	*c.events = append(*c.events, "keycloak.delete")
	return nil
}

type lifecycleProvisioner struct {
	events         *[]string
	subject        string
	subjectErr     error
	mustChange     bool
	demotionErr    error
	demotion       localidentity.EmergencyDemotionInput
	status         localidentity.StatusTransitionInput
	statusErr      error
	statusUser     *repository.User
	passwordErr    error
	markErr        error
	reconciliation localidentity.ReconciliationInput
}

func (*lifecycleProvisioner) Provision(context.Context, localidentity.ProvisionInput) error {
	return nil
}
func (*lifecycleProvisioner) Activate(context.Context, string, string) error { return nil }
func (p *lifecycleProvisioner) MarkReconciliationRequired(_ context.Context, in localidentity.ReconciliationInput) error {
	*p.events = append(*p.events, "database.reconciliation_required")
	p.reconciliation = in
	return p.markErr
}
func (*lifecycleProvisioner) DeleteProvisioned(context.Context, string, string) error { return nil }
func (p *lifecycleProvisioner) ExternalSubject(context.Context, string, string) (string, error) {
	return p.subject, p.subjectErr
}
func (p *lifecycleProvisioner) UpdatePasswordHash(_ context.Context, _, _, _ string, mustChange bool) error {
	*p.events = append(*p.events, "database.password_hash")
	p.mustChange = mustChange
	return p.passwordErr
}
func (p *lifecycleProvisioner) BindEmergencyIdentityAndTransition(_ context.Context, in localidentity.EmergencyDemotionInput) error {
	*p.events = append(*p.events, "database.bind_and_role."+in.Role)
	p.demotion = in
	return p.demotionErr
}
func (p *lifecycleProvisioner) TransitionStatus(_ context.Context, in localidentity.StatusTransitionInput) error {
	*p.events = append(*p.events, "database.status."+in.Status)
	p.status = in
	if p.statusErr != nil {
		return p.statusErr
	}
	if p.statusUser != nil {
		p.statusUser.Status = in.Status
	}
	return nil
}

type lifecycleIdentityLinkLookup struct {
	managed bool
	err     error
}

func (l lifecycleIdentityLinkLookup) HasExternalCredentialOwner(context.Context, string, string) (bool, error) {
	return l.managed, l.err
}

func (l lifecycleIdentityLinkLookup) BindLoginSources(context.Context, string, string, string, string) error {
	return l.err
}

type lifecycleSessionStore struct {
	events    *[]string
	deleteErr error
}

func (*lifecycleSessionStore) Create(context.Context, *repository.Session) error { return nil }
func (*lifecycleSessionStore) Delete(context.Context, string) error              { return nil }
func (s *lifecycleSessionStore) DeleteByUser(context.Context, string) error {
	*s.events = append(*s.events, "sessions.revoke")
	return s.deleteErr
}

type lifecycleRoleBindingService struct {
	*departmentAssignmentService
	events *[]string
	err    error
}

func (s *lifecycleRoleBindingService) TransitionPlatformRole(
	_ context.Context,
	tenantID, userID, role, departmentID, actorID string,
) error {
	*s.events = append(*s.events, "database.role."+role)
	if s.departmentAssignmentService != nil {
		s.tenantID = tenantID
		s.userID = userID
		s.departmentID = departmentID
		s.actorID = actorID
	}
	return s.err
}

type lifecyclePermissionChecker struct{ events *[]string }

func (*lifecyclePermissionChecker) HasPermission(
	context.Context,
	string, string, string, string, string, string,
) (bool, error) {
	return true, nil
}
func (p *lifecyclePermissionChecker) InvalidateUserCache(string) {
	*p.events = append(*p.events, "permission.invalidate")
}

func lifecycleRequest(method, body string) *http.Request {
	r := platformAdminContext(httptest.NewRequest(method, "/admin/v1/users/user-1", strings.NewReader(body)))
	route := chi.NewRouteContext()
	route.URLParams.Add("id", "user-1")
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
}

func lifecycleDependencies(events *[]string, client *lifecycleIdentityClient) *Dependencies {
	user := &repository.User{
		ID: "user-1", TenantID: "tenant-1", Username: "alice",
		Role: "viewer", Status: "active", DepartmentAssignmentMode: "manual",
		DepartmentAssignmentSource: "local",
	}
	return &Dependencies{
		UserStore:                &lifecycleUserStore{events: events, user: user},
		SessionRepo:              &lifecycleSessionStore{events: events},
		LocalIdentityClient:      client,
		LocalIdentityProvisioner: &lifecycleProvisioner{events: events, subject: "subject-sensitive", statusUser: user},
	}
}

func lifecycleRoleDependencies(events *[]string, client *lifecycleIdentityClient) *Dependencies {
	deps := lifecycleDependencies(events, client)
	deps.IdentityBindingService = &lifecycleRoleBindingService{
		departmentAssignmentService: &departmentAssignmentService{}, events: events,
	}
	deps.PermissionChecker = &lifecyclePermissionChecker{events: events}
	return deps
}

func TestToggleUserStatusDisablesRuntimeBeforeSessionsAndDatabase(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"disabled"}`))
	if w.Code != http.StatusOK || strings.Join(events, ",") != "keycloak.disable,sessions.revoke,database.status.disabled" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
}

func TestToggleUserStatusUsesTransactionalLifecyclePersistence(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"disabled"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	provisioner := deps.LocalIdentityProvisioner.(*lifecycleProvisioner)
	if provisioner.status.TenantID != "tenant-1" || provisioner.status.UserID != "user-1" ||
		provisioner.status.Status != "disabled" || provisioner.status.ActorID != "admin-1" {
		t.Fatalf("status transition input=%+v", provisioner.status)
	}
	if strings.Join(events, ",") != "keycloak.disable,sessions.revoke,database.status.disabled" {
		t.Fatalf("events=%v", events)
	}
	if deps.UserStore.(*lifecycleUserStore).updateErr != nil {
		t.Fatal("unexpected legacy store state")
	}
}

func TestToggleUserStatusKeepsRuntimeDisabledWhenSessionRevokeFails(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	deps.SessionRepo = &lifecycleSessionStore{events: &events, deleteErr: errors.New("session secret")}
	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"disabled"}`))

	if w.Code != http.StatusBadGateway || strings.Join(events, ",") !=
		"keycloak.disable,sessions.revoke,database.status.disabled,database.reconciliation_required" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	if got := deps.UserStore.(*lifecycleUserStore).user.Status; got != "disabled" {
		t.Fatalf("user status=%q want disabled", got)
	}
	got := deps.LocalIdentityProvisioner.(*lifecycleProvisioner).reconciliation
	if got.Operation != "status_transition" || got.Stage != "session_revoke_failed_identity_disabled" {
		t.Fatalf("reconciliation=%+v", got)
	}
	if strings.Contains(w.Body.String(), "session secret") {
		t.Fatalf("response leaked session error: %s", w.Body.String())
	}
}

func TestToggleEmergencyUserStatusDisablesDatabaseWhenSessionRevokeFails(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	user := deps.UserStore.(*lifecycleUserStore).user
	user.Role = "platform_admin"
	user.DepartmentAssignmentMode = "emergency"
	deps.SessionRepo = &lifecycleSessionStore{events: &events, deleteErr: errors.New("session secret")}
	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"disabled"}`))

	if w.Code != http.StatusBadGateway || strings.Join(events, ",") !=
		"sessions.revoke,database.status.disabled,database.reconciliation_required" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	if user.Status != "disabled" {
		t.Fatalf("user status=%q want disabled", user.Status)
	}
	got := deps.LocalIdentityProvisioner.(*lifecycleProvisioner).reconciliation
	if got.SubjectFingerprint != "" || got.Operation != "status_transition" ||
		got.Stage != "session_revoke_failed_identity_disabled" ||
		got.Provider != "local" || got.Source != "local" {
		t.Fatalf("reconciliation=%+v", got)
	}
	if strings.Contains(w.Body.String(), "session secret") || strings.Contains(w.Body.String(), user.ID) {
		t.Fatalf("response leaked internal detail: %s", w.Body.String())
	}
}

func TestToggleEmergencyUserStatusFallsBackToDisabledWhenTransactionFails(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	user := deps.UserStore.(*lifecycleUserStore).user
	user.Role = "platform_admin"
	user.DepartmentAssignmentMode = "emergency"
	deps.LocalIdentityProvisioner.(*lifecycleProvisioner).statusErr = errors.New("database secret")
	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"disabled"}`))

	if w.Code != http.StatusBadRequest || strings.Join(events, ",") !=
		"sessions.revoke,database.status.disabled,database.status_fallback.disabled,database.reconciliation_required" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	if user.Status != "disabled" {
		t.Fatalf("user status=%q want disabled", user.Status)
	}
	got := deps.LocalIdentityProvisioner.(*lifecycleProvisioner).reconciliation
	if got.SubjectFingerprint != "" || got.Operation != "status_transition" ||
		got.Stage != "database_status_update_failed_identity_absent" ||
		got.Provider != "local" || got.Source != "local" {
		t.Fatalf("reconciliation=%+v", got)
	}
	if strings.Contains(w.Body.String(), "database secret") || strings.Contains(w.Body.String(), user.ID) {
		t.Fatalf("response leaked internal detail: %s", w.Body.String())
	}
}

func TestToggleEmergencyUserStatusFallsBackWhenSessionAndTransactionFail(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	user := deps.UserStore.(*lifecycleUserStore).user
	user.Role = "platform_admin"
	user.DepartmentAssignmentMode = "emergency"
	deps.SessionRepo = &lifecycleSessionStore{events: &events, deleteErr: errors.New("session secret")}
	deps.LocalIdentityProvisioner.(*lifecycleProvisioner).statusErr = errors.New("database secret")
	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"disabled"}`))

	if w.Code != http.StatusBadRequest || strings.Join(events, ",") !=
		"sessions.revoke,database.status.disabled,database.status_fallback.disabled,database.reconciliation_required" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	if user.Status != "disabled" {
		t.Fatalf("user status=%q want disabled", user.Status)
	}
	got := deps.LocalIdentityProvisioner.(*lifecycleProvisioner).reconciliation
	if got.Stage != "session_revoke_and_database_status_update_failed_identity_absent" ||
		got.Provider != "local" || got.SubjectFingerprint != "" {
		t.Fatalf("reconciliation=%+v", got)
	}
	for _, secret := range []string{"session secret", "database secret", user.ID} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("response leaked %q: %s", secret, w.Body.String())
		}
	}
}

func TestToggleUserStatusKeepsRuntimeDisabledWhenDatabaseTransitionFails(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	deps.LocalIdentityProvisioner.(*lifecycleProvisioner).statusErr = errors.New("database secret")
	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"disabled"}`))

	if w.Code != http.StatusBadRequest || strings.Join(events, ",") !=
		"keycloak.disable,sessions.revoke,database.status.disabled,database.reconciliation_required" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	got := deps.LocalIdentityProvisioner.(*lifecycleProvisioner).reconciliation
	if got.Operation != "status_transition" || got.Stage != "database_status_update_failed_identity_disabled" {
		t.Fatalf("reconciliation=%+v", got)
	}
	if strings.Contains(w.Body.String(), "database secret") {
		t.Fatalf("response leaked database error: %s", w.Body.String())
	}
}

func TestToggleUserStatusFailsClosedWhenRuntimeDisableFails(t *testing.T) {
	events := []string{}
	client := &lifecycleIdentityClient{events: &events, setErr: errors.New("runtime failure token")}
	deps := lifecycleDependencies(&events, client)
	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"disabled"}`))
	if w.Code != http.StatusBadGateway || strings.Join(events, ",") != "keycloak.disable" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("runtime detail leaked: %s", w.Body.String())
	}
}

func TestToggleUserStatusEnablesRuntimeBeforeDatabase(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	deps.UserStore.(*lifecycleUserStore).user.Status = "disabled"
	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"active"}`))
	if w.Code != http.StatusOK || strings.Join(events, ",") != "keycloak.enable,database.status.active" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
}

func TestToggleUserStatusDisablesRuntimeWhenDatabaseEnableFails(t *testing.T) {
	events := []string{}
	client := &lifecycleIdentityClient{events: &events, setErrors: []error{nil, nil}}
	deps := lifecycleDependencies(&events, client)
	store := deps.UserStore.(*lifecycleUserStore)
	store.user.Status = "disabled"
	deps.LocalIdentityProvisioner.(*lifecycleProvisioner).statusErr = errors.New("database unavailable")
	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"active"}`))
	if w.Code != http.StatusBadRequest ||
		strings.Join(events, ",") != "keycloak.enable,database.status.active,keycloak.disable" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
}

func TestToggleUserStatusMarksReconciliationWhenEnableCompensationFails(t *testing.T) {
	events := []string{}
	client := &lifecycleIdentityClient{
		events: &events, setErrors: []error{nil, errors.New("compensation unavailable")},
	}
	deps := lifecycleDependencies(&events, client)
	store := deps.UserStore.(*lifecycleUserStore)
	store.user.Status = "disabled"
	deps.LocalIdentityProvisioner.(*lifecycleProvisioner).statusErr = errors.New("database unavailable")
	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"active"}`))
	if w.Code != http.StatusBadRequest || strings.Join(events, ",") !=
		"keycloak.enable,database.status.active,keycloak.disable,database.reconciliation_required" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "compensation") || strings.Contains(w.Body.String(), "database unavailable") {
		t.Fatalf("internal detail leaked: %s", w.Body.String())
	}
}

func TestToggleUserStatusReturnsSafeErrorWhenReconciliationMarkerFails(t *testing.T) {
	events := []string{}
	client := &lifecycleIdentityClient{
		events: &events, setErrors: []error{nil, errors.New("compensation secret")},
	}
	deps := lifecycleDependencies(&events, client)
	store := deps.UserStore.(*lifecycleUserStore)
	store.user.Status = "disabled"
	provisioner := deps.LocalIdentityProvisioner.(*lifecycleProvisioner)
	provisioner.statusErr = errors.New("database secret")
	provisioner.markErr = errors.New("marker secret")
	w := httptest.NewRecorder()
	ToggleUserStatus(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"status":"active"}`))

	if w.Code != http.StatusServiceUnavailable || decodeErrorCode(t, w.Body.String()) != "reconciliation_persistence_failed" {
		t.Fatalf("status=%d body=%s events=%v", w.Code, w.Body.String(), events)
	}
	wantFingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte("tenant-1|subject-sensitive")))
	got := provisioner.reconciliation
	if got.SubjectFingerprint != wantFingerprint || got.Operation != "status_transition" ||
		got.Stage != "database_status_update_failed_identity_compensation_failed" ||
		got.Provider != "keycloak" || got.Source != "local" {
		t.Fatalf("reconciliation=%+v want fingerprint=%s", got, wantFingerprint)
	}
	if strings.Join(events, ",") !=
		"keycloak.enable,database.status.active,keycloak.disable,database.reconciliation_required" {
		t.Fatalf("events=%v", events)
	}
	for _, secret := range []string{"database secret", "compensation secret", "marker secret", "subject-sensitive"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("response leaked %q: %s", secret, w.Body.String())
		}
	}
}

func TestUpdateUserPromotesBusinessUserToEmergencyAfterRuntimeShutdown(t *testing.T) {
	events := []string{}
	deps := lifecycleRoleDependencies(&events, &lifecycleIdentityClient{events: &events})
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"role":"platform_admin"}`))
	if w.Code != http.StatusOK || strings.Join(events, ",") !=
		"keycloak.disable,sessions.revoke,database.role.platform_admin,permission.invalidate" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"department_assignment_mode":"emergency"`) ||
		strings.Contains(w.Body.String(), `"department_id"`) {
		t.Fatalf("promotion response=%s", w.Body.String())
	}
}

func TestUpdateUserPromotionStopsWhenRuntimeDisableFails(t *testing.T) {
	events := []string{}
	client := &lifecycleIdentityClient{events: &events, setErr: errors.New("runtime secret")}
	deps := lifecycleRoleDependencies(&events, client)
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"role":"platform_admin"}`))
	if w.Code != http.StatusBadGateway || strings.Join(events, ",") != "keycloak.disable" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
}

func TestUpdateUserPromotionKeepsRuntimeDisabledWhenSessionRevokeFails(t *testing.T) {
	events := []string{}
	client := &lifecycleIdentityClient{events: &events}
	deps := lifecycleRoleDependencies(&events, client)
	deps.SessionRepo = &lifecycleSessionStore{events: &events, deleteErr: errors.New("session database")}
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"role":"platform_admin"}`))
	if w.Code != http.StatusBadGateway || strings.Join(events, ",") !=
		"keycloak.disable,sessions.revoke,database.reconciliation_required" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	got := deps.LocalIdentityProvisioner.(*lifecycleProvisioner).reconciliation
	if got.Operation != "role_transition" || got.Stage != "role_transition_session_revoke_failed_identity_disabled" {
		t.Fatalf("reconciliation=%+v", got)
	}
}

func TestUpdateUserPromotionKeepsRuntimeDisabledWhenDatabaseTransitionFails(t *testing.T) {
	events := []string{}
	client := &lifecycleIdentityClient{events: &events}
	deps := lifecycleRoleDependencies(&events, client)
	deps.IdentityBindingService.(*lifecycleRoleBindingService).err = errors.New("database unavailable")
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"role":"platform_admin"}`))
	if w.Code != http.StatusBadGateway || strings.Join(events, ",") !=
		"keycloak.disable,sessions.revoke,database.role.platform_admin,database.reconciliation_required" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	got := deps.LocalIdentityProvisioner.(*lifecycleProvisioner).reconciliation
	if got.Operation != "role_transition" || got.Stage != "role_transition_database_failed_identity_disabled" {
		t.Fatalf("reconciliation=%+v", got)
	}
}

func TestUpdateUserReturnsSafeErrorWhenReconciliationMarkerFails(t *testing.T) {
	events := []string{}
	client := &lifecycleIdentityClient{events: &events}
	deps := lifecycleRoleDependencies(&events, client)
	deps.IdentityBindingService.(*lifecycleRoleBindingService).err = errors.New("database secret")
	provisioner := deps.LocalIdentityProvisioner.(*lifecycleProvisioner)
	provisioner.markErr = errors.New("marker secret")
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"role":"platform_admin"}`))

	if w.Code != http.StatusServiceUnavailable || decodeErrorCode(t, w.Body.String()) != "reconciliation_persistence_failed" {
		t.Fatalf("status=%d body=%s events=%v", w.Code, w.Body.String(), events)
	}
	wantFingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte("tenant-1|subject-sensitive")))
	got := provisioner.reconciliation
	if got.SubjectFingerprint != wantFingerprint || got.Operation != "role_transition" ||
		got.Stage != "role_transition_database_failed_identity_disabled" ||
		got.Provider != "keycloak" || got.Source != "local" {
		t.Fatalf("reconciliation=%+v want fingerprint=%s", got, wantFingerprint)
	}
	if strings.Join(events, ",") !=
		"keycloak.disable,sessions.revoke,database.role.platform_admin,database.reconciliation_required" {
		t.Fatalf("events=%v", events)
	}
	for _, secret := range []string{"database secret", "marker secret", "subject-sensitive"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("response leaked %q: %s", secret, w.Body.String())
		}
	}
}

func TestUpdateUserDemotionRequiresDepartmentBeforeSideEffects(t *testing.T) {
	events := []string{}
	deps := lifecycleRoleDependencies(&events, &lifecycleIdentityClient{events: &events})
	user := deps.UserStore.(*lifecycleUserStore).user
	user.Role = "platform_admin"
	user.DepartmentAssignmentMode = "emergency"
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"role":"viewer"}`))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "department_required") || len(events) != 0 {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
}

func TestUpdateUserDemotesEmergencyUserBeforeRuntimeEnable(t *testing.T) {
	events := []string{}
	deps := lifecycleRoleDependencies(&events, &lifecycleIdentityClient{events: &events})
	user := deps.UserStore.(*lifecycleUserStore).user
	user.Role = "platform_admin"
	user.DepartmentAssignmentMode = "emergency"
	deps.DepartmentStore = &handlerDepartmentStore{departments: map[string]*repository.Team{
		"dept-1": {ID: "dept-1", TenantID: "tenant-1", Name: "Engineering"},
	}}
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"role":"viewer","department_id":"dept-1"}`))
	if w.Code != http.StatusOK || strings.Join(events, ",") !=
		"sessions.revoke,database.role.viewer,permission.invalidate,keycloak.enable" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"department_name":"Engineering"`) ||
		!strings.Contains(w.Body.String(), `"department_assignment_mode":"manual"`) {
		t.Fatalf("demotion response=%s", w.Body.String())
	}
}

func TestUpdateUserDemotionKeepsRuntimeDisabledWhenEnableFails(t *testing.T) {
	events := []string{}
	client := &lifecycleIdentityClient{events: &events, setErr: errors.New("runtime unavailable")}
	deps := lifecycleRoleDependencies(&events, client)
	user := deps.UserStore.(*lifecycleUserStore).user
	user.Role = "platform_admin"
	user.DepartmentAssignmentMode = "emergency"
	deps.DepartmentStore = &handlerDepartmentStore{departments: map[string]*repository.Team{
		"dept-1": {ID: "dept-1", TenantID: "tenant-1", Name: "Engineering"},
	}}
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, lifecycleRequest(http.MethodPatch, `{"role":"viewer","department_id":"dept-1"}`))
	if w.Code != http.StatusBadGateway || strings.Join(events, ",") !=
		"sessions.revoke,database.role.viewer,permission.invalidate,keycloak.enable,database.reconciliation_required" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
}

func TestUpdateUserDemotesEmergencyUserByProvisioningMissingLocalIdentity(t *testing.T) {
	events := []string{}
	client := &lifecycleIdentityClient{events: &events, createOut: "new-local-subject"}
	deps := lifecycleRoleDependencies(&events, client)
	user := deps.UserStore.(*lifecycleUserStore).user
	user.Role = "platform_admin"
	user.DepartmentAssignmentMode = "emergency"
	provisioner := deps.LocalIdentityProvisioner.(*lifecycleProvisioner)
	provisioner.subject = ""
	provisioner.subjectErr = localidentity.ErrNotFound
	deps.DepartmentStore = &handlerDepartmentStore{departments: map[string]*repository.Team{
		"dept-1": {ID: "dept-1", TenantID: "tenant-1", Name: "Engineering"},
	}}

	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, lifecycleRequest(
		http.MethodPatch, `{"role":"viewer","department_id":"dept-1"}`,
	))

	if w.Code != http.StatusOK || strings.Join(events, ",") !=
		"keycloak.create.disabled,sessions.revoke,database.bind_and_role.viewer,permission.invalidate,keycloak.enable" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	if client.created.Username != user.Username || client.created.Password == "" || !client.created.Temporary {
		t.Fatalf("created local identity=%+v", client.created)
	}
	if provisioner.demotion.TenantID != user.TenantID || provisioner.demotion.UserID != user.ID ||
		provisioner.demotion.ExternalSubject != "new-local-subject" || provisioner.demotion.PasswordHash == "" ||
		provisioner.demotion.Role != "viewer" || provisioner.demotion.DepartmentID != "dept-1" ||
		provisioner.demotion.ActorID != "admin-1" {
		t.Fatalf("demotion input=%+v", provisioner.demotion)
	}
	if strings.Contains(w.Body.String(), "new-local-subject") ||
		strings.Contains(w.Body.String(), client.created.Password) ||
		strings.Contains(w.Body.String(), provisioner.demotion.PasswordHash) {
		t.Fatalf("response leaked generated credential: %s", w.Body.String())
	}
}

func TestUpdateUserDemotesEmergencyUserToDeptManagerWithoutCompensation(t *testing.T) {
	pool := setupTenantScopedDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "tenant_dept_manager_" + suffix
	actorID := "actor_dept_manager_" + suffix
	userID := "user_dept_manager_" + suffix
	departmentID := "dept_manager_" + suffix
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id,name,edition,status,is_test)
		VALUES ($1,$1,'enterprise','active',TRUE)
	`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO teams (id,tenant_id,name,path) VALUES ($1,$2,'Security',$3)
	`, departmentID, tenantID, "/"+departmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (
			id,tenant_id,username,password_hash,role,status,
			department_assignment_mode,department_assignment_source
		) VALUES
			($1,$3,$1,'actor-hash','platform_admin','active','emergency','local'),
			($2,$3,$2,'old-hash','platform_admin','active','emergency','admin')
	`, actorID, userID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO permission_grants (id,tenant_id,user_id,scope_type,scope_id,role,granted_by)
		VALUES ($1,$2,$3,'tenant',$2,'platform_admin',$4)
	`, "grant_"+userID, tenantID, userID, actorID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_operations WHERE tenant_id=$1`, tenantID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE tenant_id=$1`, tenantID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenantID)
	})

	events := []string{}
	client := &lifecycleIdentityClient{events: &events, createOut: "dept-manager-subject"}
	provisioner, err := localidentity.NewProvisioner(pool, "https://sso.example.test/sso/realms/jjdguard")
	if err != nil {
		t.Fatal(err)
	}
	deps := &Dependencies{
		UserStore:                repository.NewUserRepository(pool),
		DepartmentStore:          repository.NewTeamRepository(pool),
		SessionRepo:              &lifecycleSessionStore{events: &events},
		LocalIdentityClient:      client,
		LocalIdentityProvisioner: provisioner,
		IdentityBindingService:   &lifecycleRoleBindingService{events: &events},
		PermissionChecker:        &lifecyclePermissionChecker{events: &events},
	}
	req := httptest.NewRequest(http.MethodPatch, "/admin/v1/users/"+userID,
		strings.NewReader(`{"role":"dept_manager","department_id":"`+departmentID+`"}`))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: actorID, TenantID: tenantID, Role: "platform_admin", Status: "active",
	}))
	route := chi.NewRouteContext()
	route.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
	w := httptest.NewRecorder()
	UpdateUser(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK || strings.Join(events, ",") !=
		"keycloak.create.disabled,sessions.revoke,permission.invalidate,keycloak.enable" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	if strings.Contains(strings.Join(events, ","), "keycloak.delete") {
		t.Fatalf("stale role validation triggered compensation: %v", events)
	}
	var role, selectedDepartment, mode, subject, grantRole string
	if err := pool.QueryRow(ctx, `
		SELECT u.role,u.department_id,u.department_assignment_mode,l.external_subject
		FROM users u JOIN user_identity_links l ON l.tenant_id=u.tenant_id AND l.user_id=u.id
		WHERE u.tenant_id=$1 AND u.id=$2
	`, tenantID, userID).Scan(&role, &selectedDepartment, &mode, &subject); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT role FROM permission_grants
		WHERE tenant_id=$1 AND user_id=$2 AND scope_type='tenant' AND scope_id=$1
	`, tenantID, userID).Scan(&grantRole); err != nil {
		t.Fatal(err)
	}
	if role != "dept_manager" || grantRole != role || selectedDepartment != departmentID ||
		mode != "manual" || subject != "dept-manager-subject" {
		t.Fatalf("role=%q grant=%q department=%q mode=%q subject=%q",
			role, grantRole, selectedDepartment, mode, subject)
	}
}

func TestResetPasswordRequiresDurableStoreBeforeNativeMutation(t *testing.T) {
	events := []string{}
	client := &lifecycleIdentityClient{events: &events}
	deps := lifecycleDependencies(&events, client)
	response := httptest.NewRecorder()
	ResetPassword(deps)(response, lifecycleRequest(http.MethodPost, `{"password":"new-secret"}`))
	if response.Code != 503 || decodeErrorCode(t, response.Body.String()) != "password_sync_unavailable" || len(events) != 0 {
		t.Fatal("missing durable credential store allowed native mutation")
	}
}

func TestResetPasswordUsesIdentityLinkInsteadOfDepartmentAssignmentSource(t *testing.T) {
	e, u, admin, state := nativeAdminFixture(t, "success")
	if _, err := e.pool.Exec(context.Background(), "UPDATE users SET department_assignment_source='admin' WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	response := nativeAdminReset(t, e, u, admin)
	if response.Code != 200 || state.password != "Admin-Chosen-Horse-77" {
		t.Fatal("administrative department assignment hid native credential ownership")
	}
}

func TestResetPasswordTakesOverLocalCredentialWhenRuntimeBindingIsAbsent(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	deps.UserStore.(*lifecycleUserStore).user.DepartmentAssignmentSource = "migration"
	deps.LocalIdentityProvisioner.(*lifecycleProvisioner).subjectErr = localidentity.ErrNotFound

	w := httptest.NewRecorder()
	ResetPassword(deps).ServeHTTP(w, lifecycleRequest(http.MethodPost, `{"password":"new-secret"}`))

	if w.Code != http.StatusOK || strings.Join(events, ",") != "database.password_hash,sessions.revoke" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	if deps.LocalIdentityProvisioner.(*lifecycleProvisioner).mustChange {
		t.Fatal("administrator reset must immediately establish the final JJDGuard password")
	}
	for _, secret := range []string{"new-secret", "subject-sensitive"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("response leaked %q: %s", secret, w.Body.String())
		}
	}
}

func TestResetPasswordRejectsLDAPOrADCredentialOwner(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	deps.UserIdentityLinkLookup = lifecycleIdentityLinkLookup{managed: true}
	deps.LocalIdentityProvisioner.(*lifecycleProvisioner).subjectErr = localidentity.ErrNotFound

	w := httptest.NewRecorder()
	ResetPassword(deps).ServeHTTP(w, lifecycleRequest(http.MethodPost, `{"password":"new-secret"}`))

	if w.Code != http.StatusConflict || decodeErrorCode(t, w.Body.String()) != "password_managed_externally" {
		t.Fatalf("status=%d events=%v body=%s", w.Code, events, w.Body.String())
	}
	if len(events) != 0 {
		t.Fatalf("LDAP/AD credential must not be mutated by JJDGuard: %v", events)
	}
}

func TestResetPasswordDoesNotPersistHashWhenRuntimeFails(t *testing.T) {
	e, u, admin, _ := nativeAdminFixture(t, "reset-ambiguous")
	response := nativeAdminReset(t, e, u, admin)
	current, err := e.deps.UserRepo.GetByID(context.Background(), u.ID)
	if response.Code != 503 || err != nil || current.Status != "reconciliation_required" || bcrypt.CompareHashAndPassword([]byte(current.PasswordHash), []byte(u.Password)) != nil {
		t.Fatal("ambiguous native reset persisted an unconfirmed local password")
	}
}

func TestResetEmergencyPasswordMarksReconciliationWhenSessionRevokeFails(t *testing.T) {
	events := []string{}
	deps := lifecycleDependencies(&events, &lifecycleIdentityClient{events: &events})
	user := deps.UserStore.(*lifecycleUserStore).user
	user.DepartmentAssignmentMode = "emergency"
	provisioner := deps.LocalIdentityProvisioner.(*lifecycleProvisioner)
	provisioner.subject = ""
	deps.SessionRepo = &lifecycleSessionStore{events: &events, deleteErr: errors.New("session secret")}
	w := httptest.NewRecorder()
	ResetPassword(deps).ServeHTTP(w, lifecycleRequest(http.MethodPost, `{"password":"new-secret"}`))

	if w.Code != http.StatusBadGateway || decodeErrorCode(t, w.Body.String()) != "session_revoke_failed" {
		t.Fatalf("status=%d body=%s events=%v", w.Code, w.Body.String(), events)
	}
	got := provisioner.reconciliation
	if got.TenantID != user.TenantID || got.UserID != user.ID || got.ActorID != "admin-1" ||
		got.SubjectFingerprint != "" || got.Operation != "password_reset" ||
		got.Stage != "password_reset_session_revoke_failed" ||
		got.Provider != "local" || got.Source != "local" {
		t.Fatalf("reconciliation=%+v", got)
	}
	if strings.Join(events, ",") !=
		"database.password_hash,sessions.revoke,database.reconciliation_required" {
		t.Fatalf("events=%v", events)
	}
	for _, secret := range []string{"session secret", user.ID, "new-secret"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("response leaked %q: %s", secret, w.Body.String())
		}
	}
}

func TestResetPasswordReturnsSafeErrorWhenReconciliationMarkerFails(t *testing.T) {
	e, u, admin, _ := nativeAdminFixture(t, "reset-ambiguous")
	e.deps.LocalIdentityProvisioner = failedNativeReconciliation{e.deps.LocalIdentityProvisioner}
	response := nativeAdminReset(t, e, u, admin)
	if response.Code != 503 || decodeErrorCode(t, response.Body.String()) != "password_identity_sync_failed" || strings.Contains(response.Body.String(), "synthetic marker failure detail") {
		t.Fatal("administrative marker failure exposed an unsafe response")
	}
}

func TestResetEmergencyPasswordSessionRevokeFailurePersistsReconciliationState(t *testing.T) {
	pool := setupTenantScopedDB(t)
	ctx := context.Background()
	provisioner, err := localidentity.NewProvisioner(pool, "https://sso.example.test/sso/realms/jjdguard")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		initial    string
		wantStatus string
	}{
		{name: "active user requires reconciliation", initial: "active", wantStatus: "reconciliation_required"},
		{name: "disabled user remains disabled", initial: "disabled", wantStatus: "disabled"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			suffix := fmt.Sprintf("%d", time.Now().UnixNano())
			tenantID := "tenant_password_reconcile_" + suffix
			actorID := "actor_password_reconcile_" + suffix
			userID := "emergency_password_reconcile_" + suffix
			if _, err := pool.Exec(ctx, `
				INSERT INTO tenants (id,name,edition,status,is_test)
				VALUES ($1,$1,'enterprise','active',TRUE)
			`, tenantID); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `
				INSERT INTO users (
					id,tenant_id,username,password_hash,role,status,
					department_assignment_mode,department_assignment_source
				) VALUES
					($1,$2,$1,'actor-hash','platform_admin','active','emergency','local'),
					($3,$2,$3,'old-hash','platform_admin',$4,'emergency','local')
			`, actorID, tenantID, userID, tc.initial); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = pool.Exec(context.Background(), `DELETE FROM audit_operations WHERE tenant_id=$1`, tenantID)
				_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE tenant_id=$1`, tenantID)
				_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenantID)
			})

			events := []string{}
			deps := &Dependencies{
				UserStore:                repository.NewUserRepository(pool),
				SessionRepo:              &lifecycleSessionStore{events: &events, deleteErr: errors.New("session secret")},
				LocalIdentityProvisioner: provisioner,
			}
			req := httptest.NewRequest(
				http.MethodPost, "/admin/v1/users/"+userID+"/reset-password",
				strings.NewReader(`{"password":"new-secret"}`),
			)
			req = withTenantScopedUserCtx(req, tenantID, actorID, "platform_admin")
			route := chi.NewRouteContext()
			route.URLParams.Add("id", userID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
			w := httptest.NewRecorder()
			ResetPassword(deps).ServeHTTP(w, req)

			if w.Code != http.StatusBadGateway || decodeErrorCode(t, w.Body.String()) != "session_revoke_failed" {
				t.Fatalf("status=%d body=%s events=%v", w.Code, w.Body.String(), events)
			}
			var status string
			if err := pool.QueryRow(ctx, `
				SELECT status FROM users WHERE tenant_id=$1 AND id=$2
			`, tenantID, userID).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status != tc.wantStatus {
				t.Fatalf("status=%q want=%q", status, tc.wantStatus)
			}
			var markerCount int
			if err := pool.QueryRow(ctx, `
				SELECT COUNT(*) FROM audit_operations
				WHERE tenant_id=$1 AND target_id=$2
				  AND action_type='local_identity.reconciliation_required'
				  AND action_detail->>'operation'='password_reset'
				  AND action_detail->>'stage'='password_reset_session_revoke_failed'
				  AND action_detail->>'provider'='local'
			`, tenantID, userID).Scan(&markerCount); err != nil {
				t.Fatal(err)
			}
			if markerCount != 1 {
				t.Fatalf("reconciliation markers=%d want=1", markerCount)
			}
		})
	}
}
