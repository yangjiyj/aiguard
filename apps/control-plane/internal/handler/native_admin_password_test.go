package handler

import (
	"context"
	"errors"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func nativeAdminFixture(t *testing.T, mode string) (*consoleLoginEnv, consoleTestUser, consoleTestUser, *nativePasswordHTTPState) {
	t.Helper()
	e, u, _ := managedEmployeeFixture(t)
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, "UPDATE user_identity_links SET local_runtime_managed=TRUE WHERE user_id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	admin := e.createUser("platform_admin", "active", "Correct-Horse-Admin-42")
	return e, u, admin, nativePasswordHTTPFixture(t, e, u, mode)
}
func nativeAdminRequest(t *testing.T, e *consoleLoginEnv, u, admin consoleTestUser, password string) *http.Request {
	t.Helper()
	actor, err := e.deps.UserRepo.GetByID(context.Background(), admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/users/"+u.ID+"/reset-password", strings.NewReader(`{"password":"`+password+`"}`))
	route := chi.NewRouteContext()
	route.URLParams.Add("id", u.ID)
	return request.WithContext(context.WithValue(context.WithValue(request.Context(), auth.UserKey, actor), chi.RouteCtxKey, route))
}
func nativeAdminReset(t *testing.T, e *consoleLoginEnv, u, admin consoleTestUser) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	ResetPassword(e.deps)(response, nativeAdminRequest(t, e, u, admin, "Admin-Chosen-Horse-77"))
	return response
}
func TestNativeAdminPasswordHTTPFailuresPauseAndFenceOldSessions(t *testing.T) {
	for _, mode := range []string{"disable", "reset", "reset-ambiguous", "enable", "database"} {
		t.Run(mode, func(t *testing.T) {
			e, u, admin, state := nativeAdminFixture(t, mode)
			ctx := context.Background()
			if mode == "database" {
				fn := "native_admin_password_fail_" + fmt.Sprint(consoleLoginSeq.Add(1))
				if _, err := e.pool.Exec(ctx, "CREATE FUNCTION "+fn+"() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id='"+u.ID+"' AND NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN RAISE EXCEPTION 'isolated native admin persistence failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER "+fn+" BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION "+fn+"();"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { e.pool.Exec(ctx, "DROP TRIGGER "+fn+" ON users; DROP FUNCTION "+fn+"();") })
			}
			metadata, _ := employeeKeyReply(t, employeeKeyHTTP(e, "ensure", employeeKeyRequest{UserID: u.ID, LoginMode: "local", ExternalSubject: "trusted-local-subject", LocalCredentialVersion: 1}, e.tenantID))
			if before, raw, err := e.deps.EmployeeKeyRepo.Credential(ctx, e.tenantID, u.ID); err != nil || before == nil || before.ID != metadata.ID || raw == "" {
				t.Fatal("native admin fixture lacks a usable existing managed credential")
			}
			oldTicket := chatFixtureTicket(t, e, u)
			response := nativeAdminReset(t, e, u, admin)
			wanted := "password_identity_sync_failed"
			if mode == "enable" {
				wanted = "password_updated_identity_sync_failed"
			}
			if response.Code != 503 || decodeConsoleError(t, response).Error.Code != wanted {
				t.Fatalf("native admin mode=%s status=%d", mode, response.Code)
			}
			if strings.Contains(response.Body.String(), "chat_ticket") || strings.Contains(response.Body.String(), "token") {
				t.Fatal("failed administrative password sync issued a login credential")
			}
			current, err := e.deps.UserRepo.GetByID(ctx, u.ID)
			if err != nil || current.Status != "reconciliation_required" {
				t.Fatal("native admin ambiguity left CP identity usable")
			}
			if mode != "disable" && state.enabled {
				t.Fatal("native admin ambiguity left native identity enabled")
			}
			var epoch int64
			e.pool.QueryRow(ctx, "SELECT local_credential_version FROM users WHERE id=$1", u.ID).Scan(&epoch)
			if epoch <= 1 {
				t.Fatal("native admin ambiguity retained old local epoch")
			}
			if mode == "enable" {
				if bcrypt.CompareHashAndPassword([]byte(current.PasswordHash), []byte("Admin-Chosen-Horse-77")) != nil {
					t.Fatal("admin updated-password code differs from stored password")
				}
			} else if bcrypt.CompareHashAndPassword([]byte(current.PasswordHash), []byte(u.Password)) != nil {
				t.Fatal("admin unchanged-password code differs from stored password")
			}
			if mode == "reset-ambiguous" && state.password != "Admin-Chosen-Horse-77" {
				t.Fatal("fixture did not model a remote write followed by failure")
			}
			if old := redeemFixtureTicket(e, e.tenantID, oldTicket, "", true); old.Code != 401 {
				t.Fatalf("old native admin ticket status=%d", old.Code)
			}
			if identity, err := e.deps.ChatLoginTickets.CurrentIdentity(ctx, e.tenantID, u.ID, e.deps.IdentityRuntimeConfig.IssuerURL); err != nil || identity != nil {
				t.Fatal("paused native admin identity still authorized local Chat")
			}
			var actorID string
			if err := e.pool.QueryRow(ctx, "SELECT action_detail->>'actor_id' FROM audit_operations WHERE tenant_id=$1 AND target_id=$2 AND action_type='local_identity.reconciliation_required' ORDER BY created_at DESC LIMIT 1", e.tenantID, u.ID).Scan(&actorID); err != nil || actorID != admin.ID {
				t.Fatal("native admin failure audit lost the administrative actor")
			}
			if _, raw, err := e.deps.EmployeeKeyRepo.Credential(ctx, e.tenantID, u.ID, 1); !errors.Is(err, repository.ErrEmployeeKeyDenied) || raw != "" {
				t.Fatal("old native admin epoch obtained a credential")
			}
			if _, raw, err := e.deps.EmployeeKeyRepo.Credential(ctx, e.tenantID, u.ID); !errors.Is(err, repository.ErrEmployeeKeyDenied) || raw != "" {
				t.Fatal("OIDC/server consumer obtained a paused native credential")
			}

		})
	}
}
func TestNativeAdminPasswordSuccessRecoversPauseAndPreservesDisabledStatus(t *testing.T) {
	for _, initial := range []string{"active", "disabled", "reconciliation_required"} {
		t.Run(initial, func(t *testing.T) {
			e, u, admin, state := nativeAdminFixture(t, "success")
			ctx := context.Background()
			if _, err := e.pool.Exec(ctx, "UPDATE users SET status=$2 WHERE id=$1", u.ID, initial); err != nil {
				t.Fatal(err)
			}
			if initial != "active" {
				state.enabled = false
			}
			response := nativeAdminReset(t, e, u, admin)
			if response.Code != 200 {
				t.Fatalf("admin reset initial=%s status=%d", initial, response.Code)
			}
			current, err := e.deps.UserRepo.GetByID(ctx, u.ID)
			wanted := "active"
			if initial == "disabled" {
				wanted = "disabled"
			}
			if err != nil || current.Status != wanted || state.enabled != (wanted == "active") || state.password != "Admin-Chosen-Horse-77" || bcrypt.CompareHashAndPassword([]byte(current.PasswordHash), []byte(state.password)) != nil {
				t.Fatal("native admin completion did not synchronize both credentials and preserve status")
			}
			if current.MustChangePassword {
				t.Fatal("administrative reset introduced a second forced password change")
			}
		})
	}
}
func TestPausedNativePasswordCannotBeReenabledByOrdinaryStatusToggle(t *testing.T) {
	e, u, admin, state := nativeAdminFixture(t, "reset-ambiguous")
	ctx := context.Background()
	if response := nativeAdminReset(t, e, u, admin); response.Code != 503 {
		t.Fatalf("native pause setup status=%d", response.Code)
	}
	current, err := e.deps.UserRepo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := e.deps.UserRepo.GetByID(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	writes := state.writes
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/admin/v1/users/"+u.ID+"/status", nil)
	if applyManagedUserStatus(response, request, e.deps, actor, current, "active") || response.Code != 409 || state.writes != writes {
		t.Fatal("ordinary status activation bypassed unresolved native password sync")
	}
	disabledResponse := httptest.NewRecorder()
	if applyManagedUserStatus(disabledResponse, request, e.deps, actor, current, "disabled") || disabledResponse.Code != 409 {
		t.Fatal("ordinary disable erased the password reconciliation marker")
	}
	activeResponse := httptest.NewRecorder()
	if applyManagedUserStatus(activeResponse, request, e.deps, actor, current, "active") || activeResponse.Code != 409 {
		t.Fatal("two-step disable/enable bypassed password reconciliation")
	}
	actual, err := e.deps.UserRepo.GetByID(ctx, u.ID)
	if err != nil || actual.Status != "reconciliation_required" {
		t.Fatal("ordinary status activation changed paused account")
	}
}
func TestNativeAdminPasswordCancellationStillAuditsAndPauses(t *testing.T) {
	e, u, admin, state := nativeAdminFixture(t, "cancel")
	ctx := context.Background()
	request := nativeAdminRequest(t, e, u, admin, "Admin-Chosen-Horse-77")
	requestCtx, cancel := context.WithCancel(request.Context())
	defer cancel()
	state.onReset = cancel
	request = request.WithContext(requestCtx)
	response := httptest.NewRecorder()
	ResetPassword(e.deps)(response, request)
	if response.Code != 503 || state.enabled {
		t.Fatalf("canceled admin sync status=%d enabled=%v", response.Code, state.enabled)
	}
	var status string
	var audits int
	e.pool.QueryRow(ctx, "SELECT status FROM users WHERE id=$1", u.ID).Scan(&status)
	e.pool.QueryRow(ctx, "SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND target_id=$2 AND action_type='local_identity.reconciliation_required'", e.tenantID, u.ID).Scan(&audits)
	if status != "reconciliation_required" || audits != 1 {
		t.Fatal("canceled administrative reset lost pause or durable audit")
	}
}

type failedNativeReconciliation struct{ localidentity.Provisioner }

func (f failedNativeReconciliation) MarkReconciliationRequired(context.Context, localidentity.ReconciliationInput) error {
	return errors.New("synthetic marker failure detail")
}
func TestNativeAdminPasswordMarkerFailureStillKeepsDurablePauseAndSafeError(t *testing.T) {
	e, u, admin, state := nativeAdminFixture(t, "reset-ambiguous")
	e.deps.LocalIdentityProvisioner = failedNativeReconciliation{e.deps.LocalIdentityProvisioner}
	response := nativeAdminReset(t, e, u, admin)
	if response.Code != 503 || decodeConsoleError(t, response).Error.Code != "password_identity_sync_failed" || state.enabled || strings.Contains(response.Body.String(), "synthetic marker failure detail") {
		t.Fatal("native marker error exposed details or enabled the account")
	}
	current, err := e.deps.UserRepo.GetByID(context.Background(), u.ID)
	if err != nil || current.Status != "reconciliation_required" {
		t.Fatal("failed marker persistence removed the already committed pause")
	}
}

func TestNativeStaleStatusSnapshotCannotOverwritePasswordPause(t *testing.T) {
	for _, target := range []string{"active", "disabled"} {
		t.Run(target, func(t *testing.T) {
			e, u, admin, state := nativeAdminFixture(t, "success")
			ctx := context.Background()
			before := "active"
			if target == "active" {
				before = "disabled"
			}
			if _, err := e.pool.Exec(ctx, "UPDATE users SET status=$2 WHERE id=$1", u.ID, before); err != nil {
				t.Fatal(err)
			}
			snapshot, err := e.deps.UserRepo.GetByID(ctx, u.ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.pool.Exec(ctx, "UPDATE users SET status='reconciliation_required',local_credential_version=local_credential_version+1 WHERE id=$1", u.ID); err != nil {
				t.Fatal(err)
			}
			actor, err := e.deps.UserRepo.GetByID(ctx, admin.ID)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPatch, "/admin/v1/users/"+u.ID+"/status", nil)
			if applyManagedUserStatus(response, request, e.deps, actor, snapshot, target) || response.Code != 409 {
				t.Fatalf("stale status target=%s status=%d", target, response.Code)
			}
			current, err := e.deps.UserRepo.GetByID(ctx, u.ID)
			if err != nil || current.Status != "reconciliation_required" || state.enabled {
				t.Fatal("stale status snapshot erased password pause or enabled native login")
			}
		})
	}
}
