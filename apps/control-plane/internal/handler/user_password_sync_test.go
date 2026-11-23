package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type nativePasswordHTTPState struct {
	enabled      bool
	password     string
	writes       int
	mode         string
	onReset      func()
	resetStarted chan struct{}
	resumeReset  chan struct{}
	releaseOnce  sync.Once
}

func nativePasswordHTTPFixture(t *testing.T, e *consoleLoginEnv, u consoleTestUser, mode string) *nativePasswordHTTPState {
	t.Helper()
	state := &nativePasswordHTTPState{enabled: true, password: u.Password, mode: mode, resetStarted: make(chan struct{}), resumeReset: make(chan struct{})}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			w.Header().Set("content-type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-native-http-token", "expires_in": 300})
			return
		}
		state.writes++
		if strings.HasSuffix(r.URL.Path, "/reset-password") {
			if mode == "serialize" && state.writes == 2 {
				close(state.resetStarted)
				select {
				case <-state.resumeReset:
				case <-r.Context().Done():
					return
				}
			}

			var body struct {
				Value     string `json:"value"`
				Temporary bool   `json:"temporary"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Temporary || body.Value == "" {
				t.Error("invalid native credential update")
			}
			if mode == "reset" {
				w.WriteHeader(503)
				return
			}
			state.password = body.Value
			if state.onReset != nil {
				state.onReset()
			}
			if mode == "reset-ambiguous" {
				w.WriteHeader(503)
				return
			}
		} else {
			var body struct {
				Enabled bool `json:"enabled"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid native enable update")
			}
			if mode == "disable" && !body.Enabled || mode == "enable" && body.Enabled {
				w.WriteHeader(503)
				return
			}
			state.enabled = body.Enabled
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(server.Close)
	client, err := localidentity.NewClient(localidentity.Config{BaseURL: server.URL + "/sso", Realm: "jjdguard", ClientID: "fixture-client", ClientSecret: "synthetic-native-http-secret", HTTPClient: server.Client(), RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	e.deps.LocalIdentityClient = client
	provisioner, err := localidentity.NewProvisioner(e.pool, e.deps.IdentityRuntimeConfig.IssuerURL)
	if err != nil {
		t.Fatal(err)
	}
	e.deps.LocalIdentityProvisioner = provisioner
	return state
}
func TestEmployeeNativePasswordHTTPFailurePausesIdentityWithoutSuccessTicket(t *testing.T) {
	for _, mode := range []string{"disable", "reset", "reset-ambiguous", "enable", "database"} {
		t.Run(mode, func(t *testing.T) {
			e, u, _ := managedEmployeeFixture(t)
			ctx := context.Background()
			if _, err := e.pool.Exec(ctx, "UPDATE user_identity_links SET local_runtime_managed=TRUE WHERE user_id=$1", u.ID); err != nil {
				t.Fatal(err)
			}
			state := nativePasswordHTTPFixture(t, e, u, mode)
			if mode == "database" {
				fn := "native_password_fail_" + fmt.Sprint(consoleLoginSeq.Add(1))
				if _, err := e.pool.Exec(ctx, "CREATE FUNCTION "+fn+"() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id='"+u.ID+"' AND NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN RAISE EXCEPTION 'isolated native password persistence failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER "+fn+" BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION "+fn+"();"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { e.pool.Exec(ctx, "DROP TRIGGER "+fn+" ON users; DROP FUNCTION "+fn+"();") })
			}
			oldTicket := chatFixtureTicket(t, e, u)
			response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", map[string]string{"new_password": "Changed-Horse-2026!"})
			wantCode := "password_identity_sync_failed"
			if mode == "enable" {
				wantCode = "password_updated_identity_sync_failed"
			}
			if response.Code != 503 || decodeConsoleError(t, response).Error.Code != wantCode {
				t.Fatalf("native failure mode=%s status=%d", mode, response.Code)
			}
			var body map[string]json.RawMessage
			json.Unmarshal(response.Body.Bytes(), &body)
			if len(body["chat_ticket"]) > 0 || len(body["token"]) > 0 {
				t.Fatal("incomplete native password sync issued a credential")
			}
			current, err := e.deps.UserRepo.GetByID(ctx, u.ID)
			if err != nil || current == nil || current.Status != "reconciliation_required" {
				t.Fatal("native uncertainty left CP identity active")
			}
			if mode != "disable" && state.enabled {
				t.Fatal("incomplete native password sync left native identity enabled")
			}
			if mode == "enable" {
				if bcrypt.CompareHashAndPassword([]byte(current.PasswordHash), []byte("Changed-Horse-2026!")) != nil {
					t.Fatal("updated-password failure code mismatches persisted CP password")
				}
			} else if bcrypt.CompareHashAndPassword([]byte(current.PasswordHash), []byte(u.Password)) != nil {
				t.Fatal("unchanged-password failure code mismatches persisted CP password")
			}
			if old := redeemFixtureTicket(e, e.tenantID, oldTicket, "", true); old.Code != 401 {
				t.Fatalf("staged native password change retained old ticket status=%d", old.Code)
			}
			var audits int
			if err := e.pool.QueryRow(ctx, "SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND target_id=$2 AND action_type='local_identity.reconciliation_required'", e.tenantID, u.ID).Scan(&audits); err != nil || audits != 1 {
				t.Fatal("native password sync failure lacks durable reconciliation audit")
			}
		})
	}
}
func TestEmployeeNativePasswordHTTPCompletesBothCredentialsBeforeTicket(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, "UPDATE user_identity_links SET local_runtime_managed=TRUE WHERE user_id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	state := nativePasswordHTTPFixture(t, e, u, "success")
	response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", map[string]string{"new_password": "Changed-Horse-2026!"})
	var body struct {
		Ticket string `json:"chat_ticket"`
		Token  string `json:"token"`
	}
	json.Unmarshal(response.Body.Bytes(), &body)
	if response.Code != 200 || body.Ticket == "" || body.Token != "" {
		t.Fatalf("native success status=%d", response.Code)
	}
	current, err := e.deps.UserRepo.GetByID(ctx, u.ID)
	if err != nil || current == nil || current.Status != "active" || bcrypt.CompareHashAndPassword([]byte(current.PasswordHash), []byte(state.password)) != nil || state.password != "Changed-Horse-2026!" || !state.enabled {
		t.Fatal("ticket granted before both native and CP password were synchronized")
	}
	if state.writes != 3 {
		t.Fatalf("native phase writes=%d", state.writes)
	}
	if redeemed := redeemFixtureTicket(e, e.tenantID, body.Ticket, "", true); redeemed.Code != 200 {
		t.Fatalf("new native synchronized ticket status=%d", redeemed.Code)
	}
}
func TestEmployeeStandalonePasswordChangeDoesNotUseConfiguredIssuerAsNativeOwnership(t *testing.T) {
	for _, issuerConfigured := range []bool{false, true} {
		t.Run(fmt.Sprint(issuerConfigured), func(t *testing.T) {
			e, u, _ := managedEmployeeFixture(t)
			state := nativePasswordHTTPFixture(t, e, u, "must-not-call")
			if !issuerConfigured {
				e.deps.IdentityRuntimeConfig.IssuerURL = ""
			}
			response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", map[string]string{"new_password": "Changed-Horse-2026!"})
			if response.Code != 200 || state.writes != 0 {
				t.Fatalf("standalone issuer=%v status=%d native writes=%d", issuerConfigured, response.Code, state.writes)
			}
		})
	}
}
func TestEmployeeLocalPasswordChangeRejectsEnterpriseOwnedCredentials(t *testing.T) {
	for _, kind := range []string{"ldap", "oidc-only"} {
		t.Run(kind, func(t *testing.T) {
			e, u, _ := managedEmployeeFixture(t)
			state := nativePasswordHTTPFixture(t, e, u, "must-not-call")
			source := kind
			if kind == "oidc-only" {
				source = "oidc"
			}
			sourceID := ""
			if kind == "ldap" {
				sourceID = e.deps.IdentityRuntimeConfig.IssuerURL
			}
			if _, err := e.pool.Exec(context.Background(), "UPDATE user_identity_links SET source_type=$2,source_id=$3 WHERE user_id=$1", u.ID, source, sourceID); err != nil {
				t.Fatal(err)
			}
			response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", map[string]string{"new_password": "Changed-Horse-2026!"})
			expectedStatus, expectedCode := 409, "password_managed_externally"
			// LDAP anonymous login fails before password rotation, without revealing ownership.
			if kind == "ldap" {
				expectedStatus, expectedCode = 401, "invalid_credentials"
			}
			if response.Code != expectedStatus || decodeConsoleError(t, response).Error.Code != expectedCode || state.writes != 0 {
				t.Fatalf("enterprise owner=%s status=%d native writes=%d", kind, response.Code, state.writes)
			}
		})
	}
}
func TestNativeAdministratorPasswordResetIncrementsLocalCredentialVersion(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	provisioner, err := localidentity.NewProvisioner(e.pool, e.deps.IdentityRuntimeConfig.IssuerURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := provisioner.UpdatePasswordHash(context.Background(), e.tenantID, u.ID, "synthetic-admin-updated-hash", false); err != nil {
		t.Fatal(err)
	}
	var version int64
	if err := e.pool.QueryRow(context.Background(), "SELECT local_credential_version FROM users WHERE id=$1", u.ID).Scan(&version); err != nil || version != 2 {
		t.Fatal("native administrator reset retained old credential epoch")
	}
}

func TestEmployeeOldAuthenticatedPasswordCannotIssueNewVersionTicket(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	ctx := context.Background()
	authenticated, err := e.deps.UserRepo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(authenticated.PasswordHash), []byte(u.Password)) != nil {
		t.Fatal("invalid authenticated fixture")
	}
	// A concurrent administrative reset lands after bcrypt, before Issue.
	if err := e.deps.UserRepo.UpdatePassword(ctx, u.ID, "synthetic-concurrent-reset-hash", false); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/employee-login", nil)
	ticket, issued := issueChatLoginTicket(response, request, e.deps, authenticated)
	if issued || ticket != "" || response.Code != 403 {
		t.Fatal("old password proof created a current-version Chat ticket")
	}
	var count int
	if err := e.pool.QueryRow(ctx, "SELECT count(*) FROM chat_login_tickets WHERE user_id=$1", u.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("old password proof persisted a new ticket")
	}
}

func TestNativeSelfAndAdministratorPasswordUpdatesAreSerialized(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, "UPDATE user_identity_links SET local_runtime_managed=TRUE WHERE user_id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	state := nativePasswordHTTPFixture(t, e, u, "serialize")
	release := func() { state.releaseOnce.Do(func() { close(state.resumeReset) }) }
	defer release()
	employeeDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		employeeDone <- e.employeeLogin(u.Username, u.Password, "192.0.2.1", map[string]string{"new_password": "Changed-Horse-2026!"})
	}()
	select {
	case <-state.resetStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("native self change did not enter remote credential update")
	}
	admin := e.createUser("platform_admin", "active", "Correct-Horse-Admin-42")
	actor, err := e.deps.UserRepo.GetByID(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/users/"+u.ID+"/reset-password", strings.NewReader(`{"password":"Admin-Chosen-Horse-77"}`))
	route := chi.NewRouteContext()
	route.URLParams.Add("id", u.ID)
	request = request.WithContext(context.WithValue(context.WithValue(request.Context(), auth.UserKey, actor), chi.RouteCtxKey, route))
	adminDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		ResetPassword(e.deps)(response, request)
		adminDone <- response
	}()
	select {
	case <-adminDone:
		t.Fatal("administrator reset crossed an active native self change")
	case <-time.After(40 * time.Millisecond):
	}
	release()
	employeeResponse := <-employeeDone
	adminResponse := <-adminDone
	if adminResponse.Code != 200 {
		t.Fatalf("serialized administrator status=%d", adminResponse.Code)
	}
	if employeeResponse.Code != 200 && employeeResponse.Code != 409 && employeeResponse.Code != 403 {
		t.Fatalf("serialized employee status=%d", employeeResponse.Code)
	}
	current, err := e.deps.UserRepo.GetByID(ctx, u.ID)
	if err != nil || state.password != "Admin-Chosen-Horse-77" || bcrypt.CompareHashAndPassword([]byte(current.PasswordHash), []byte(state.password)) != nil {
		t.Fatal("concurrent self/admin changes split native and CP credentials")
	}
}

func TestNativePasswordCancellationStillPausesAndAuditsWithIndependentContext(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, "UPDATE user_identity_links SET local_runtime_managed=TRUE WHERE user_id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	state := nativePasswordHTTPFixture(t, e, u, "cancel")
	current, err := e.deps.UserRepo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, cancel := context.WithCancel(context.WithValue(ctx, auth.UserKey, current))
	defer cancel()
	state.onReset = cancel
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/me/change-password", strings.NewReader(`{"current_password":"Correct-Horse-42","new_password":"Changed-Horse-2026!"}`)).WithContext(requestCtx)
	response := httptest.NewRecorder()
	ChangeCurrentPassword(e.deps)(response, request)
	if response.Code != 503 || state.enabled {
		t.Fatalf("canceled native password status=%d enabled=%v", response.Code, state.enabled)
	}
	var status string
	var audits int
	if err := e.pool.QueryRow(ctx, "SELECT status FROM users WHERE id=$1", u.ID).Scan(&status); err != nil || status != "reconciliation_required" {
		t.Fatal("canceled native request left identity usable")
	}
	if err := e.pool.QueryRow(ctx, "SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND target_id=$2 AND action_type='local_identity.reconciliation_required'", e.tenantID, u.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("canceled native request lost durable reconciliation audit")
	}
}
