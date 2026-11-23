package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func (e *consoleLoginEnv) employeeLogin(username, password, ip string, extra map[string]string) *httptest.ResponseRecorder {
	e.t.Helper()
	id := fmt.Sprintf("ecap-%d", consoleLoginSeq.Add(1))
	if err := e.redis.Set(context.Background(), captchaRedisKey(id), captchaDigest("ABCD"), time.Minute).Err(); err != nil {
		e.t.Fatal(err)
	}
	body := map[string]string{"username": username, "password": password, "captcha_id": id, "captcha_code": "ABCD"}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/employee-login", strings.NewReader(string(raw)))
	request.RemoteAddr = ip + ":40000"
	request.Header.Set(portalIntegrationTenantHeader, e.tenantID)
	response := httptest.NewRecorder()
	EmployeeLogin(e.deps)(response, request)
	return response
}
func TestEmployeeLoginAndConsoleAudienceStaySeparate(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	console := e.login(u.Username, u.Password, "192.0.2.10", nil)
	if console.Code != 403 || decodeConsoleError(t, console).Error.Code != "console_role_required" {
		t.Fatalf("console status=%d", console.Code)
	}
	employee := e.employeeLogin(u.Username, u.Password, "192.0.2.10", nil)
	var body map[string]json.RawMessage
	_ = json.Unmarshal(employee.Body.Bytes(), &body)
	var ticket, token string
	_ = json.Unmarshal(body["chat_ticket"], &ticket)
	_ = json.Unmarshal(body["token"], &token)
	if employee.Code != 200 || ticket == "" || token != "" {
		t.Fatalf("employee status=%d ticket-present=%v token-present=%v", employee.Code, ticket != "", token != "")
	}
	for _, cookie := range employee.Result().Cookies() {
		if cookie.Name == "session_token" && cookie.Value != "" {
			t.Fatal("employee management cookie")
		}
	}
}
func TestConsoleRejectsEveryNonAdministratorRoleBeforeSessionIssuance(t *testing.T) {
	for _, role := range []string{"chat_user", "developer", "viewer", "dept_manager", "operator", "platform_connector"} {
		t.Run(role, func(t *testing.T) {
			e := newConsoleLoginEnv(t)
			u := e.createUser(role, "active", "Correct-Horse-42")
			response := e.login(u.Username, u.Password, "192.0.2.10", nil)
			if response.Code != 403 || decodeConsoleError(t, response).Error.Code != "console_role_required" {
				t.Fatalf("role=%s status=%d", role, response.Code)
			}
			keys, err := e.redis.Keys(context.Background(), "session:*").Result()
			if err != nil || len(keys) != 0 {
				t.Fatalf("sessions=%d err=%v", len(keys), err)
			}
		})
	}
}
func TestEmployeeLoginRequiresCurrentTenant(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	original := e.tenantID
	e.tenantID = "other-tenant"
	response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", nil)
	e.tenantID = original
	if response.Code != 401 {
		t.Fatalf("cross-tenant status=%d", response.Code)
	}
}
func TestEmployeeLoginPasswordChangeIssuesOnlyFreshChatTicket(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, "UPDATE users SET must_change_password=TRUE WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.sessions.Create(ctx, &repository.Session{ID: u.ID + "-legacy", UserID: u.ID, TenantID: e.tenantID, Role: "chat_user"}); err != nil {
		t.Fatal(err)
	}
	blocked := e.employeeLogin(u.Username, u.Password, "192.0.2.1", nil)
	if blocked.Code != 403 || decodeConsoleError(t, blocked).Error.Code != "password_change_required" {
		t.Fatalf("required status=%d", blocked.Code)
	}
	changed := e.employeeLogin(u.Username, u.Password, "192.0.2.1", map[string]string{"new_password": "Changed-Horse-2026!"})
	var reply map[string]json.RawMessage
	_ = json.Unmarshal(changed.Body.Bytes(), &reply)
	if changed.Code != 200 || len(reply["chat_ticket"]) < 3 || len(reply["token"]) > 0 {
		t.Fatalf("change status=%d", changed.Code)
	}
	var user struct {
		ID       string `json:"id"`
		Role     string `json:"role"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(reply["user"], &user); err != nil || user.ID != u.ID || user.Role != "chat_user" || user.TenantID != e.tenantID {
		t.Fatal("changed-password response lacks current employee identity")
	}
	if session, err := e.sessions.Get(ctx, u.ID+"-legacy"); err != nil || session != nil {
		t.Fatal("legacy session retained")
	}
}

func TestEmployeeLoginRequiresCaptchaAndSharesLockoutProtection(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	bad := e.employeeLogin(u.Username, u.Password, "192.0.2.1", map[string]string{"captcha_code": "WRONG"})
	if bad.Code != http.StatusBadRequest || decodeConsoleError(t, bad).Error.Code != "invalid_captcha" {
		t.Fatalf("captcha status=%d", bad.Code)
	}
	for i := 0; i < 5; i++ {
		response := e.employeeLogin(u.Username, "wrong-password", "192.0.2.1", nil)
		expected := http.StatusUnauthorized

		if response.Code != expected {
			t.Fatalf("failure %d status=%d", i, response.Code)
		}
	}
	if response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("same client lock status=%d", response.Code)
	}
	if response := e.employeeLogin(u.Username, u.Password, "192.0.2.2", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("another client bypassed account lock status=%d", response.Code)
	}
}
func TestEmployeeLoginChecksTOTPAndPreventsReplay(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	e.withConsoleSecurity()
	secret := setupTOTPForUser(t, e, u)
	missing := e.employeeLogin(u.Username, u.Password, "192.0.2.1", nil)
	if missing.Code != http.StatusUnauthorized || decodeConsoleError(t, missing).Error.Code != "totp_required" {
		t.Fatalf("missing TOTP status=%d", missing.Code)
	}
	code, _ := totpCodeAt(secret, uint64(time.Now().Unix()/totpPeriod))
	accepted := e.employeeLogin(u.Username, u.Password, "192.0.2.1", map[string]string{"totp_code": code})
	if accepted.Code != http.StatusOK {
		t.Fatalf("TOTP status=%d", accepted.Code)
	}
	replay := e.employeeLogin(u.Username, u.Password, "192.0.2.1", map[string]string{"totp_code": code})
	if replay.Code == http.StatusOK {
		t.Fatal("TOTP replay accepted")
	}
}

func TestEmployeeLoginScopesDuplicateUsernameAndAccountLockoutToTenant(t *testing.T) {
	first, userA, _ := chatLoginFixture(t)
	second, userB, _ := chatLoginFixture(t)
	ctx := context.Background()
	if _, err := second.pool.Exec(ctx, "UPDATE users SET username=$2 WHERE id=$1", userB.ID, userA.Username); err != nil {
		t.Fatal(err)
	}
	userB.Username = userA.Username
	// Both tenants use the same deployment Redis. A tenant A lock must not
	// prevent the identically named tenant B employee from authenticating.
	second.redis = first.redis
	second.deps.RedisClient = first.redis
	for _, fixture := range []struct {
		e *consoleLoginEnv
		u consoleTestUser
	}{{first, userA}, {second, userB}} {
		response := fixture.e.employeeLogin(fixture.u.Username, fixture.u.Password, "192.0.2.1", nil)
		var reply struct {
			User struct {
				ID     string `json:"id"`
				Tenant string `json:"tenant_id"`
			} `json:"user"`
		}
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &reply) != nil || reply.User.ID != fixture.u.ID || reply.User.Tenant != fixture.e.tenantID {
			t.Fatal("same-name login resolved another tenant identity")
		}
	}
	for i := 0; i < 5; i++ {
		first.employeeLogin(userA.Username, "wrong-password", "192.0.2.1", nil)
	}
	if locked := first.employeeLogin(userA.Username, userA.Password, "192.0.2.1", nil); locked.Code != 401 {
		t.Fatalf("locked tenant status=%d", locked.Code)
	}
	if other := second.employeeLogin(userB.Username, userB.Password, "192.0.2.1", nil); other.Code != 200 {
		t.Fatalf("other tenant inherited lock status=%d", other.Code)
	}
}

// Every human role enters the personal portal with the same restricted audience.
func TestPersonalPortalLoginAcceptsHumanRolesWithoutManagementSession(t *testing.T) {
	for _, role := range []string{"chat_user", "developer", "viewer", "dept_manager", "security_officer", "auditor", "platform_admin", "tenant_admin", "admin", "tenant_owner", "operator"} {
		t.Run(role, func(t *testing.T) {
			e, u, _ := chatLoginFixture(t)
			if _, err := e.pool.Exec(context.Background(), "UPDATE users SET role=$2 WHERE id=$1", u.ID, role); err != nil {
				t.Fatal(err)
			}
			extra := map[string]string{}
			if chatTicketRequiresAdminSecurity(role) {
				e.withConsoleSecurity()
				secret := setupTOTPForUser(t, e, u)
				code, _ := totpCodeAt(secret, uint64(time.Now().Unix()/totpPeriod))
				extra["totp_code"] = code
			}
			response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", extra)
			if response.Code != 200 {
				t.Fatalf("personal portal role=%s status=%d body=%s", role, response.Code, response.Body.String())
			}
			var body struct {
				Ticket string `json:"chat_ticket"`
				Token  string `json:"token"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Ticket == "" || body.Token != "" {
				t.Fatal("personal login must issue only a single-use portal ticket")
			}
			for _, cookie := range response.Result().Cookies() {
				if cookie.Name == "session_token" && cookie.Value != "" {
					t.Fatal("personal portal issued management cookie")
				}
			}
			redeemed := redeemFixtureTicket(e, e.tenantID, body.Ticket, "", true)
			if redeemed.Code != 200 {
				t.Fatalf("role=%s redemption=%d %s", role, redeemed.Code, redeemed.Body.String())
			}
			current, err := e.deps.ChatLoginTickets.CurrentIdentity(context.Background(), e.tenantID, u.ID, e.deps.IdentityRuntimeConfig.IssuerURL)
			if err != nil || current == nil {
				t.Fatalf("role=%s current identity missing: %v", role, err)
			}
		})
	}
}
func TestPersonalPortalEmergencyAccountCanSignInWithoutModelAuthorization(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	if _, err := e.pool.Exec(context.Background(), "UPDATE users SET role='platform_admin',department_id=NULL,department_assignment_mode='emergency' WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	e.withConsoleSecurity()
	secret := setupTOTPForUser(t, e, u)
	code, _ := totpCodeAt(secret, uint64(time.Now().Unix()/totpPeriod))
	response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", map[string]string{"totp_code": code})
	if response.Code != 200 {
		t.Fatalf("personal login=%d %s", response.Code, response.Body.String())
	}
	var body struct {
		Ticket string `json:"chat_ticket"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &body)
	redeemed := redeemFixtureTicket(e, e.tenantID, body.Ticket, "", true)
	if redeemed.Code != 200 {
		t.Fatalf("personal redemption=%d %s", redeemed.Code, redeemed.Body.String())
	}
	var identity map[string]any
	_ = json.Unmarshal(redeemed.Body.Bytes(), &identity)
	if identity["portal_allowed"] != true || identity["chat_allowed"] != false {
		t.Fatalf("personal login must preserve model denial: %s", redeemed.Body.String())
	}
}

func TestPersonalPortalAdministratorPreservesIPAndTOTPPolicy(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	e.withConsoleSecurity()
	if _, err := e.pool.Exec(context.Background(), "UPDATE users SET role='platform_admin' WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	_ = e.sys.Set(context.Background(), "console_admin_ip_allowlist", "198.51.100.5")
	_ = e.sys.Set(context.Background(), "console_admin_totp_required", "true")
	denied := e.employeeLogin(u.Username, u.Password, "192.0.2.1", nil)
	if denied.Code != 403 || decodeConsoleError(t, denied).Error.Code != "login_ip_not_allowed" {
		t.Fatal("personal admin bypassed IP policy")
	}
	missing := e.employeeLogin(u.Username, u.Password, "198.51.100.5", nil)
	if missing.Code != 403 || decodeConsoleError(t, missing).Error.Code != "totp_setup_required" {
		t.Fatal("personal admin bypassed TOTP setup")
	}
	secret := setupTOTPForUser(t, e, u)
	code, _ := totpCodeAt(secret, uint64(time.Now().Unix()/totpPeriod))
	response := e.employeeLogin(u.Username, u.Password, "198.51.100.5", map[string]string{"totp_code": code})
	if response.Code != 200 {
		t.Fatalf("allowed personal admin status=%d", response.Code)
	}
	var body map[string]json.RawMessage
	_ = json.Unmarshal(response.Body.Bytes(), &body)
	var setupPending bool
	var managementToken, personalTicket string
	_ = json.Unmarshal(body["totp_setup_required"], &setupPending)
	_ = json.Unmarshal(body["token"], &managementToken)
	_ = json.Unmarshal(body["chat_ticket"], &personalTicket)
	if personalTicket == "" || managementToken != "" || setupPending {
		t.Fatal("personal login entered management setup or issued its session")
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "session_token" && cookie.Value != "" {
			t.Fatal("personal login issued management cookie")
		}
	}
	if console := e.login(u.Username, u.Password, "192.0.2.1", nil); console.Code != 403 {
		t.Fatal("management IP policy changed")
	}
}
func TestPersonalPortalPasswordRotationKeepsEveryRoleInPersonalAudience(t *testing.T) {
	for _, role := range []string{"developer", "auditor", "platform_admin"} {
		t.Run(role, func(t *testing.T) {
			e, u, _ := chatLoginFixture(t)
			if _, err := e.pool.Exec(context.Background(), "UPDATE users SET role=$2,must_change_password=TRUE WHERE id=$1", u.ID, role); err != nil {
				t.Fatal(err)
			}
			extra := map[string]string{"new_password": "Rotated-Personal-42!"}
			if chatTicketRequiresAdminSecurity(role) {
				e.withConsoleSecurity()
				secret := setupTOTPForUser(t, e, u)
				code, _ := totpCodeAt(secret, uint64(time.Now().Unix()/totpPeriod))
				extra["totp_code"] = code
			}
			response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", extra)
			var body map[string]json.RawMessage
			_ = json.Unmarshal(response.Body.Bytes(), &body)
			if response.Code != 200 || len(body["chat_ticket"]) < 3 || len(body["token"]) > 0 {
				t.Fatalf("personal password rotation role=%s status=%d body=%s", role, response.Code, response.Body.String())
			}
		})
	}
}
func TestPersonalPortalLoginDoesNotRequireAConfiguredModelApplication(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	e.deps.EmployeeKeyRepo = repository.NewEmployeeAPIKeyRepository(e.pool)
	ticket := chatFixtureTicket(t, e, u)
	response := redeemFixtureTicket(e, e.tenantID, ticket, "", true)
	if response.Code != 200 {
		t.Fatalf("personal login depends on model application: %d %s", response.Code, response.Body.String())
	}
}

func TestPersonalPortalAdminKeepsBoundTOTPVerification(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	e.withConsoleSecurity()
	if _, err := e.pool.Exec(context.Background(), "UPDATE users SET role='platform_admin' WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	secret := setupTOTPForUser(t, e, u)
	if response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", nil); response.Code != 401 {
		t.Fatal("administrator's bound TOTP was bypassed")
	}
	code, _ := totpCodeAt(secret, uint64(time.Now().Unix()/totpPeriod))
	if response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", map[string]string{"totp_code": code}); response.Code != 200 {
		t.Fatalf("personal TOTP login=%d", response.Code)
	}
}
func TestPersonalPortalAuthorizationPreservesEmergencyModelDenial(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	if _, err := e.pool.Exec(context.Background(), "UPDATE users SET role='platform_admin',department_id=NULL,department_assignment_mode='emergency' WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	e.deps.TeamModelRepo = repository.NewTeamModelRepository(e.pool)
	router := chi.NewRouter()
	router.Get("/users/{id}/authorization-context", GetPortalUserAuthorizationContext(e.deps))
	request := httptest.NewRequest(http.MethodGet, "/users/"+u.ID+"/authorization-context", nil)
	request.Header.Set(portalIntegrationTenantHeader, e.tenantID)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("personal context=%d %s", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			PortalAllowed bool     `json:"portal_allowed"`
			ChatAllowed   bool     `json:"chat_allowed"`
			Models        []string `json:"model_ids"`
		}
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Data.PortalAllowed || body.Data.ChatAllowed || len(body.Data.Models) > 0 {
		t.Fatalf("personal access granted models: %s", response.Body.String())
	}
}
