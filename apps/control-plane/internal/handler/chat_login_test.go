package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestChatUserPasswordLoginDoesNotIssueManagementToken(t *testing.T) {
	e := newConsoleLoginEnv(t)
	u := e.createUser("chat_user", "active", "Correct-Horse-42")
	var departmentID string
	if err := e.pool.QueryRow(context.Background(), "SELECT id FROM teams WHERE tenant_id=$1 AND system_key='unassigned'", e.tenantID).Scan(&departmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(context.Background(), "UPDATE users SET department_id=$2,department_assignment_mode='manual',department_assignment_source='local' WHERE id=$1", u.ID, departmentID); err != nil {
		t.Fatal(err)
	}
	e.deps.ChatLoginTickets = repository.NewChatLoginTicketRepository(e.pool)
	e.deps.IdentityRuntimeConfig.IssuerURL = "https://issuer.test"
	if _, err := e.pool.Exec(context.Background(), "INSERT INTO user_identity_links(id,tenant_id,user_id,issuer,source_type,source_id,external_subject) VALUES($1,$2,$3,$4,'local','','real-idp-subject')", u.ID+"-link", e.tenantID, u.ID, e.deps.IdentityRuntimeConfig.IssuerURL); err != nil {
		t.Fatal(err)
	}
	response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Token, ChatTicket string
		User              struct{ ID, Role string }
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw["token"], &body.Token)
	_ = json.Unmarshal(raw["chat_ticket"], &body.ChatTicket)
	_ = json.Unmarshal(raw["user"], &body.User)
	if body.Token != "" || body.ChatTicket == "" {
		t.Fatalf("Chat-only login must provide ticket without management token, body=%s", response.Body.String())
	}
	cleared := false
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "session_token" && cookie.Value == "" && cookie.MaxAge < 0 {
			cleared = true
		}
		if cookie.Name == "session_token" && cookie.Value != "" {
			t.Fatal("Chat-only login must not set a management cookie")
		}
	}
	if !cleared {
		t.Fatal("Chat login must clear any previous console session cookie")
	}
	if strings.Contains(response.Body.String(), u.Password) {
		t.Fatal("password in login response")
	}
}

func chatLoginFixture(t *testing.T) (*consoleLoginEnv, consoleTestUser, string) {
	t.Helper()
	e := newConsoleLoginEnv(t)
	u := e.createUser("chat_user", "active", "Correct-Horse-42")
	var departmentID string
	if err := e.pool.QueryRow(context.Background(), "SELECT id FROM teams WHERE tenant_id=$1 AND system_key='unassigned'", e.tenantID).Scan(&departmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(context.Background(), "UPDATE users SET department_id=$2,department_assignment_mode='manual',department_assignment_source='local' WHERE id=$1", u.ID, departmentID); err != nil {
		t.Fatal(err)
	}
	e.deps.ChatLoginTickets = repository.NewChatLoginTicketRepository(e.pool)
	e.deps.IdentityRuntimeConfig.IssuerURL = "https://issuer.test"
	if _, err := e.pool.Exec(context.Background(), "INSERT INTO user_identity_links(id,tenant_id,user_id,issuer,source_type,source_id,external_subject) VALUES($1,$2,$3,$4,'local','','trusted-local-subject')", u.ID+"-link", e.tenantID, u.ID, e.deps.IdentityRuntimeConfig.IssuerURL); err != nil {
		t.Fatal(err)
	}
	return e, u, departmentID
}
func chatFixtureTicket(t *testing.T, e *consoleLoginEnv, u consoleTestUser) string {
	t.Helper()
	response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", nil)
	if response.Code != 200 {
		t.Fatalf("login=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Ticket string `json:"chat_ticket"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Ticket == "" {
		t.Fatalf("missing ticket: %s", response.Body.String())
	}
	return body.Ticket
}
func redeemFixtureTicket(e *consoleLoginEnv, tenant, ticket, body string, authorized bool) *httptest.ResponseRecorder {
	if body == "" {
		body = fmt.Sprintf(`{"ticket":%q}`, ticket)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/chat-login/redeem", strings.NewReader(body))
	request.Header.Set("X-JJDGuard-Tenant-Id", tenant)
	if authorized {
		request.Header.Set("Authorization", "Bearer isolated-portal-secret")
	}
	w := httptest.NewRecorder()
	PortalIntegrationAPIMiddleware("isolated-portal-secret", e.deps)(RedeemChatLoginTicket(e.deps)).ServeHTTP(w, request)
	return w
}
func TestChatTicketIsSingleUseSecretOnlyTenantBoundAndCurrent(t *testing.T) {
	e, u, originalDept := chatLoginFixture(t)
	ticket := chatFixtureTicket(t, e, u)
	ctx := context.Background()
	var hash string
	var ttl float64
	if err := e.pool.QueryRow(ctx, "SELECT ticket_hash,EXTRACT(EPOCH FROM expires_at-created_at) FROM chat_login_tickets WHERE user_id=$1", u.ID).Scan(&hash, &ttl); err != nil {
		t.Fatal(err)
	}
	if hash != chatTicketHash(ticket) || hash == ticket || ttl > 60 {
		t.Fatalf("not hash-only short-lived proof: ttl=%v", ttl)
	}
	if w := redeemFixtureTicket(e, e.tenantID, ticket, "", false); w.Code == 200 {
		t.Fatal("missing machine secret accepted")
	}
	if w := redeemFixtureTicket(e, "wrong-tenant", ticket, "", true); w.Code == 200 {
		t.Fatal("cross-tenant ticket accepted")
	}
	if w := redeemFixtureTicket(e, e.tenantID, ticket, fmt.Sprintf(`{"ticket":%q,"user_id":"forged-user"}`, ticket), true); w.Code != 400 {
		t.Fatalf("identity override status=%d", w.Code)
	}
	newDept := u.ID + "-department"
	if _, err := e.pool.Exec(ctx, "INSERT INTO teams(id,tenant_id,name,path) VALUES($1,$2,'Current Department',$1)", newDept, e.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, "UPDATE users SET department_id=$2 WHERE id=$1", u.ID, newDept); err != nil {
		t.Fatal(err)
	}
	w := redeemFixtureTicket(e, e.tenantID, ticket, "", true)
	if w.Code != 200 {
		t.Fatalf("redeem=%d body=%s", w.Code, w.Body.String())
	}
	var identity repository.ChatLoginIdentity
	if err := json.Unmarshal(w.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	if identity.UserID != u.ID || identity.TenantID != e.tenantID || identity.ExternalSubject != "trusted-local-subject" || identity.DepartmentID != newDept || identity.DepartmentID == originalDept {
		t.Fatalf("identity is not authoritative: %+v", identity)
	}
	if strings.Contains(w.Body.String(), "token") || strings.Contains(w.Body.String(), u.Password) {
		t.Fatal("management token/password returned to Portal")
	}
	if w := redeemFixtureTicket(e, e.tenantID, ticket, "", true); w.Code != 401 {
		t.Fatalf("replay accepted: %d", w.Code)
	}
}
func TestChatTicketConcurrentRedemptionHasExactlyOneWinner(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	ticket := chatFixtureTicket(t, e, u)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := redeemFixtureTicket(e, e.tenantID, ticket, "", true)
			if w.Code == 200 {
				winners.Add(1)
			} else if w.Code != 401 {
				t.Errorf("unexpected status %d body=%s", w.Code, w.Body.String())
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners=%d", winners.Load())
	}
}
func TestChatTicketExpiresOrRevokesBeforeRedemption(t *testing.T) {
	for _, change := range []string{"expired", "disabled", "service", "password_change", "directory", "binding_changed", "binding_deleted"} {
		t.Run(change, func(t *testing.T) {
			e, u, _ := chatLoginFixture(t)
			ticket := chatFixtureTicket(t, e, u)
			ctx := context.Background()
			var err error
			switch change {
			case "expired":
				_, err = e.pool.Exec(ctx, "UPDATE chat_login_tickets SET expires_at=NOW()-interval '1 second' WHERE user_id=$1", u.ID)
			case "disabled":
				_, err = e.pool.Exec(ctx, "UPDATE users SET status='disabled' WHERE id=$1", u.ID)
			case "service":
				_, err = e.pool.Exec(ctx, "UPDATE users SET role='platform_connector',department_id=NULL,department_assignment_mode='service' WHERE id=$1", u.ID)
			case "password_change":
				_, err = e.pool.Exec(ctx, "UPDATE users SET must_change_password=TRUE WHERE id=$1", u.ID)
			case "directory":
				_, err = e.pool.Exec(ctx, "INSERT INTO user_identity_links(id,tenant_id,user_id,issuer,source_type,source_id,external_subject) VALUES($1,$2,$3,'directory-source','ldap','directory-source','directory-subject')", u.ID+"-dir", e.tenantID, u.ID)
			case "binding_changed":
				_, err = e.pool.Exec(ctx, "UPDATE user_identity_links SET external_subject='different-trusted-subject' WHERE user_id=$1", u.ID)
			case "binding_deleted":
				_, err = e.pool.Exec(ctx, "DELETE FROM user_identity_links WHERE user_id=$1", u.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			w := redeemFixtureTicket(e, e.tenantID, ticket, "", true)
			if w.Code != 401 {
				t.Fatalf("revoked ticket redeemed: status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
func TestChatUserManagementHardDenyWithRBACDryRun(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	if err := e.sessions.Create(context.Background(), &repository.Session{ID: u.ID + "-session", UserID: u.ID, TenantID: e.tenantID, Role: "chat_user"}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/admin/v1/users", "/admin/v1/providers", "/admin/v1/system/settings", "/admin/v1/stats/overview"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer "+u.ID+"-session")
		w := httptest.NewRecorder()
		downstream := permission.Middleware(nil, e.pool, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("Chat user reached RBAC dry-run downstream") }))
		auth.Middleware(e.sessions, e.deps.UserRepo)(downstream).ServeHTTP(w, request)
		if w.Code != 403 {
			t.Fatalf("%s status=%d", path, w.Code)
		}
	}
}
func TestChatTicketWaitsForRealPasswordChangeAndRevokesEveryOldSession(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	ctx := context.Background()
	priorTicket := chatFixtureTicket(t, e, u)
	if _, err := e.pool.Exec(ctx, "UPDATE users SET must_change_password=TRUE WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	token := u.ID + "-pre-upgrade-session"
	if err := e.sessions.Create(ctx, &repository.Session{ID: token, UserID: u.ID, TenantID: e.tenantID, Role: "chat_user"}); err != nil {
		t.Fatal(err)
	}
	otherToken := u.ID + "-old-session"
	if err := e.sessions.Create(ctx, &repository.Session{ID: otherToken, UserID: u.ID, TenantID: e.tenantID, Role: "chat_user"}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/me/chat-login", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	route := auth.Middleware(e.sessions, e.deps.UserRepo)(CreateChatLoginTicket(e.deps))
	w := httptest.NewRecorder()
	route.ServeHTTP(w, request)
	if w.Code != 403 {
		t.Fatal("required password change bypassed")
	}
	changed := e.employeeLogin(u.Username, u.Password, "192.0.2.1", map[string]string{"new_password": "Changed-Horse-2026!"})
	if changed.Code != 200 {
		t.Fatalf("password change=%d %s", changed.Code, changed.Body.String())
	}
	for _, old := range []string{token, otherToken} {
		if session, err := e.sessions.Get(ctx, old); err != nil || session != nil {
			t.Fatalf("old session survives: %v", err)
		}
	}
	var response struct {
		Ticket string `json:"chat_ticket"`
	}
	if err := json.Unmarshal(changed.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Ticket == "" {
		t.Fatalf("real password change must return a fresh ticket, body=%s", changed.Body.String())
	}
	w = httptest.NewRecorder()
	route.ServeHTTP(w, request)
	if w.Code != 401 {
		t.Fatalf("revoked token still accepted: %d", w.Code)
	}
	redeemed := redeemFixtureTicket(e, e.tenantID, response.Ticket, "", true)
	if redeemed.Code != 200 {
		t.Fatalf("new ticket cannot enter Chat: %d %s", redeemed.Code, redeemed.Body.String())
	}
	if oldProof := redeemFixtureTicket(e, e.tenantID, priorTicket, "", true); oldProof.Code != 401 {
		t.Fatalf("pre-rotation ticket revived after password change: %d %s", oldProof.Code, oldProof.Body.String())
	}
	if rejected := e.employeeLogin(u.Username, u.Password, "192.0.2.1", nil); rejected.Code != 401 {
		t.Fatal("old password still works")
	}
}

func TestNewUserDatabaseDefaultIsChatUser(t *testing.T) {
	e, u, dept := chatLoginFixture(t)
	if _, err := e.pool.Exec(context.Background(), "INSERT INTO users(id,tenant_id,username,status,department_id,department_assignment_mode) VALUES($1,$2,$1,'active',$3,'manual')", u.ID+"-default", e.tenantID, dept); err != nil {
		t.Fatal(err)
	}
	var role string
	if err := e.pool.QueryRow(context.Background(), "SELECT role FROM users WHERE id=$1", u.ID+"-default").Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "chat_user" {
		t.Fatalf("DB default role=%s want chat_user", role)
	}
}

func TestChatUserOldSessionCannotUseFullConsoleChain(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, "UPDATE users SET must_change_password=TRUE WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	token := u.ID + "-pre-upgrade-session"
	if err := e.sessions.Create(ctx, &repository.Session{ID: token, UserID: u.ID, TenantID: e.tenantID, Role: "chat_user"}); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Use(auth.Middleware(e.sessions, e.deps.UserRepo))
	router.Use(permission.SoDGuard(e.pool))
	router.Use(permission.Middleware(permission.NewChecker(e.pool, permission.NewGrantsCache()), e.pool, false))
	router.Post("/admin/v1/logout", Logout(e.deps))
	for _, path := range []string{"/admin/v1/users", "/admin/v1/providers", "/admin/v1/logout", "/admin/v1/logout/other"} {
		router.Get(path, func(http.ResponseWriter, *http.Request) {
			t.Fatal("restricted Chat user reached management or GET logout")
		})
	}
	router.Post("/admin/v1/logout/other", func(http.ResponseWriter, *http.Request) { t.Fatal("logout prefix bypass") })
	for _, route := range []struct{ method, path string }{{"GET", "/admin/v1/users"}, {"GET", "/admin/v1/providers"}, {"GET", "/admin/v1/logout"}, {"POST", "/admin/v1/logout/other"}} {
		request := httptest.NewRequest(route.method, route.path, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != 403 {
			t.Fatalf("%s %s status=%d body=%s", route.method, route.path, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/logout", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("legacy console logout status=%d", response.Code)
	}

}

func TestChatLocalLoginAndAuthorizationDoNotRequireSSOIssuer(t *testing.T) {
	for _, issuer := range []string{"", "https://issuer.test"} {
		t.Run(issuer, func(t *testing.T) {
			e, u, _ := chatLoginFixture(t)
			e.deps.IdentityRuntimeConfig.IssuerURL = issuer
			ticket := chatFixtureTicket(t, e, u)
			w := redeemFixtureTicket(e, e.tenantID, ticket, "", true)
			if w.Code != http.StatusOK {
				t.Fatalf("local redemption status=%d body=%s", w.Code, w.Body.String())
			}
			identity, err := e.deps.ChatLoginTickets.CurrentIdentity(context.Background(), e.tenantID, u.ID, issuer)
			if err != nil || identity == nil || identity.ExternalSubject != "trusted-local-subject" {
				t.Fatalf("local recheck: identity=%+v err=%v", identity, err)
			}

			e.deps.TeamModelRepo = repository.NewTeamModelRepository(e.pool)
			request := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/users/"+u.ID+"/authorization", nil)
			request.Header.Set("X-JJDGuard-Tenant-Id", e.tenantID)
			route := chi.NewRouteContext()
			route.URLParams.Add("id", u.ID)
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
			authorization := httptest.NewRecorder()
			GetPortalUserAuthorizationContext(e.deps).ServeHTTP(authorization, request)
			if authorization.Code != http.StatusOK {
				t.Fatalf("authorization status=%d body=%s", authorization.Code, authorization.Body.String())
			}
			var payload struct {
				Data struct {
					LocalLoginAllowed    bool   `json:"local_login_allowed"`
					LocalExternalSubject string `json:"local_external_subject"`
				} `json:"data"`
			}
			if err := json.Unmarshal(authorization.Body.Bytes(), &payload); err != nil || !payload.Data.LocalLoginAllowed || payload.Data.LocalExternalSubject != identity.ExternalSubject {
				t.Fatalf("local authority not exposed: %s err=%v", authorization.Body.String(), err)
			}
		})
	}
}

func TestChatLocalConversationBindingIsStrictWithoutSSOAndNeverFallsBack(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	e.deps.IdentityRuntimeConfig.IssuerURL = ""
	e.deps.TeamModelRepo = repository.NewTeamModelRepository(e.pool)
	check := func(query string, secret bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/users/"+u.ID+"/authorization-context?"+query, nil)
		request.Header.Set("X-JJDGuard-Tenant-Id", e.tenantID)
		if secret {
			request.Header.Set("Authorization", "Bearer isolated-portal-secret")
		}
		route := chi.NewRouteContext()
		route.URLParams.Add("id", u.ID)
		request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
		response := httptest.NewRecorder()
		PortalIntegrationAPIMiddleware("isolated-portal-secret", e.deps)(GetPortalUserAuthorizationContext(e.deps)).ServeHTTP(response, request)
		return response
	}
	for _, query := range []string{"external_subject=trusted-local-subject&login_mode=local", "external_subject=forged-subject&login_mode=local", "login_mode=local", "external_subject=trusted-local-subject&login_mode=forged"} {
		response := check(query, true)
		want := http.StatusNotFound
		if strings.Contains(query, "external_subject=trusted-local-subject&login_mode=local") {
			want = http.StatusOK
		}
		if strings.Contains(query, "login_mode=forged") {
			want = http.StatusBadRequest
		}
		if response.Code != want {
			t.Fatalf("query=%s status=%d want=%d body=%s", query, response.Code, want, response.Body.String())
		}
	}
	if response := check("external_subject=trusted-local-subject&login_mode=local", false); response.Code == http.StatusOK {
		t.Fatal("untrusted local mode accepted")
	}
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO user_identity_links(id,tenant_id,user_id,issuer,source_type,source_id,external_subject) VALUES($1,$2,$3,'https://directory.test','ldap','https://directory.test','directory-subject')`, u.ID+"-directory", e.tenantID, u.ID); err != nil {
		t.Fatal(err)
	}
	if response := check("external_subject=trusted-local-subject&login_mode=local", true); response.Code != http.StatusNotFound {
		t.Fatalf("directory takeover must deny local binding without fallback: status=%d body=%s", response.Code, response.Body.String())
	}
}
