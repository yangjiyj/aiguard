package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func standaloneUserAPIFixture(t *testing.T) (*consoleLoginEnv, string, string, *httptest.Server) {
	t.Helper()
	e, _, _ := managedEmployeeFixture(t)
	ctx := context.Background()
	admin := e.createUser("platform_admin", "active", "Correct-Horse-Admin-42")
	token := admin.ID + "-standalone-create"
	if err := e.sessions.Create(ctx, &repository.Session{ID: token, UserID: admin.ID, TenantID: e.tenantID, Role: "platform_admin"}); err != nil {
		t.Fatal(err)
	}
	dept := ensureDepartment(t, e.pool, e.tenantID, "standalone-office")
	project := dept + "-chat"
	if _, err := e.pool.Exec(ctx, `INSERT INTO projects(id,tenant_id,name,team_id,status,code,environment) VALUES($1,$2,'Standalone Chat',$3,'active','standalone','test')`, project, e.tenantID, dept); err != nil {
		t.Fatal(err)
	}
	provisioner, err := localidentity.NewStandaloneProvisioner(e.pool)
	if err != nil {
		t.Fatal(err)
	}
	e.deps.LocalIdentityProvisioner = provisioner
	e.deps.LocalIdentityClient = nil
	e.deps.IdentityRuntimeConfig.IssuerURL = ""
	e.deps.DepartmentStore = repository.NewTeamRepository(e.pool)
	e.deps.TenantRepo = repository.NewTenantRepository(e.pool)
	router := chi.NewRouter()
	router.Use(auth.Middleware(e.sessions, e.deps.UserRepo))
	router.Post("/admin/v1/users", CreateUser(e.deps))
	router.Patch("/admin/v1/users/{id}/status", ToggleUserStatus(e.deps))
	router.Post("/admin/v1/users/{id}/reset-password", ResetPassword(e.deps))
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return e, dept, token, server
}
func standaloneUserAPI(t *testing.T, server *httptest.Server, token, method, path string, payload any) (int, map[string]json.RawMessage) {
	t.Helper()
	body, _ := json.Marshal(payload)
	request, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
	request.Header.Set("content-type", "application/json")
	request.Header.Set("authorization", "Bearer "+token)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	var data map[string]json.RawMessage
	if len(raw) > 0 {
		if json.Unmarshal(raw, &data) != nil {
			t.Fatal("invalid standalone official API response")
		}
	}
	return response.StatusCode, data
}
func TestStandaloneOfficialLocalUserCreateLoginKeyPasswordStatusAndLaterSSO(t *testing.T) {
	e, dept, token, server := standaloneUserAPIFixture(t)
	username := e.tenantID + "-standalone-employee"
	password := "Correct-Horse-42"
	status, created := standaloneUserAPI(t, server, token, "POST", "/admin/v1/users", map[string]any{"tenant_id": e.tenantID, "username": username, "password": password, "department_id": dept})
	var id, role string
	json.Unmarshal(created["id"], &id)
	json.Unmarshal(created["role"], &role)
	if status != 201 && status != 200 || id == "" || role != "chat_user" {
		t.Fatalf("official standalone creation status=%d", status)
	}
	var native bool
	var issuer, subject string
	if err := e.pool.QueryRow(context.Background(), "SELECT issuer,external_subject,local_runtime_managed FROM user_identity_links WHERE user_id=$1 AND source_type='local'", id).Scan(&issuer, &subject, &native); err != nil || native || issuer != "urn:jjdguard:local" || subject != id {
		t.Fatal("official standalone identity ownership is not trusted and CP-only")
	}
	login := e.employeeLogin(username, password, "192.0.2.1", nil)
	var reply struct {
		Ticket string `json:"chat_ticket"`
		Token  string `json:"token"`
	}
	json.Unmarshal(login.Body.Bytes(), &reply)
	if login.Code != 200 || reply.Ticket == "" || reply.Token != "" {
		t.Fatalf("official standalone login status=%d", login.Code)
	}
	if redeemed := redeemFixtureTicket(e, e.tenantID, reply.Ticket, "", true); redeemed.Code != 200 {
		t.Fatalf("official standalone ticket status=%d", redeemed.Code)
	}
	key, err := e.deps.EmployeeKeyRepo.Current(context.Background(), e.tenantID, id, 1)
	if err != nil || key == nil || key.UserID != id {
		t.Fatal("official standalone login did not create personal Key")
	}
	// Adding an enterprise runtime later never converts existing CP-only
	// credentials into native credentials or invalidates their trusted link.
	e.deps.IdentityRuntimeConfig.IssuerURL = "https://later-enterprise.test"
	configured, err := localidentity.NewProvisioner(e.pool, e.deps.IdentityRuntimeConfig.IssuerURL)
	if err != nil {
		t.Fatal(err)
	}
	e.deps.LocalIdentityProvisioner = configured
	changed := e.employeeLogin(username, password, "192.0.2.1", map[string]string{"new_password": "Changed-Horse-2026!"})
	if changed.Code != 200 {
		t.Fatalf("standalone after enterprise configuration change status=%d", changed.Code)
	}
	current, err := e.deps.UserRepo.GetByID(context.Background(), id)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(current.PasswordHash), []byte("Changed-Horse-2026!")) != nil {
		t.Fatal("standalone password did not update without a native client")
	}
	if status, _ := standaloneUserAPI(t, server, token, "POST", "/admin/v1/users/"+id+"/reset-password", map[string]string{"password": "Admin-Chosen-Horse-77"}); status != 200 {
		t.Fatalf("standalone admin reset status=%d", status)
	}
	var before int64
	e.pool.QueryRow(context.Background(), "SELECT local_credential_version FROM users WHERE id=$1", id).Scan(&before)
	if status, _ := standaloneUserAPI(t, server, token, "PATCH", "/admin/v1/users/"+id+"/status", map[string]string{"status": "disabled"}); status != 200 {
		t.Fatalf("standalone disable status=%d", status)
	}
	var after int64
	e.pool.QueryRow(context.Background(), "SELECT local_credential_version FROM users WHERE id=$1", id).Scan(&after)
	if after <= before {
		t.Fatal("standalone disable kept old local session epoch")
	}
	if status, _ := standaloneUserAPI(t, server, token, "PATCH", "/admin/v1/users/"+id+"/status", map[string]string{"status": "active"}); status != 200 {
		t.Fatalf("standalone enable status=%d", status)
	}
	if response := e.employeeLogin(username, "Admin-Chosen-Horse-77", "192.0.2.1", nil); response.Code != 200 {
		t.Fatalf("re-enabled standalone login status=%d", response.Code)
	}
	var audits int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_operations WHERE target_id=$1 AND action_type='user.create' AND action_detail->>'credential_owner'='standalone'", id).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("standalone official creation has no credential-owner audit")
	}
}
func TestStandaloneOfficialLocalUserCreateEnforcesPolicyTenantAndRole(t *testing.T) {
	e, dept, token, server := standaloneUserAPIFixture(t)
	base := map[string]any{"tenant_id": e.tenantID, "username": e.tenantID + "-standalone-denial", "password": "Correct-Horse-42", "department_id": dept}
	for _, tc := range []struct {
		name, field string
		value       any
		expected    int
	}{{"weak", "password", "weak", 400}, {"foreign-department", "department_id", "foreign-department", 404}, {"foreign-tenant", "tenant_id", "foreign-tenant", 404}, {"invalid-role", "role", "forged-platform-superuser", 400}} {
		t.Run(tc.name, func(t *testing.T) {
			req := map[string]any{}
			for k, v := range base {
				req[k] = v
			}
			req[tc.field] = tc.value
			status, _ := standaloneUserAPI(t, server, token, "POST", "/admin/v1/users", req)
			if status != tc.expected {
				t.Fatalf("denial=%s status=%d", tc.name, status)
			}
		})
	}
	var count int
	e.pool.QueryRow(context.Background(), "SELECT count(*) FROM users WHERE username=$1", base["username"]).Scan(&count)
	if count != 0 {
		t.Fatal("denied standalone request created an account")
	}
	// A partially configured native runtime never chooses the standalone path.
	configured, err := localidentity.NewProvisioner(e.pool, "https://configured.test")
	if err != nil {
		t.Fatal(err)
	}
	e.deps.LocalIdentityProvisioner = configured
	e.deps.LocalIdentityClient = nil
	if status, _ := standaloneUserAPI(t, server, token, "POST", "/admin/v1/users", base); status != 503 {
		t.Fatalf("native outage degraded to standalone status=%d", status)
	}
	// Nonadministrator machine sessions cannot create ordinary local accounts.
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/users", strings.NewReader(`{}`))
	request = request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{Role: "platform_connector"}))
	response := httptest.NewRecorder()
	CreateUser(e.deps)(response, request)
	if response.Code != 403 {
		t.Fatalf("connector create status=%d", response.Code)
	}
}

func TestNativeLocalLoginStillRequiresItsConfiguredRuntimeIssuer(t *testing.T) {
	e, u, _ := managedEmployeeFixture(t)
	if _, err := e.pool.Exec(context.Background(), "UPDATE user_identity_links SET local_runtime_managed=TRUE WHERE user_id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	e.deps.IdentityRuntimeConfig.IssuerURL = ""
	if response := e.employeeLogin(u.Username, u.Password, "192.0.2.1", nil); response.Code != 403 {
		t.Fatalf("native account silently became standalone status=%d", response.Code)
	}
}
