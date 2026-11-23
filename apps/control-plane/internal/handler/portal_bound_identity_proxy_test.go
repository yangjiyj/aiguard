package handler

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
)

// Exercises the real proxy process, real gateway process, real control-plane
// handlers, PG authorization and current managed employee credentials. The provider is an isolated
// HTTP fixture; no customer or external model service receives a request.
func TestPortalBoundIdentityProxyAndRealGateway(t *testing.T) {
	gatewayBinary := os.Getenv("PORTAL_PROXY_GATEWAY_TEST_BINARY")
	if gatewayBinary == "" {
		t.Skip("PORTAL_PROXY_GATEWAY_TEST_BINARY is required for the process integration test")
	}
	deps, pool, tenant, userID, project := portalProjectFixture(t)
	deps.EmployeeKeyRepo = repository.NewEmployeeAPIKeyRepository(pool)
	deps.ChatLoginTickets = repository.NewChatLoginTicketRepository(pool)
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "portal-integration-fixture-encryption")
	t.Setenv("JJD_MASTER_KEY", "")
	ctx := context.Background()
	var dept string
	if err := pool.QueryRow(ctx, "SELECT department_id FROM users WHERE id=$1", userID).Scan(&dept); err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, "UPDATE users SET role='developer' WHERE id=$1", userID)
	// Personal model access and membership are customer-owned test fixtures.
	localID, secondID := tenant+"-local", tenant+"-second"
	for _, id := range []string{localID, secondID} {
		mustExec(t, pool, `INSERT INTO users(id,tenant_id,username,role,status,department_id,department_assignment_mode) VALUES($1,$2,$1,'chat_user','active',$3,'manual')`, id, tenant, dept)
		if err := repository.NewUserIdentityLinkRepository(pool).BindLoginSources(ctx, tenant, id, "https://portal-project.test", id+"-subject"); err != nil {
			t.Fatal(err)
		}
	}
	nextDept := ensureDepartment(t, pool, tenant, "marketing")
	nextProject := tenant + "-marketing-app"
	mustExec(t, pool, `UPDATE teams SET model_access_mode='all_active' WHERE tenant_id=$1`, tenant)
	mustExec(t, pool, `INSERT INTO projects(id,tenant_id,name,team_id,status,code,environment) VALUES($1,$2,'Marketing Chat',$3,'active','fixture','test')`, nextProject, tenant, nextDept)
	mustExec(t, pool, `INSERT INTO model_policies(id,tenant_id,project_id,scope_type,allow_models_json,deny_models_json) VALUES($1,$2,$3,'project','[]','["app-denied"]'),($4,$2,$5,'project','[]','["app-denied"]')`, project+"-policy", tenant, project, nextProject+"-policy", nextProject)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"fixture-response","object":"chat.completion","model":"callable-model","choices":[{"index":0,"message":{"role":"assistant","content":"isolated fixture reply"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	defer upstream.Close()
	ciphertext, keyRef, err := secrets.EncryptProviderSecret("fixture-upstream-key")
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"ready", "no-credential", "no-endpoint"} {
		url := upstream.URL
		if suffix == "no-endpoint" {
			url = ""
		}
		provider := tenant + "-" + suffix
		mustExec(t, pool, `INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,status) VALUES($1,$2,$3,'custom',$4,'api_key','active')`, provider, tenant, suffix, url)
		if suffix != "no-credential" {
			mustExec(t, pool, `INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status) VALUES($1,$2,'fixture',$3,$4,'active')`, provider+"-credential", provider, ciphertext, keyRef)
		}
	}
	for _, name := range []string{"callable-model", "personal-other", "app-denied", "no-credential", "no-endpoint", "unsupported-protocol"} {
		suffix := "ready"
		if name == "no-credential" || name == "no-endpoint" {
			suffix = name
		}
		model := tenant + "-" + name
		mustExec(t, pool, `INSERT INTO models(id,provider_id,model_name,status) VALUES($1,$2,$3,'active')`, model, tenant+"-"+suffix, name)
		state := "supported"
		if name == "unsupported-protocol" {
			state = "unsupported"
		}
		if name != "no-endpoint" {
			mustExec(t, pool, `INSERT INTO model_endpoint_capability_overrides(id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id,config_version) VALUES($1,$2,$3,'chat',$5,'isolated fixture',$4,1)`, model+"-override", tenant, model, userID, state)
		}
	}
	mustExec(t, pool, "UPDATE teams SET model_access_mode='allowlist' WHERE tenant_id=$1", tenant)
	mustExec(t, pool, "INSERT INTO team_models(team_id,model_id,allowed) SELECT d.id,m.id,TRUE FROM teams d JOIN providers p ON p.tenant_id=d.tenant_id JOIN models m ON m.provider_id=p.id WHERE d.tenant_id=$1 AND m.model_name<>'app-denied'", tenant)
	mustExec(t, pool, `INSERT INTO user_model_policies(tenant_id,user_id,mode,model_names,updated_by) VALUES($1,$2,'allowlist','["callable-model"]',$3)`, tenant, secondID, userID)
	t.Cleanup(func() {
		for _, statement := range []string{
			`DELETE FROM request_audit_logs WHERE tenant_id=$1`,
			`DELETE FROM model_endpoint_capability_overrides WHERE tenant_id=$1`,
			`DELETE FROM model_catalog_entries WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`,
			`DELETE FROM team_models WHERE team_id IN(SELECT id FROM teams WHERE tenant_id=$1)`,
			`DELETE FROM models WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`,
			`DELETE FROM provider_credentials WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`,
			`DELETE FROM providers WHERE tenant_id=$1`,
		} {
			_, _ = pool.Exec(context.Background(), statement, tenant)
		}
	})
	system := newConsoleTestSystemRepo()
	system.values["chat_portal_enabled"] = "true"
	deps.SystemRepo = system
	var identityWrites atomic.Int32
	router := chi.NewRouter()
	router.Use(PortalIntegrationAPIMiddleware("fixture-portal-secret", deps))
	router.Post("/admin/v1/portal-integration/users", func(w http.ResponseWriter, r *http.Request) { identityWrites.Add(1); EnsurePortalUser(deps)(w, r) })
	router.Get("/admin/v1/portal-integration/users/{id}/authorization-context", GetPortalUserAuthorizationContext(deps))
	router.Get("/admin/v1/portal-integration/employee-key/credential", EmployeeKeyEndpoint(deps, "credential"))
	router.Post("/admin/v1/portal-integration/employee-key/reset", EmployeeKeyEndpoint(deps, "reset"))
	router.Post("/admin/v1/portal-integration/keys", CreatePortalKey(deps))
	router.Post("/admin/v1/portal-integration/keys/{id}/revoke", RevokePortalKey(deps))
	router.Get("/admin/v1/portal-integration/system/chat-portal-status", GetPortalChatPortalStatus(deps))
	router.Post("/admin/v1/portal-integration/employee-key/ensure", EmployeeKeyEndpoint(deps, "ensure"))
	cp := httptest.NewServer(router)
	defer cp.Close()
	redis := miniredis.RunT(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	fixtureDir := t.TempDir()
	gatewayLog, err := os.Create(filepath.Join(fixtureDir, "gateway.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer gatewayLog.Close()
	gateway := exec.Command(gatewayBinary)
	gateway.Env = append(os.Environ(), "LISTEN_ADDR="+addr, "PROXY_LISTEN_ADDR=127.0.0.1:0", "PROXY_ENABLED=false", "DATABASE_URL="+os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL"), "REDIS_URL=redis://"+redis.Addr(), "CONTROL_PLANE_URL="+cp.URL, "UAG_GOVERNOR_DISABLED=true", "SECURITY_AUDIT_ONLY=true", "BILLING_ENABLED=false", "BILLING_MODE=off", "JJD_INTERNAL_API_SECRET=fixture-internal-secret")
	gateway.Stdout = gatewayLog
	gateway.Stderr = gatewayLog
	if err := gateway.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Process.Kill(); _ = gateway.Wait() })
	gatewayURL := "http://" + addr
	ready := false
	for i := 0; i < 200; i++ {
		response, err := http.Get(gatewayURL + "/live")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		logs, _ := os.ReadFile(gatewayLog.Name())
		t.Fatalf("isolated gateway readiness: %s", logs)
	}
	proxyRoot, err := filepath.Abs("../../../../portal-proxy")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("node", "--import", "tsx", "test/fixtures/bound-identity-gateway.ts")
	command.Dir = proxyRoot
	command.Env = append(os.Environ(), "TEST_CP_URL="+cp.URL, "TEST_GATEWAY_URL="+gatewayURL, "TEST_TENANT="+tenant, "TEST_AUTOMATIC_USER="+userID, "TEST_LOCAL_USER="+localID, "TEST_SECOND_USER="+secondID, "TEST_PROJECT="+project, "TEST_DEPARTMENT="+dept, "TEST_NEXT_DEPARTMENT="+nextDept, "TEST_NEXT_PROJECT="+nextProject)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("real bound proxy flow: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
	if identityWrites.Load() != 0 {
		t.Fatalf("bound reads/Chat reconstructed identities %d times", identityWrites.Load())
	}
}
