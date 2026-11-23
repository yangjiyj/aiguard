package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/authhelpers"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestUserModelAccessSameDepartmentCatalogCallsAndRevocation(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("JJD_REQUIRE_IDENTITY_DB_TESTS") == "1" {
			t.Fatal("isolated test database is required")
		}
		t.Skip("isolated database not configured")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	tenant := fmt.Sprintf("um_%d", time.Now().UnixNano())
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1::varchar,$1::varchar,'enterprise','active',true)`, tenant)
	exec(`INSERT INTO teams(id,tenant_id,name,path,model_access_mode) VALUES($1::varchar||'_dept',$1::varchar,'same department','/'||$1::varchar,'allowlist')`, tenant)
	exec(`INSERT INTO users(id,tenant_id,username,email,role,status,department_id,department_assignment_mode) VALUES($1::varchar||'_u1',$1::varchar,$1::varchar||'_u1','u1@test.invalid','chat_user','active',$1::varchar||'_dept','manual'),($1::varchar||'_u2',$1::varchar,$1::varchar||'_u2','u2@test.invalid','chat_user','active',$1::varchar||'_dept','manual')`, tenant)
	exec(`INSERT INTO projects(id,tenant_id,name,status,team_id) VALUES($1::varchar||'_proj',$1::varchar,'fixture','active',$1::varchar||'_dept')`, tenant)
	exec(`INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,status) VALUES($1::varchar||'_provider',$1::varchar,'fixture','custom','https://fixture.invalid','api_key','active')`, tenant)
	exec(`INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status) VALUES($1::varchar||'_credential',$1::varchar||'_provider','fixture','fixture','fixture','active')`, tenant)
	exec(`INSERT INTO models(id,provider_id,model_name,status) VALUES($1::varchar||'_ma',$1::varchar||'_provider','shared-a','active'),($1::varchar||'_mb',$1::varchar||'_provider','shared-b','active')`, tenant)
	exec(`INSERT INTO team_models(team_id,model_id,allowed) VALUES($1::varchar||'_dept',$1::varchar||'_ma',true),($1::varchar||'_dept',$1::varchar||'_mb',true)`, tenant)
	exec(`INSERT INTO model_endpoint_capability_overrides(id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id,config_version) SELECT 'ov_'||m.id,$1::varchar,m.id,'chat','supported','fixture',$1::varchar||'_u1',1 FROM models m WHERE m.provider_id=$1::varchar||'_provider'`, tenant)
	exec(`INSERT INTO user_model_policies(tenant_id,user_id,mode,model_names,updated_by) VALUES($1::varchar,$1::varchar||'_u1','allowlist','["shared-a","shared-b"]',$1::varchar||'_u1'),($1::varchar,$1::varchar||'_u2','allowlist','["shared-a"]',$1::varchar||'_u1')`, tenant)
	t.Cleanup(func() {
		for _, sql := range []string{
			`DELETE FROM model_endpoint_capability_overrides WHERE tenant_id=$1::varchar`,
			`DELETE FROM model_catalog_entries WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id=$1::varchar)`,
			`DELETE FROM team_models WHERE team_id IN (SELECT id FROM teams WHERE tenant_id=$1::varchar)`,
			`DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id=$1::varchar)`,
			`DELETE FROM provider_credentials WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id=$1::varchar)`,
			`DELETE FROM providers WHERE tenant_id=$1::varchar`, `DELETE FROM projects WHERE tenant_id=$1::varchar`,
			`DELETE FROM team_members WHERE user_id IN(SELECT id FROM users WHERE tenant_id=$1::varchar)`,
			`DELETE FROM users WHERE tenant_id=$1::varchar`, `DELETE FROM teams WHERE tenant_id=$1::varchar`, `DELETE FROM tenants WHERE id=$1::varchar`,
		} {
			if _, err := db.Exec(context.Background(), sql, tenant); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	})
	gate := auth.UserModelAuthorization(func(c context.Context, tenantID, userID string) (*modelaccess.Access, error) {
		return modelaccess.ReadAccess(c, db, tenantID, userID)
	})
	catalog := gate(NewModelsHandler(db).Handler())
	caller := &MockProviderCaller{}
	resolver := &MockModelResolver{QuotaPolicy: &modelrouter.QuotaPolicy{EnforcementMode: "bypass"}}
	chat := gate(NewChatCompletionsHandler(&config.Config{SecurityAuditOnly: true}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: caller}, nil, nil).Handler())
	call := func(handler http.Handler, user, path, body string) *httptest.ResponseRecorder {
		method := http.MethodPost
		if body == "" {
			method = http.MethodGet
		}
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		c := context.WithValue(r.Context(), auth.TenantKey, tenant)
		c = context.WithValue(c, auth.UserKey, tenant+"_"+user)
		c = context.WithValue(c, auth.ProjectKey, tenant+"_proj")
		c = context.WithValue(c, auth.KeyIDKey, "fixture-key")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r.WithContext(c))
		return w
	}
	for _, tc := range []struct {
		user  string
		count int
	}{{"u1", 2}, {"u2", 1}} {
		w := call(catalog, tc.user, "/v1/models", "")
		var data ModelsResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &data) != nil || len(data.Data) != tc.count {
			t.Fatalf("user %s catalog: %d %s", tc.user, w.Code, w.Body.String())
		}
	}

	t.Run("RestrictedKeyHTTPAdmissionAndLiveRevocation", func(t *testing.T) {
		raw := "fixture-restricted-key-" + tenant
		exec("INSERT INTO internal_keys(id,tenant_id,user_id,project_id,key_hash,key_prefix,status,scopes_json,model_allowlist) VALUES($1::varchar||'_restricted',$1::varchar,$1::varchar||'_u1',$1::varchar||'_proj',$2,'fixture','active','[\"chat\",\"models\"]',ARRAY['shared-a'])", tenant, authhelpers.HashKey(raw))
		defer exec("DELETE FROM internal_keys WHERE id=$1::varchar||'_restricted'", tenant)
		middleware := auth.NewAuthMiddleware(db, nil, nil).Middleware(&config.Config{})
		mux := http.NewServeMux()
		mux.Handle("/v1/chat/completions", middleware(chat))
		mux.Handle("/v1/models", middleware(catalog))
		server := httptest.NewServer(mux)
		defer server.Close()
		request := func(path, body string) (int, string) {
			method := "POST"
			if body == "" {
				method = "GET"
			}
			req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+raw)
			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			payload, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			return response.StatusCode, string(payload)
		}
		before := len(caller.CallCalls)
		code, body := request("/v1/chat/completions", `{"model":"shared-b","messages":[{"role":"user","content":"hi"}]}`)
		if code != 403 || !strings.Contains(body, "key_model_not_allowed") || len(caller.CallCalls) != before {
			t.Fatalf("restricted denial=%d calls=%d", code, len(caller.CallCalls))
		}
		code, _ = request("/v1/chat/completions", `{"model":"shared-a","messages":[{"role":"user","content":"hi"}]}`)
		if code != 200 || len(caller.CallCalls) != before+1 {
			t.Fatalf("allowed call=%d", code)
		}
		code, body = request("/v1/models", "")
		if code != 200 || !strings.Contains(body, "shared-a") || strings.Contains(body, "shared-b") {
			t.Fatal("catalog bypassed key limits")
		}
		exec(`UPDATE user_model_policies SET model_names='[]' WHERE tenant_id=$1 AND user_id=$1::varchar||'_u1'`, tenant)
		code, _ = request("/v1/chat/completions", `{"model":"shared-a","messages":[{"role":"user","content":"hi"}]}`)
		exec(`UPDATE user_model_policies SET model_names='["shared-a","shared-b"]' WHERE tenant_id=$1 AND user_id=$1::varchar||'_u1'`, tenant)
		if code != 403 || len(caller.CallCalls) != before+1 {
			t.Fatal("live user revocation bypassed")
		}
		// Keep pre-existing outer assertions independent of this additional request.
		caller.CallCalls = caller.CallCalls[:before]
	})
	forbidden := `{"model":"shared-b","messages":[{"role":"user","content":"hi"}]}`
	w := call(chat, "u2", "/v1/chat/completions", forbidden)
	if w.Code != 403 || len(caller.CallCalls) != 0 {
		t.Fatalf("must deny before upstream: %d calls=%d body=%s", w.Code, len(caller.CallCalls), w.Body.String())
	}
	allowed := `{"model":"shared-a","messages":[{"role":"user","content":"hi"}]}`
	w = call(chat, "u2", "/v1/chat/completions", allowed)
	if w.Code != 200 || len(caller.CallCalls) != 1 {
		t.Fatalf("authorized call: %d calls=%d body=%s", w.Code, len(caller.CallCalls), w.Body.String())
	}

	t.Run("ReviewAuthorizedUnavailableRouteIs503", func(t *testing.T) {
		defer exec("UPDATE provider_credentials SET status='active' WHERE provider_id=$1::varchar||'_provider'", tenant)
		exec("UPDATE provider_credentials SET status='inactive' WHERE provider_id=$1::varchar||'_provider'", tenant)
		access, err := modelaccess.ReadAccess(ctx, db, tenant, tenant+"_u2")
		if err != nil {
			t.Fatal(err)
		}
		if !access.Allows("shared-a") {
			t.Fatal("route health removed department authorization")
		}
		offline := gate(NewChatCompletionsHandler(&config.Config{SecurityAuditOnly: true}, &MockModelResolver{ResolveError: fmt.Errorf("no eligible route")}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: caller}, nil, nil).Handler())
		w := call(offline, "u2", "/v1/chat/completions", allowed)
		if w.Code != 503 || !strings.Contains(w.Body.String(), "model_route_unavailable") {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		denied := call(chat, "u2", "/v1/chat/completions", forbidden)
		if denied.Code != 403 {
			t.Fatalf("unauthorized status=%d", denied.Code)
		}
		exec("UPDATE provider_credentials SET status='active' WHERE provider_id=$1::varchar||'_provider'", tenant)
	})
	exec(`UPDATE user_model_policies SET model_names='[]',version=version+1 WHERE tenant_id=$1::varchar AND user_id=$1::varchar||'_u2'`, tenant)
	w = call(chat, "u2", "/v1/chat/completions", allowed)
	if w.Code != 403 || len(caller.CallCalls) != 1 {
		t.Fatalf("old key retained a revoked model: %d calls=%d", w.Code, len(caller.CallCalls))
	}
	exec(`UPDATE models SET status='inactive' WHERE id=$1::varchar||'_mb'`, tenant)
	w = call(catalog, "u1", "/v1/models", "")
	var data ModelsResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &data) != nil || len(data.Data) != 1 {
		t.Fatalf("disabled model survived: %d %s", w.Code, w.Body.String())
	}
	// A tenant-local unallowed name can collide with an allowed row's ID.
	// Authorization must use exactly the router's name-before-ID precedence.
	exec(`INSERT INTO models(id,provider_id,model_name,status) VALUES($1::varchar||'_shadow',$1::varchar||'_provider',$1::varchar||'_ma','active')`, tenant)
	current, readErr := modelaccess.ReadAccess(ctx, db, tenant, tenant+"_u1")
	if readErr != nil {
		t.Fatal(readErr)
	}
	resolved, found, resolveErr := modelrouter.NewModelRouter(db).ResolveLogicalModelName(ctx, tenant, tenant+"_ma")
	if resolveErr != nil || !found || resolved != tenant+"_ma" {
		t.Fatalf("resolver precedence: %q found=%v err=%v", resolved, found, resolveErr)
	}
	if current.AllowsReference(tenant + "_ma") {
		t.Fatal("an unallowed logical name bypassed permissions through another model's ID")
	}

	t.Run("ReviewExtraGrantRevocationAndExpiryImmediate", func(t *testing.T) {
		exec("UPDATE models SET status='active' WHERE id=$1::varchar||'_mb'", tenant)
		body := "{\"model\":\"shared-b\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"
		exec("INSERT INTO user_model_extra_grants(id,tenant_id,user_id,model,reason,created_by,created_at,expires_at) VALUES($1::varchar||'_extra_live',$1::varchar,$1::varchar||'_u2','shared-b','review fixture',$1::varchar||'_u1',now()-interval '1 day',now()+interval '1 hour')", tenant)
		if w := call(chat, "u2", "/v1/chat/completions", body); w.Code != 200 {
			t.Fatalf("extra admission=%d %s", w.Code, w.Body.String())
		}
		listing := call(catalog, "u2", "/v1/models", "")
		if listing.Code != 200 || !strings.Contains(listing.Body.String(), "shared-b") {
			t.Fatal("extra grant missing in model directory")
		}
		before := len(caller.CallCalls)
		exec("UPDATE user_model_extra_grants SET revoked_at=statement_timestamp() WHERE id=$1::varchar||'_extra_live'", tenant)
		if w := call(chat, "u2", "/v1/chat/completions", body); w.Code != 403 || len(caller.CallCalls) != before {
			t.Fatalf("revoke not immediate: %d calls=%d", w.Code, len(caller.CallCalls))
		}
		exec("INSERT INTO user_model_extra_grants(id,tenant_id,user_id,model,reason,created_by,created_at,expires_at) VALUES($1::varchar||'_extra_expiry',$1::varchar,$1::varchar||'_u2','shared-b','review expiry',$1::varchar||'_u1',now()-interval '1 day',now()+interval '1 hour')", tenant)
		if w := call(chat, "u2", "/v1/chat/completions", body); w.Code != 200 {
			t.Fatalf("expiring grant admission=%d", w.Code)
		}
		before = len(caller.CallCalls)
		exec("UPDATE user_model_extra_grants SET expires_at=statement_timestamp()-interval '1 second' WHERE id=$1::varchar||'_extra_expiry'", tenant)
		if w := call(chat, "u2", "/v1/chat/completions", body); w.Code != 403 || len(caller.CallCalls) != before {
			t.Fatalf("expiry not immediate: %d calls=%d", w.Code, len(caller.CallCalls))
		}
	})
	t.Run("ReviewDeveloperOwnedKeyWithoutPersonalPolicy", func(t *testing.T) {
		exec("UPDATE users SET role='developer' WHERE id=$1::varchar||'_u2'", tenant)
		exec("DELETE FROM user_model_policies WHERE tenant_id=$1 AND user_id=$1::varchar||'_u2'", tenant)
		exec("DELETE FROM team_models WHERE team_id=$1::varchar||'_dept' AND model_id=$1::varchar||'_mb'", tenant)
		raw := "review-owned-key-" + tenant
		exec("INSERT INTO internal_keys(id,tenant_id,user_id,project_id,key_hash,key_prefix,status,scopes_json) VALUES($1::varchar||'_real_key',$1::varchar,$1::varchar||'_u2',$1::varchar||'_proj',$2,'fixture','active','[\"chat\",\"models\"]')", tenant, authhelpers.HashKey(raw))
		realAuth := auth.NewAuthMiddleware(db, nil, nil).Middleware(&config.Config{})(chat)
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(forbidden))
		req.Header.Set("Authorization", "Bearer "+raw)
		before := len(caller.CallCalls)
		w := httptest.NewRecorder()
		realAuth.ServeHTTP(w, req)
		if w.Code != 403 || len(caller.CallCalls) != before {
			t.Fatalf("developer owner bypass=%d calls=%d body=%s", w.Code, len(caller.CallCalls), w.Body.String())
		}

		exec("INSERT INTO employee_api_keys(tenant_id,user_id,key_id,department_id,department_version,generation,issued_role) SELECT u.tenant_id,u.id,$1::varchar||'_real_key',u.department_id,u.department_version,1,u.role FROM users u WHERE u.id=$1::varchar||'_u2'", tenant)
		successReq := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(allowed))
		successReq.Header.Set("Authorization", "Bearer "+raw)
		fresh := httptest.NewRecorder()
		realAuth.ServeHTTP(fresh, successReq)
		if fresh.Code != 200 {
			t.Fatalf("fresh managed developer key=%d", fresh.Code)
		}
		exec("UPDATE users SET role='viewer' WHERE id=$1::varchar||'_u2'", tenant)
		changedReq := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(allowed))
		changedReq.Header.Set("Authorization", "Bearer "+raw)
		rejected := httptest.NewRecorder()
		realAuth.ServeHTTP(rejected, changedReq)
		if rejected.Code != 403 {
			t.Fatalf("role-changed managed key=%d", rejected.Code)
		}
		exec("DELETE FROM employee_api_keys WHERE user_id=$1::varchar||'_u2'", tenant)
		exec("DELETE FROM internal_keys WHERE id=$1::varchar||'_real_key'", tenant)
	})

	t.Run("ReviewUnownedKeyCannotAcquireAnActorFromHeaders", func(t *testing.T) {
		raw := "review-service-key-" + tenant
		exec("INSERT INTO internal_keys(id,tenant_id,project_id,key_hash,key_prefix,status,scopes_json) VALUES($1::varchar||'_service_key',$1::varchar,$1::varchar||'_proj',$2,'fixture','active','[\"chat\"]')", tenant, authhelpers.HashKey(raw))
		exec("INSERT INTO model_policies(id,tenant_id,project_id,scope_type,scope_ref,allow_models_json,deny_models_json) VALUES($1::varchar||'_svc_policy',$1::varchar,$1::varchar||'_proj','project',$1::varchar||'_proj','[\"shared-a\"]','[]')", tenant)
		serviceResolver := &MockModelResolver{ModelPolicy: &modelrouter.ModelPolicy{AllowList: []string{"shared-a"}}, QuotaPolicy: &modelrouter.QuotaPolicy{EnforcementMode: "bypass"}}
		serviceChat := gate(NewChatCompletionsHandler(&config.Config{SecurityAuditOnly: true}, serviceResolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, &MockAuditWriter{}, &MockProviderAdapterFactory{MockProviderCaller: caller}, nil, nil).Handler())
		realAuth := auth.NewAuthMiddleware(db, nil, nil).Middleware(&config.Config{})(serviceChat)
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(forbidden))
		req.Header.Set("Authorization", "Bearer "+raw)
		req.Header.Set("X-User-ID", tenant+"_u1")
		req.Header.Set("X-JJDGuard-Actor-User-Id", tenant+"_u1")
		req.Header.Set("X-NewAPI-User-Id", tenant+"_u1")
		before := len(caller.CallCalls)
		w := httptest.NewRecorder()
		realAuth.ServeHTTP(w, req)
		if w.Code != 403 || len(caller.CallCalls) != before {
			t.Fatalf("service key actor header bypass=%d body=%s", w.Code, w.Body.String())
		}
		exec("DELETE FROM model_policies WHERE id=$1::varchar||'_svc_policy'", tenant)
		exec("DELETE FROM internal_keys WHERE id=$1::varchar||'_service_key'", tenant)
	})
	t.Run("ReviewGatewayTenantAndUnassigned", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(allowed))
		c := context.WithValue(r.Context(), auth.TenantKey, "foreign-tenant")
		c = context.WithValue(c, auth.UserKey, tenant+"_u1")
		w := httptest.NewRecorder()
		chat.ServeHTTP(w, r.WithContext(c))
		if w.Code != 403 {
			t.Fatalf("foreign tenant=%d", w.Code)
		}
		exec("UPDATE users SET department_id=(SELECT id FROM teams WHERE tenant_id=$1 AND system_key='unassigned') WHERE id=$1::varchar||'_u2'", tenant)
		if w := call(chat, "u2", "/v1/chat/completions", allowed); w.Code != 403 {
			t.Fatalf("unassigned user=%d", w.Code)
		}
	})

}
