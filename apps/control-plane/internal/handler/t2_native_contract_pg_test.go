package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func t2NativeContractPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TRI_LEGACY_CONTRACT_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires dedicated tri_rawfacts_t2_legacy_ PostgreSQL")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid private test DSN")
	}
	if cfg.ConnConfig.Host != "127.0.0.1" || cfg.ConnConfig.Port != 25462 || !strings.HasPrefix(cfg.ConnConfig.Database, "tri_rawfacts_t2_legacy_") {
		t.Fatal("refusing non-task dedicated test database")
	}
	db, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal("dedicated test PostgreSQL unavailable")
	}
	t.Cleanup(db.Close)
	_, err = db.Exec(context.Background(), `DROP SCHEMA public CASCADE;CREATE SCHEMA public;
CREATE TABLE teams(id TEXT PRIMARY KEY,tenant_id TEXT,name TEXT);
CREATE TABLE users(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,username TEXT NOT NULL,email TEXT,phone TEXT,password_hash TEXT,must_change_password BOOLEAN DEFAULT FALSE,role TEXT NOT NULL,status TEXT NOT NULL,external_subject TEXT,department_id TEXT,department_assignment_mode TEXT DEFAULT '',department_assignment_source TEXT DEFAULT '',department_assignment_rule_id TEXT,department_resolved_at TIMESTAMPTZ,department_version BIGINT DEFAULT 0);
CREATE TABLE agentguard_policies(id TEXT PRIMARY KEY,tenant_id TEXT,name TEXT,scope_type TEXT,scope_ref TEXT,mode TEXT,default_action TEXT,fail_policy TEXT,priority INT,enabled BOOLEAN,template_id TEXT,rules_json JSONB,behavior_json JSONB,dlp_json JSONB,created_by TEXT,updated_by TEXT,created_at TIMESTAMPTZ,updated_at TIMESTAMPTZ);
INSERT INTO users(id,tenant_id,username,role,status) VALUES('pg-user','pg-tenant','pg-connector','platform_connector','active');`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func t2NativePGSession(t *testing.T, db *pgxpool.Pool) (*Dependencies, string) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	sessions := repository.NewSessionRepository(client)
	token := uuid.NewString()
	// The stored role intentionally differs: authorization must use the current PG user.
	if err := sessions.Create(context.Background(), &repository.Session{ID: token, UserID: "pg-user", TenantID: "pg-tenant", Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	return &Dependencies{SessionRepo: sessions, UserRepo: repository.NewUserRepository(db), AgentGuardPolicyRepo: repository.NewAgentGuardPolicyRepository(db)}, token
}

func TestT2NativeLegacyPGActualRouterDeniesSealedAndPreservesLegacy(t *testing.T) {
	db := t2NativeContractPG(t)
	deps, token := t2NativePGSession(t, db)
	routes := []string{"/admin/v1/portal-integration/projects", "/admin/v1/portal-integration/audit-events", "/admin/v1/portal-integration/policies/model", "/admin/v1/eval-integration/audit-events"}
	for _, path := range routes {
		called := false
		router := t2LegacyRouter(deps, &called)
		request := httptest.NewRequest("GET", path, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set(InternalAPISecretHeader, "unit-legacy-secret")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != 403 || called {
			t.Fatalf("actual router=%s status=%d called=%v", path, response.Code, called)
		}
	}
	called := false
	router := t2LegacyRouter(deps, &called)
	request := httptest.NewRequest("GET", routes[0], nil)
	request.Header.Set("Authorization", "Bearer unit-legacy-secret")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != 204 || !called {
		t.Fatal("actual native stores broke ordinary legacy shared secret")
	}
}

func TestT2NativeLegacyPGCurrentIdentityAndStoreFaultFailClosed(t *testing.T) {
	for _, kind := range []string{"disabled", "tenant", "role_changed", "unknown", "expired", "user_store_fault"} {
		t.Run(kind, func(t *testing.T) {
			db := t2NativeContractPG(t)
			deps, token := t2NativePGSession(t, db)
			ctx := context.Background()
			want := 401
			switch kind {
			case "disabled":
				_, _ = db.Exec(ctx, `UPDATE users SET status='disabled' WHERE id='pg-user'`)
			case "tenant":
				_, _ = db.Exec(ctx, `UPDATE users SET tenant_id='other-tenant' WHERE id='pg-user'`)
			case "role_changed":
				_, _ = db.Exec(ctx, `UPDATE users SET role='viewer' WHERE id='pg-user'`)
			case "unknown":
				token = uuid.NewString()
			case "expired":
				if err := deps.SessionRepo.Delete(ctx, token); err != nil {
					t.Fatal(err)
				}
			case "user_store_fault":
				_, _ = db.Exec(ctx, `DROP TABLE users`)
				want = 503
			}
			called := false
			request := httptest.NewRequest("GET", "/admin/v1/portal-integration/projects", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			t2LegacyRouter(deps, &called).ServeHTTP(response, request)
			if response.Code != want || called {
				t.Fatalf("status=%d want=%d legacy-called=%v", response.Code, want, called)
			}
		})
	}
}

func TestT2NativeAgentGuardPGEmptyListIsArrayThroughAuthRoute(t *testing.T) {
	db := t2NativeContractPG(t)
	deps, token := t2NativePGSession(t, db)
	sessions := deps.SessionRepo.(*repository.SessionRepository)
	handler := auth.Middleware(sessions, deps.UserRepo)(ListAgentGuardPolicies(deps))
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/agentguard/policies", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("actual auth/repo route status=%d", response.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data, ok := body["data"].([]interface{})
	if !ok || len(data) != 0 {
		t.Fatalf("empty actual PG policy data=%s", response.Body.String())
	}
}
