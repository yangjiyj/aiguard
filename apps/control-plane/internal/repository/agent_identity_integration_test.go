package repository

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
	"time"
)

func TestIdentityRegistrationTenantScopeAndRevokeIntegration(t *testing.T) {
	dsn := os.Getenv("AGENTGUARD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENTGUARD_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("identity_test_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	cfg, _ := pgxpool.ParseConfig(dsn)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE TABLE request_logs(request_id text PRIMARY KEY,tenant_id text,created_at timestamptz DEFAULT now(),agent_type text,agent_detection_source text,agent_detection_confidence double precision,proxy_mode text,environment_scope text,client_id text,user_id text,project_id text,source_ip text,proxy_source_ip text,proxy_user_agent text, agent_instance_id varchar(128))`)
	migration, err := os.ReadFile("../../../../deploy/migrations/830_agent_identity_registration.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(string(migration))
	// Minimal stub tables so the agent-identity projection subqueries (users/internal_keys/projects)
	// plan against an isolated schema that only seeds request_logs + the 830 migration.
	exec(`CREATE TABLE users (id text, tenant_id text, username text)`)
	exec(`CREATE TABLE internal_keys (id text, tenant_id text, name text, project_id text, agent_instance_id varchar(128))`)
	exec(`CREATE TABLE projects (id text, tenant_id text, name text)`)
	insert := func(id, tenant, env, channel, client, product, ua string) {
		t.Helper()
		exec(`INSERT INTO request_logs(request_id,tenant_id,environment_scope,proxy_mode,client_id,agent_type,proxy_user_agent,agent_detection_source,agent_detection_confidence) VALUES($1,$2,$3,$4,$5,$6,$7,'explicit_header',1)`, id, tenant, env, channel, client, product, ua)
	}
	assertType := func(id, want string) {
		t.Helper()
		var got string
		if err := db.QueryRow(ctx, `SELECT agent_type FROM request_logs WHERE request_id=$1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s type=%s want=%s", id, got, want)
		}
	}
	repo := NewAgentIdentityRepository(db)
	insert("reviewed", "a", "customer", "chat_completion", "key-a", "main", "client/1")
	insert("historical", "a", "customer", "chat_completion", "key-a", "main", "client/1")
	if _, err = repo.Confirm(ctx, "b", "admin", "reviewed", "workbuddy", "request", "verified config", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross tenant: %v", err)
	}
	id, err := repo.Confirm(ctx, "a", "admin", "reviewed", "workbuddy", "fingerprint", "verified config", false)
	if err != nil {
		t.Fatal(err)
	}
	assertType("reviewed", "workbuddy")
	assertType("historical", "main")
	// A late completion of an old request must not silently backfill unreviewed history.
	exec(`UPDATE request_logs SET agent_type=agent_type WHERE request_id='historical'`)
	assertType("historical", "main")
	insert("future", "a", "customer", "chat_completion", "key-a", "main", "client/1")
	assertType("future", "workbuddy")
	insert("other-tenant", "b", "customer", "chat_completion", "key-a", "main", "client/1")
	assertType("other-tenant", "main")
	insert("other-env", "a", "home", "chat_completion", "key-a", "main", "client/1")
	assertType("other-env", "main")
	insert("other-channel", "a", "customer", "reverse", "key-a", "main", "client/1")
	assertType("other-channel", "main")
	insert("other-key", "a", "customer", "chat_completion", "key-b", "main", "client/1")
	assertType("other-key", "main")
	insert("other-ua", "a", "customer", "chat_completion", "key-a", "main", "client/2")
	assertType("other-ua", "main")
	insert("known", "a", "customer", "chat_completion", "key-a", "claude-code", "client/1")
	assertType("known", "claude-code")
	// ON CONFLICT receives the before-insert projection. Repeated completions must preserve raw identity.
	exec(`INSERT INTO request_logs(request_id,tenant_id,environment_scope,proxy_mode,client_id,agent_type,proxy_user_agent,agent_detection_source) VALUES('future','a','customer','chat_completion','key-a','main','client/1','explicit_header') ON CONFLICT(request_id) DO UPDATE SET agent_type=EXCLUDED.agent_type,agent_detection_source=EXCLUDED.agent_detection_source`)
	assertType("future", "workbuddy")
	if _, err = repo.Confirm(ctx, "a", "admin", "historical", "cline", "dedicated_key", "verified dedicated", true); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if err = repo.Revoke(ctx, "b", "admin", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross tenant revoke: %v", err)
	}
	if err = repo.Revoke(ctx, "a", "admin", id); err != nil {
		t.Fatal(err)
	}
	assertType("reviewed", "main")
	assertType("future", "main")
	var source string
	var confidence float64
	if err = db.QueryRow(ctx, `SELECT agent_detection_source,agent_detection_confidence FROM request_logs WHERE request_id='future'`).Scan(&source, &confidence); err != nil {
		t.Fatal(err)
	}
	if source != "explicit_header" || confidence != 1 {
		t.Fatalf("raw evidence changed: %s %v", source, confidence)
	}
	insert("after-revoke", "a", "customer", "chat_completion", "key-a", "main", "client/1")
	assertType("after-revoke", "main")
	insert("no-key", "a", "customer", "forward", "", "agent-tool-call", "")
	single, err := repo.Confirm(ctx, "a", "admin", "no-key", "cline", "request", "verified terminal", false)
	if err != nil {
		t.Fatal(err)
	}
	assertType("no-key", "cline")
	if err = repo.Revoke(ctx, "a", "admin", single); err != nil {
		t.Fatal(err)
	}
	assertType("no-key", "agent-tool-call")
	items, _, err := repo.Pending(ctx, "b", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].RequestID != "other-tenant" {
		t.Fatalf("pending scope: %+v", items)
	}
	rules, err := repo.Rules(ctx, "b")
	if err != nil || len(rules) != 0 {
		t.Fatalf("rule leakage: %+v %v", rules, err)
	}
}
