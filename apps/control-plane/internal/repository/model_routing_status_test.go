package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/testcontainer"
)

func statusTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), dockerPreflightOverallTimeout)
	defer cancel()
	if err := migration116DockerPreflight(ctx, exec.LookPath, runMigration116Docker); err != nil {
		t.Skipf("real PostgreSQL unavailable: %v", err)
	}
	name := fmt.Sprintf("jjdguard-routing-status-%d", time.Now().UnixNano())
	run := func(in string, args ...string) (string, error) {
		return runMigration116Docker(context.Background(), dockerCommandTimeout, in, args...)
	}
	reapOrphanTestContainers(t)
	runArgs := append([]string{"run", "--pull=never", "--rm", "-d", "--name", name}, testcontainer.LabelArgs("routing-status")...)
	runArgs = append(runArgs, "-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_DB=test", "postgres:16-alpine")
	if out, err := run("", runArgs...); err != nil {
		_, _ = run("", "rm", "-fv", name)
		t.Skipf("start PostgreSQL: %v: %s", err, out)
	}
	t.Cleanup(func() { _, _ = run("", "rm", "-fv", name) })
	for deadline := time.Now().Add(dockerReadinessTimeout); ; time.Sleep(100 * time.Millisecond) {
		if _, err := run("", "exec", name, "pg_isready", "-U", "postgres", "-d", "test"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("PostgreSQL readiness timeout")
		}
	}
	out, err := run("", "port", name, "5432/tcp")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimSpace(out), ":")
	port, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		t.Fatal(err)
	}
	db, err := pgxpool.New(context.Background(), fmt.Sprintf("postgres://postgres:test@127.0.0.1:%d/test?sslmode=disable", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	for deadline := time.Now().Add(dockerReadinessTimeout); ; time.Sleep(100 * time.Millisecond) {
		if err := db.Ping(context.Background()); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("published PostgreSQL port did not become ready: %v", err)
		}
	}
	_, err = db.Exec(context.Background(), `CREATE TABLE tenants(id varchar(64) PRIMARY KEY); CREATE TABLE providers(id varchar(64) PRIMARY KEY,tenant_id varchar(64) NOT NULL REFERENCES tenants(id),name varchar(255) NOT NULL,provider_type varchar(64) NOT NULL DEFAULT 'openai',base_url varchar(512),auth_mode varchar(64),is_default boolean NOT NULL DEFAULT FALSE,status varchar(32) NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()); CREATE TABLE provider_credentials(id varchar(64) PRIMARY KEY,provider_id varchar(64) NOT NULL REFERENCES providers(id),secret_ciphertext text,status varchar(32) NOT NULL,created_at timestamptz NOT NULL DEFAULT now()); CREATE TABLE models(id varchar(64) PRIMARY KEY,provider_id varchar(64) NOT NULL REFERENCES providers(id),model_name varchar(255) NOT NULL,status varchar(32) NOT NULL,capabilities_json jsonb NOT NULL DEFAULT '{}',created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()); CREATE TABLE routing_policies(id varchar(64) PRIMARY KEY,tenant_id varchar(64) NOT NULL REFERENCES tenants(id),scope_type varchar(16) NOT NULL,scope_ref varchar(255),layer varchar(16) NOT NULL,strategy varchar(32) NOT NULL DEFAULT 'priority',config_json jsonb NOT NULL DEFAULT '{}',enabled boolean NOT NULL DEFAULT true,schema_version smallint NOT NULL DEFAULT 1,config_version bigint NOT NULL DEFAULT 1,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()); CREATE TABLE request_logs(id varchar(64) PRIMARY KEY,request_id varchar(64) UNIQUE NOT NULL,tenant_id varchar(64) NOT NULL REFERENCES tenants(id),provider_id varchar(64) REFERENCES providers(id),model_id varchar(64) REFERENCES models(id),endpoint_type varchar(32),request_status varchar(32),created_at timestamptz NOT NULL DEFAULT now(), agent_instance_id varchar(128))`)
	if err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../../../deploy/migrations/116_explicit_model_routing.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), string(migration)); err != nil {
		t.Fatal(err)
	}
	capabilityMigration, err := os.ReadFile("../../../../deploy/migrations/149_model_endpoint_capability_facts.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), string(capabilityMigration)); err != nil {
		t.Fatal(err)
	}
	healthMigration, err := os.ReadFile("../../../../deploy/migrations/151_shared_route_health_snapshots.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(context.Background(), string(healthMigration)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"../../../../deploy/migrations/149_model_endpoint_capability_facts.sql",
		"../../../../deploy/migrations/150_model_route_attempt_ledger.sql",
		"../../../../deploy/migrations/151_shared_route_health_snapshots.sql",
		"../../../../deploy/migrations/152_request_outcome_dimensions.sql",
		"../../../../deploy/migrations/153_restore_safe_agent_destructive_functions.sql",
	} {
		migration, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, execErr := db.Exec(context.Background(), string(migration)); execErr != nil {
			t.Fatalf("rerunnable forwarding migration %s: %v", path, execErr)
		}
	}
	return db
}

func seedStatus(t *testing.T, db *pgxpool.Pool, tenant, provider, modelID, modelName, pStatus, mStatus, cStatus string) {
	t.Helper()
	ctx := context.Background()
	_, _ = db.Exec(ctx, `INSERT INTO tenants(id) VALUES($1) ON CONFLICT DO NOTHING`, tenant)
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,status) VALUES($1,$2,$1,$3) ON CONFLICT DO NOTHING`, provider, tenant, pStatus); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO provider_credentials(id,provider_id,secret_ciphertext,status) VALUES('c-'||$1,$1,'test-ciphertext',$2) ON CONFLICT DO NOTHING`, provider, cStatus); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name,status) VALUES($1,$2,$3,$4)`, modelID, provider, modelName, mStatus); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO model_endpoint_capability_overrides(id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id) VALUES('o-'||$1,$2,$1,'chat','supported','test fixture','test')`, modelID, tenant); err != nil {
		t.Fatal(err)
	}
}

func TestListStatusGroupsSameModelAcrossProviders(t *testing.T) {
	db := statusTestDB(t)
	for i := 0; i < 3; i++ {
		seedStatus(t, db, "ta", fmt.Sprintf("pa%d", i), fmt.Sprintf("ma%d", i), "deepseek-r1", "active", "active", "active")
	}
	seedStatus(t, db, "tb", "pb", "mb", "deepseek-r1", "active", "active", "active")
	var before, after int
	_ = db.QueryRow(context.Background(), `SELECT count(*) FROM routing_policies`).Scan(&before)
	got, next, err := NewModelRoutingRepository(db).ListRoutingStatus(context.Background(), "ta", RoutingStatusFilter{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if next != "" || len(got) != 1 || got[0].RouteCount != 3 || got[0].State != "pending" || len(got[0].Routes) != 3 {
		t.Fatalf("got=%+v next=%q", got, next)
	}
	for _, r := range got[0].Routes {
		if strings.HasPrefix(r.ProviderID, "pb") {
			t.Fatal("tenant leak")
		}
	}
	_ = db.QueryRow(context.Background(), `SELECT count(*) FROM routing_policies`).Scan(&after)
	if before != after {
		t.Fatal("list wrote policy")
	}
}

func TestListStatusExcludesDeletedModels(t *testing.T) {
	db := statusTestDB(t)
	seedStatus(t, db, "ta", "p1", "active-model", "active-model", "active", "active", "active")
	seedStatus(t, db, "ta", "p1", "deleted-model", "deleted-model", "active", "deleted", "active")

	got, _, err := NewModelRoutingRepository(db).ListRoutingStatus(context.Background(), "ta", RoutingStatusFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ModelName != "active-model" {
		t.Fatalf("deleted model leaked into routing status: %+v", got)
	}
}

func TestListStatusMarksSingleConfiguredAndUnavailable(t *testing.T) {
	db := statusTestDB(t)
	seedStatus(t, db, "ta", "p1", "s", "single", "active", "active", "active")
	seedStatus(t, db, "ta", "p1", "c1", "configured", "active", "active", "active")
	seedStatus(t, db, "ta", "p2", "c2", "configured", "active", "active", "active")
	seedStatus(t, db, "ta", "off", "u", "unavailable", "inactive", "active", "active")
	_, _ = db.Exec(context.Background(), `INSERT INTO routing_policies(id,tenant_id,scope_type,scope_ref,layer,schema_version,config_version) VALUES('v3','ta','model','configured','provider',3,9)`)
	got, _, err := NewModelRoutingRepository(db).ListRoutingStatus(context.Background(), "ta", RoutingStatusFilter{})
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]LogicalModelRoutingStatus{}
	for _, x := range got {
		m[x.ModelName] = x
	}
	if m["single"].State != "single" || m["configured"].State != "configured" || m["configured"].ConfigVersion != 9 || m["unavailable"].State != "unavailable" || m["unavailable"].RouteCount != 0 {
		t.Fatalf("states=%+v", m)
	}
}

func TestListStatusSeparatesConfiguredAndEndpointEligibleCandidates(t *testing.T) {
	db := statusTestDB(t)
	seedStatus(t, db, "ta", "p1", "m1", "logical", "active", "active", "active")
	seedStatus(t, db, "ta", "p2", "m2", "logical", "active", "active", "active")
	if _, err := db.Exec(context.Background(), `DELETE FROM model_endpoint_capability_overrides WHERE model_id='m2' AND endpoint_type='chat'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(context.Background(), `INSERT INTO model_route_health_snapshots(tenant_id,model_name,provider_id,state,version,observed_at,expires_at,source_instance) VALUES('ta','logical','p1','unhealthy',1,NOW(),NOW()+INTERVAL '1 minute','test')`); err != nil {
		t.Fatal(err)
	}
	got, _, err := NewModelRoutingRepository(db).ListRoutingStatus(context.Background(), "ta", RoutingStatusFilter{Endpoint: "chat"})
	if err != nil || len(got) != 1 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if got[0].ConfiguredCandidateCount != 2 || got[0].EligibleCandidateCount != 0 || got[0].RouteCount != 2 || got[0].State != "pending" {
		t.Fatalf("status=%+v", got[0])
	}
	if len(got[0].Routes) != 2 || got[0].Routes[0].HealthState != "unhealthy" {
		t.Fatalf("route health=%+v", got[0].Routes)
	}
	if got[0].Routes[1].CapabilityState != "unknown" {
		t.Fatalf("newly synced route should remain configurable while capability is unknown: %+v", got[0].Routes)
	}
}

func TestListStatusCanFilterMultiUpstreamModels(t *testing.T) {
	db := statusTestDB(t)
	seedStatus(t, db, "ta", "p1", "single-1", "single", "active", "active", "active")
	seedStatus(t, db, "ta", "p1", "multi-1", "multi", "active", "active", "active")
	seedStatus(t, db, "ta", "p2", "multi-2", "multi", "active", "active", "active")

	got, _, err := NewModelRoutingRepository(db).ListRoutingStatus(context.Background(), "ta", RoutingStatusFilter{MinRouteCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ModelName != "multi" || got[0].RouteCount != 2 {
		t.Fatalf("multi-upstream filter returned %+v", got)
	}
}

func TestListStatusIsTenantScopedAndCursorPaged(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	for _, tenant := range []string{"ta", "tb"} {
		seedStatus(t, db, tenant, tenant+"p1", tenant+"seed", "seed", "active", "active", "active")
		seedStatus(t, db, tenant, tenant+"p2", tenant+"seed2", "seed2", "active", "active", "active")
		rows := make([][]any, 0, 750)
		for i := 0; i < 500; i++ {
			n := fmt.Sprintf("model-%03d", i)
			rows = append(rows, []any{fmt.Sprintf("%s-a-%03d", tenant, i), tenant + "p1", n, "active"})
			if i%2 == 0 {
				rows = append(rows, []any{fmt.Sprintf("%s-b-%03d", tenant, i), tenant + "p2", n, "active"})
			}
		}
		if _, err := db.CopyFrom(ctx, pgx.Identifier{"models"}, []string{"id", "provider_id", "model_name", "status"}, pgx.CopyFromRows(rows)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `
INSERT INTO model_endpoint_capability_overrides(id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id)
SELECT 'bulk-o-'||m.id,$1,m.id,'chat','supported','test fixture','test'
FROM models m JOIN providers p ON p.id=m.provider_id
WHERE p.tenant_id=$1 AND m.model_name LIKE 'model-%'
ON CONFLICT (model_id,endpoint_type) DO NOTHING
`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	repo := NewModelRoutingRepository(db)
	seen := map[string]bool{}
	cursor := ""
	for {
		page, next, err := repo.ListRoutingStatus(ctx, "ta", RoutingStatusFilter{Query: "model-", Limit: 37, Cursor: cursor})
		if err != nil || len(page) > 37 {
			t.Fatalf("len=%d err=%v", len(page), err)
		}
		for _, x := range page {
			if seen[x.ModelName] {
				t.Fatal("duplicate")
			}
			seen[x.ModelName] = true
			for _, r := range x.Routes {
				if !strings.HasPrefix(r.ProviderID, "ta") {
					t.Fatal("tenant leak")
				}
			}
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 500 {
		t.Fatalf("got %d", len(seen))
	}
	checks := []RoutingStatusFilter{{Query: "model-042"}, {State: "single", Query: "model-"}, {ProviderRef: "tap2", Query: "model-"}, {RouteCount: 2, Query: "model-"}, {Query: "%' OR 1=1 --"}, {ProviderRef: "tap2' OR '1'='1"}}
	wants := []int{1, 100, 100, 100, 0, 0}
	for i, f := range checks {
		f.Limit = 100
		x, _, err := repo.ListRoutingStatus(ctx, "ta", f)
		if err != nil || len(x) != wants[i] {
			t.Fatalf("filter=%+v len=%d err=%v", f, len(x), err)
		}
	}
	page, _, err := repo.ListRoutingStatus(ctx, "ta", RoutingStatusFilter{Query: "model-", Limit: 10000})
	if err != nil || len(page) != 100 {
		t.Fatalf("cap len=%d err=%v", len(page), err)
	}
	if _, _, err = repo.ListRoutingStatus(ctx, "ta", RoutingStatusFilter{Cursor: "%%%"}); err == nil {
		t.Fatal("bad cursor accepted")
	}
	if _, _, err = repo.ListRoutingStatus(ctx, "ta", RoutingStatusFilter{State: "x' OR true --"}); err == nil {
		t.Fatal("bad state accepted")
	}
}

func TestCaptureBaselineUsesLatestSuccessfulRoute(t *testing.T) {
	db := statusTestDB(t)
	ctx := context.Background()
	seedStatus(t, db, "ta", "p1", "m1", "deepseek-r1", "active", "active", "active")
	seedStatus(t, db, "ta", "p2", "m2", "deepseek-r1", "active", "active", "active")
	seedStatus(t, db, "ta", "p1", "other", "other", "active", "active", "active")
	seedStatus(t, db, "ta", "off", "offm", "deepseek-r1", "inactive", "active", "active")
	seedStatus(t, db, "tb", "foreign", "fm", "deepseek-r1", "active", "active", "active")
	_, _ = db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,provider_id,model_id,request_status,created_at) VALUES('1','r1','ta','p1','m1','success',now()-interval '3 min'),('2','r2','ta','p1','m1','failed',now()-interval '1 min'),('3','r3','ta','p2','m2','success',now()-interval '2 min')`)
	repo := NewModelRoutingRepository(db)
	tx, _ := db.Begin(ctx)
	if err := repo.CaptureBaseline(ctx, tx, "ta", "deepseek-r1", "p1"); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
	var p, source string
	_ = db.QueryRow(ctx, `SELECT provider_id,captured_from FROM model_route_baselines WHERE tenant_id='ta' AND model_name='deepseek-r1'`).Scan(&p, &source)
	if p != "p2" || source != "runtime" {
		t.Fatalf("baseline=%s/%s", p, source)
	}
	tx, _ = db.Begin(ctx)
	if err := repo.CaptureBaseline(ctx, tx, "ta", "deepseek-r1", "p1"); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
	_ = db.QueryRow(ctx, `SELECT provider_id FROM model_route_baselines WHERE tenant_id='ta' AND model_name='deepseek-r1'`).Scan(&p)
	if p != "p2" {
		t.Fatal("overwritten")
	}
	reject := func(model, confirmed string, want error) {
		tx, _ := db.Begin(ctx)
		err := repo.CaptureBaseline(ctx, tx, "ta", model, confirmed)
		_ = tx.Rollback(ctx)
		if want != nil && !errors.Is(err, want) {
			t.Fatalf("err=%v", err)
		}
		if want == nil && err == nil {
			t.Fatal("invalid confirmation accepted")
		}
	}
	reject("missing", "", ErrCurrentRouteConfirmationRequired)
	reject("missing", "foreign", nil)
	reject("missing", "p1", nil)
	reject("other", "off", nil)
	tx, _ = db.Begin(ctx)
	if err := repo.CaptureBaseline(ctx, tx, "ta", "other", "p1"); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
}
