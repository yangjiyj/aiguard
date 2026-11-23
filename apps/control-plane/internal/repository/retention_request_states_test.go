package repository

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
	"time"
)

func TestRetentionRequestStatesRespectTenantWindowAndEnvironment(t *testing.T) {
	url := os.Getenv("RETENTION_TURN_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("explicit isolated test DB not configured")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A connection-local temporary table keeps this test away from persistent data.
	_, err = db.Exec(ctx, `CREATE TEMP TABLE request_logs(request_id text,tenant_id text,request_status text,latency_ms bigint,created_at timestamptz,environment_scope text)`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 4; i++ {
		tenant, scope, at := "tenant", "customer", now
		if i == 1 {
			tenant = "foreign"
		}
		if i == 2 {
			scope = "test"
		}
		if i == 3 {
			at = now.Add(-2 * time.Hour)
		}
		if _, err = db.Exec(ctx, `INSERT INTO request_logs VALUES ('r1',$1,'stream_aborted',125,$2,$3)`, tenant, at, scope); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("RETENTION_INCLUDE_LEGACY_UNCLASSIFIED", "false")
	repo := NewContentLogRepository(db)
	check := func(wantContext bool) {
		t.Helper()
		rows, err := repo.ListRetentionRequestStatesScoped(ctx, "tenant", []string{"r1"}, now.Add(-time.Hour), now.Add(time.Hour), "customer")
		if err != nil || len(rows) != 1 || rows[0].LatencyMS != 125 || rows[0].Status != "stream_aborted" {
			t.Fatalf("states=%+v err=%v", rows, err)
		}
		var context map[string]interface{}
		if err = json.Unmarshal(rows[0].TurnContext, &context); err != nil {
			t.Fatal(err)
		}
		if (context["version"] != nil) != wantContext {
			t.Fatalf("context=%s", rows[0].TurnContext)
		}
	}
	check(false) // Old DB schema must remain readable during staged deployment.
	migration, err := os.ReadFile("../../../../deploy/migrations/828_retention_turn_context.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `UPDATE request_logs SET retention_turn_context='{"version":1}'::jsonb WHERE tenant_id='tenant' AND environment_scope='customer'`); err != nil {
		t.Fatal(err)
	}
	check(true)
	rows, err := repo.ListRetentionRequestStatesScoped(ctx, "absent", []string{"r1"}, now.Add(-time.Hour), now.Add(time.Hour), "customer")
	if err != nil || len(rows) != 0 {
		t.Fatalf("foreign tenant returned data: %+v %v", rows, err)
	}
}
