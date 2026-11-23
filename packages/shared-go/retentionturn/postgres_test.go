package retentionturn

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"os"
	"testing"
)

func TestPostgresMigrationAndScopedPatches(t *testing.T) {
	url := os.Getenv("RETENTION_TURN_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("explicit isolated test DB not configured")
	}
	ctx := context.Background()
	db, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	// Only this connection's temporary table is modified, including by migration.
	_, err = db.Exec(ctx, `CREATE TEMP TABLE request_logs(tenant_id text,request_id text,environment_scope text);
 INSERT INTO request_logs VALUES ('a','r1','customer'),('b','r1','customer'),('a','r1','test');`)
	if err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../../deploy/migrations/828_retention_turn_context.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = db.Exec(ctx, string(migration)); err != nil {
			t.Fatal(err)
		}
	}
	request := &Request{HistoryKey: Digest("q"), IdentityKey: Digest("caller"), UserCount: 1, Links: []string{}}
	for _, patch := range [][]byte{Patch(request, nil), Patch(nil, BuildResponse(nil, "answer"))} {
		result, err := db.Exec(ctx, UpdateSQL, "a", "r1", "customer", string(patch))
		if err != nil || result.RowsAffected() != 1 {
			t.Fatalf("scoped write rows=%d err=%v", result.RowsAffected(), err)
		}
	}
	var raw []byte
	if err := db.QueryRow(ctx, `SELECT retention_turn_context FROM request_logs WHERE tenant_id='a' AND environment_scope='customer'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var got Context
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Request == nil || got.Response == nil || got.Request.HistoryKey != request.HistoryKey || len(got.Response.Links) != 1 {
		t.Fatalf("merge lost request/response: %s", raw)
	}
	var untouched int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM request_logs WHERE retention_turn_context='{}'::jsonb`).Scan(&untouched); err != nil || untouched != 2 {
		t.Fatalf("cross tenant/scope modified count=%d err=%v", untouched, err)
	}
}
