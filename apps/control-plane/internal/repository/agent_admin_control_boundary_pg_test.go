package repository

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestAgentAdminControlBoundaryRoundTripsThroughPostgres stores a heartbeat
// health through the real Heartbeat SQL and reads it back through the admin
// projection. AGENT_CONTROL_BOUNDARY_PG_HEALTH_FILE may point at a health
// object captured from a real hookd heartbeat; otherwise a fixture is used.
func TestAgentAdminControlBoundaryRoundTripsThroughPostgres(t *testing.T) {
	dsn := os.Getenv("AGENT_CONTROL_BOUNDARY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENT_CONTROL_BOUNDARY_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var name string
	if err = db.QueryRow(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "ir_test_") {
		t.Fatalf("refusing non-disposable database %q", name)
	}
	reported := []byte(`{"queue_events":1,"control_boundary":{"schema":"jjdguard-control-boundary/v1","require_trusted_agent_authorization":false,"decide_fail_mode":"open","hosts":{"openclaw":{},"claude-code":{}}}}`)
	if path := os.Getenv("AGENT_CONTROL_BOUNDARY_PG_HEALTH_FILE"); path != "" {
		if reported, err = os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	var reportedHealth map[string]any
	if err = json.Unmarshal(reported, &reportedHealth); err != nil || reportedHealth["control_boundary"] == nil {
		t.Fatalf("health fixture has no control_boundary: %s err=%v", reported, err)
	}

	tenant := "cb-" + uuid.NewString()[:8]
	endpoints := NewAgentEndpointRepository(db)
	admin := NewAgentAdminRepository(db)
	insert := func(id string) {
		t.Helper()
		_, err := db.Exec(ctx, `INSERT INTO agent_endpoints(id,tenant_id,machine_id,hostname,os,arch,agent_product,token_hash) VALUES($1,$2,$1,'h','linux','amd64','openclaw',$3)`, id, tenant, HashAgentToken(id))
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = db.Exec(context.Background(), `DELETE FROM agent_endpoints WHERE tenant_id=$1`, tenant) })

	insert("ep-reporting")
	if err = endpoints.Heartbeat(ctx, tenant, "ep-reporting", reportedHealth, 7, 1); err != nil {
		t.Fatal(err)
	}
	insert("ep-legacy")
	if err = endpoints.Heartbeat(ctx, tenant, "ep-legacy", map[string]any{"queue_events": 0}, 7, 1); err != nil {
		t.Fatal(err)
	}
	insert("ep-never")

	got, err := admin.GetEndpoint(ctx, tenant, "ep-reporting")
	if err != nil || got == nil {
		t.Fatalf("get reporting endpoint: %v %v", got, err)
	}
	var want, have any
	wantRaw, _ := json.Marshal(reportedHealth["control_boundary"])
	_ = json.Unmarshal(wantRaw, &want)
	if err = json.Unmarshal(got.ControlBoundary, &have); err != nil {
		t.Fatalf("control_boundary=%s err=%v", got.ControlBoundary, err)
	}
	wantJSON, _ := json.Marshal(want)
	haveJSON, _ := json.Marshal(have)
	if string(wantJSON) != string(haveJSON) {
		t.Fatalf("control_boundary changed through jsonb:\nwant %s\nhave %s", wantJSON, haveJSON)
	}

	page, err := admin.ListEndpoints(ctx, tenant, AgentEndpointFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, item := range page.Items {
		data, _ := json.Marshal(item)
		var shape map[string]json.RawMessage
		_ = json.Unmarshal(data, &shape)
		seen[item.ID] = string(shape["control_boundary"])
	}
	if len(seen) != 3 || seen["ep-legacy"] != "null" || seen["ep-never"] != "null" || !strings.Contains(seen["ep-reporting"], `"jjdguard-control-boundary/v1"`) {
		t.Fatalf("list control_boundary projection=%v", seen)
	}
}
