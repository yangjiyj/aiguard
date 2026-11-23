package repository

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// F-UNKSESS batch 6 helper: row counts of agent_events and every table an event projects into,
// for one tenant (and, where the table carries endpoint_id, one endpoint when endpoint != "").
func perEventRows(t *testing.T, db *pgxpool.Pool, tenant, endpoint string) map[string]int {
	t.Helper()
	out := map[string]int{}
	byEndpoint := map[string]bool{"agent_events": true, "security_events": false, "tool_call_logs": true,
		"agent_alerts": true, "agent_endpoint_assets": true, "agent_sessions": true, "agent_turns": false}
	for table, hasEndpoint := range byEndpoint {
		q, args := "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", []any{tenant}
		if endpoint != "" && hasEndpoint {
			q, args = q+" AND endpoint_id=$2", append(args, endpoint)
		}
		var n int
		if err := db.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		out[table] = n
	}
	return out
}

// perEventSecondEndpoint registers endpoint "<A>-b" in the fixture tenant.
func perEventSecondEndpoint(t *testing.T, db *pgxpool.Pool, f agentIngestFixture) string {
	t.Helper()
	second := f.endpoint + "-b"
	if _, err := db.Exec(context.Background(), `INSERT INTO agent_endpoints(id,tenant_id,machine_id,hostname,os,arch,agent_product,token_hash)
		VALUES($1,$2,$3,'host-b','linux','amd64','test',$4)`, second, f.tenant, "machine-b-"+second, HashAgentToken(uuid.NewString())); err != nil {
		t.Fatal(err)
	}
	return second
}

type perEventRejection struct {
	EventID string `json:"event_id"`
	Code    string `json:"code"`
}

// rejections reads the per-event reasons through the result's JSON (the wire shape), so these
// tests compile against the pre-fix tree too and fail there on behaviour, not on build.
func rejections(t *testing.T, result *AgentEventBatchResult) []perEventRejection {
	t.Helper()
	var wire struct {
		Rejections []perEventRejection `json:"rejections"`
	}
	if result != nil {
		data, _ := json.Marshal(result)
		_ = json.Unmarshal(data, &wire)
	}
	return append(wire.Rejections, perEventRejection{}) // trailing zero entry: [0] is always indexable
}
