package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// F-UNKSESS handler level over real PostgreSQL: the Events handler drives the real repository.
type unksessRepo struct {
	*repository.AgentEndpointRepository
}

func (unksessRepo) Policy(context.Context, string) (map[string]any, error) {
	return map[string]any{"version": int64(3), "checksum": "sha256:" + strings.Repeat("b", 64)}, nil
}

func unksessPost(t *testing.T, db *pgxpool.Pool, tenant, endpoint string, batch map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	batch["endpoint_id"] = endpoint
	body, _ := json.Marshal(batch)
	r := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(string(body)))
	r = r.WithContext(contextWithEndpoint(r.Context(), &repository.AgentEndpointContext{
		TenantID: tenant, EndpointID: endpoint, PolicyVersion: 3, Mode: "monitor"}))
	w := httptest.NewRecorder()
	(&AgentEndpointAPI{Repo: unksessRepo{repository.NewAgentEndpointRepository(db)}}).Events(w, r)
	return w
}

// unksessSetup creates a tenant with two endpoints on AGENT_ENDPOINT_TEST_DATABASE_URL (migrated db).
func unksessSetup(t *testing.T) (*pgxpool.Pool, string, [2]string) {
	t.Helper()
	dsn := os.Getenv("AGENT_ENDPOINT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AGENT_ENDPOINT_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	suffix := uuid.NewString()
	tenant, eps := "unksess-tenant-"+suffix, [2]string{"unksess-ep-a-" + suffix, "unksess-ep-b-" + suffix}
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,is_test) VALUES($1,$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	for _, ep := range eps {
		if _, err := db.Exec(ctx, `INSERT INTO agent_endpoints(id,tenant_id,machine_id,hostname,os,arch,agent_product,token_hash)
			VALUES($1,$2,$1,'host','linux','amd64','test',$3)`, ep, tenant, repository.HashAgentToken(ep)); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, table := range []string{"agent_alerts", "security_events", "agent_events", "tool_call_logs", "agent_turns", "agent_sessions", "agent_endpoint_assets", "agent_endpoints"} {
			_, _ = db.Exec(context.Background(), "DELETE FROM "+table+" WHERE tenant_id=$1", tenant)
		}
		_, _ = db.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant)
		db.Close()
	})
	return db, tenant, eps
}

// unksessWireBatch loads the real hookd a0296bf6 wire batch, rebases times to now, and rewrites
// session ids and event ids (fresh per call).
func unksessWireBatch(t *testing.T, sessionID string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../../../packages/shared-go/endpointevents/testdata/hookd-a0296bf6/batch-a-cc-t13-deny.json")
	if err != nil {
		t.Fatal(err)
	}
	var batch map[string]any
	if err := json.Unmarshal(raw, &batch); err != nil {
		t.Fatal(err)
	}
	sent, _ := time.Parse(time.RFC3339Nano, batch["sent_at"].(string))
	shift := time.Since(sent)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:11]
	for i, e := range batch["events"].([]any) {
		event := e.(map[string]any)
		ts, _ := time.Parse(time.RFC3339Nano, event["occurred_at"].(string))
		event["occurred_at"] = ts.Add(shift).UTC().Format(time.RFC3339Nano)
		id := event["event_id"].(string)
		event["event_id"] = id[:len(id)-12] + suffix + string("0123456789abcdef"[i])
		event["session"].(map[string]any)["session_id"] = sessionID
	}
	batch["sent_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	return batch
}
