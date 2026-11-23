package handler

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// F-UNKSESS batch 6: structural errors keep the whole-batch 4xx. A batch holding an "unknown"
// event plus a schema-invalid event (event_type not in events.v1) is still 422 invalid_event
// and stores nothing: per-event rejection only covers invalid_session / ownership conflicts.
func TestAgentEndpointEventsStructuralErrorStillWholeBatch4xx(t *testing.T) {
	db, tenant, eps := unksessSetup(t)
	batch := unksessWireBatch(t, "unksess-"+uuid.NewString())
	events := batch["events"].([]any)
	events[0].(map[string]any)["session"].(map[string]any)["session_id"] = "unknown"
	events[3].(map[string]any)["event_type"] = "tool.bogus"
	w := unksessPost(t, db, tenant, eps[0], batch)
	if w.Code != http.StatusUnprocessableEntity || !containsCode(w.Body.String(), "invalid_event") {
		t.Fatalf("schema-invalid batch: %d %s", w.Code, w.Body.String())
	}
	events[3].(map[string]any)["event_type"] = "tool.pre"
	batch["schema_version"] = "events.v0"
	if w := unksessPost(t, db, tenant, eps[0], batch); w.Code < 400 || w.Code >= 500 {
		t.Fatalf("bad schema_version: %d %s", w.Code, w.Body.String())
	}
	var n int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM agent_events WHERE tenant_id=$1`, tenant).Scan(&n); err != nil || n != 0 {
		t.Fatalf("structurally invalid batch stored %d rows (%v)", n, err)
	}
}
