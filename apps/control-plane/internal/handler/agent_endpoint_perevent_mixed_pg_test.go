package handler

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// F-UNKSESS batch 6 at the HTTP boundary: 7 valid events + 1 "unknown" -> 200; rejected[] holds
// exactly the bad id (the []string shape hookd a0296bf6 reads), rejections[] carries its code.
func TestAgentEndpointEventsMixedUnknownPerEvent(t *testing.T) {
	db, tenant, eps := unksessSetup(t)
	batch := unksessWireBatch(t, "unksess-"+uuid.NewString())
	bad := batch["events"].([]any)[5].(map[string]any)
	bad["session"].(map[string]any)["session_id"] = "unknown"
	w := unksessPost(t, db, tenant, eps[0], batch)
	body := decodeEventsAck(t, w)
	if w.Code != http.StatusOK || len(body.Accepted) != 7 || len(body.Rejected) != 1 || body.Rejected[0] != bad["event_id"] ||
		body.Rejections[0].EventID != bad["event_id"] || body.Rejections[0].Code != "invalid_session" {
		t.Fatalf("mixed batch: %d %s", w.Code, w.Body.String())
	}
	var stored, unknown int
	if err := db.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM agent_events WHERE tenant_id=$1),
		(SELECT count(*) FROM agent_sessions WHERE tenant_id=$1 AND lower(btrim(session_id))='unknown')`, tenant).Scan(&stored, &unknown); err != nil || stored != 7 || unknown != 0 {
		t.Fatalf("stored=%d unknown sessions=%d (%v)", stored, unknown, err)
	}
}
