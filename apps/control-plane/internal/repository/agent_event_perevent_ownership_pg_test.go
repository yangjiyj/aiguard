package repository

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// F-UNKSESS batch 6: endpoint B sends one event on endpoint A's session inside an otherwise valid
// batch. That event alone is rejected (session_ownership_conflict); B's other 7 events land; A's
// session keeps its owner and counters; nothing is derived from the rejected event.
func TestAgentEventPerEventRejectOwnershipConflict(t *testing.T) {
	db := agentEndpointTestDB(t)
	ctx := context.Background()
	f := newAgentIngestFixture(t, db)
	second := perEventSecondEndpoint(t, db, f)
	repo := NewAgentEndpointRepository(db)
	if r, err := repo.AcceptEventBatch(ctx, f.tenant, f.endpoint, unksessBatch(t, f.session)); err != nil || len(r.Accepted) != 8 {
		t.Fatalf("endpoint A: %+v %v", r, err)
	}
	before := perEventRows(t, db, f.tenant, f.endpoint)
	batch := unksessBatch(t, "sess-b-"+uuid.NewString())
	var bad map[string]any
	_ = json.Unmarshal(batch.Events[5], &bad)
	bad["session"].(map[string]any)["session_id"] = f.session
	batch.Events[5], _ = json.Marshal(bad)
	r, err := repo.AcceptEventBatch(ctx, f.tenant, second, batch)
	if err != nil || len(r.Accepted) != 7 || len(r.Rejected) != 1 || r.Rejected[0] != bad["event_id"] ||
		len(rejections(t, r)) != 2 || rejections(t, r)[0].Code != "session_ownership_conflict" {
		t.Fatalf("endpoint B: %+v %v", r, err)
	}
	if b := perEventRows(t, db, f.tenant, second); b["agent_events"] != 7 || b["agent_sessions"] != 1 || b["tool_call_logs"] != 1 {
		t.Fatalf("endpoint B rows: %v", b)
	}
	if after := perEventRows(t, db, f.tenant, f.endpoint); after["agent_events"] != before["agent_events"] || after["tool_call_logs"] != before["tool_call_logs"] {
		t.Fatalf("endpoint A changed: before=%v after=%v", before, after)
	}
	var owner string
	var events int
	if err := db.QueryRow(ctx, `SELECT endpoint_id,event_count FROM agent_sessions WHERE session_id=$1`, f.session).Scan(&owner, &events); err != nil || owner != f.endpoint || events != 8 {
		t.Fatalf("session A: owner=%s events=%d %v", owner, events, err)
	}
}
