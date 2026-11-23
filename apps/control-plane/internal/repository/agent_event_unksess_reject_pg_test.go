package repository

import (
	"context"
	"testing"
)

// F-UNKSESS (batch 6 semantics): a placeholder session id ("unknown" in any case, surrounding
// space, or whitespace only) is not a session identity. Each such event is rejected on its own
// (rejected[] + code invalid_session, no batch error), so a batch made only of them is answered
// with every id rejected, and no row is written to agent_events, agent_sessions or projections.
func TestAgentEventUnknownSessionRejectedPerEvent(t *testing.T) {
	db := agentEndpointTestDB(t)
	ctx := context.Background()
	f := newAgentIngestFixture(t, db)
	repo := NewAgentEndpointRepository(db)
	for _, sid := range []string{"unknown", "UNKNOWN", " Unknown ", "   "} {
		batch := unksessBatch(t, sid)
		result, err := repo.AcceptEventBatch(ctx, f.tenant, f.endpoint, batch)
		rj := rejections(t, result)
		if err != nil || len(result.Accepted) != 0 || len(result.Rejected) != len(batch.Events) || len(rj) != len(batch.Events)+1 {
			t.Fatalf("session_id %q: %+v %v", sid, result, err)
		}
		for _, r := range rj[:len(batch.Events)] {
			if r.Code != "invalid_session" {
				t.Fatalf("session_id %q: rejection %+v", sid, r)
			}
		}
	}
	for table, n := range perEventRows(t, db, f.tenant, "") {
		if n != 0 {
			t.Fatalf("placeholder session persisted: %s=%d", table, n)
		}
	}
	// A real session id in the same shape is unaffected.
	result, err := repo.AcceptEventBatch(ctx, f.tenant, f.endpoint, unksessBatch(t, f.session))
	if err != nil || len(result.Accepted) != 8 || len(result.Rejected) != 0 {
		t.Fatalf("normal session: %+v %v", result, err)
	}
}
