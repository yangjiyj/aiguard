package repository

import (
	"context"
	"testing"
)

// F-UNKSESS (batch 6 semantics): two endpoints of one tenant report the same session id. Every
// event of the second endpoint on that session is rejected on its own (rejected[] + code
// session_ownership_conflict) instead of a batch error: hookd a0296bf6 retries any non-2xx batch
// forever, but acks and drops ids listed in a 2xx rejected[].
func TestAgentEventSessionOwnershipConflictRejectedPerEvent(t *testing.T) {
	db := agentEndpointTestDB(t)
	ctx := context.Background()
	f := newAgentIngestFixture(t, db)
	second := perEventSecondEndpoint(t, db, f)
	repo := NewAgentEndpointRepository(db)
	if result, err := repo.AcceptEventBatch(ctx, f.tenant, f.endpoint, unksessBatch(t, f.session)); err != nil || len(result.Accepted) != 8 {
		t.Fatalf("first endpoint: %+v %v", result, err)
	}
	secBefore := perEventRows(t, db, f.tenant, "")["security_events"]
	result, err := repo.AcceptEventBatch(ctx, f.tenant, second, unksessBatch(t, f.session))
	if err != nil || len(result.Accepted) != 0 || len(result.Rejected) != 8 || len(rejections(t, result)) != 9 ||
		rejections(t, result)[0].Code != "session_ownership_conflict" {
		t.Fatalf("second endpoint same session: %+v %v", result, err)
	}
	for table, n := range perEventRows(t, db, f.tenant, second) {
		// security_events / agent_turns carry no endpoint_id: compare tenant-wide below.
		if n != 0 && table != "security_events" && table != "agent_turns" {
			t.Fatalf("conflicting events stored for second endpoint: %s=%d", table, n)
		}
	}
	if secAfter := perEventRows(t, db, f.tenant, "")["security_events"]; secAfter != secBefore {
		t.Fatalf("security_events derived from rejected events: %d -> %d", secBefore, secAfter)
	}
}
