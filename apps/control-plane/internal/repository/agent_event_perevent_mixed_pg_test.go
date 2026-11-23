package repository

import (
	"context"
	"encoding/json"
	"testing"
)

// F-UNKSESS batch 6: 7 valid events + 1 "unknown" (the blocking tool.pre) in one real hookd batch.
// 200-level result, only that id in rejected with code invalid_session, 7 stored, nothing derived
// from the rejected event (no security_events / tool_call_logs for toolu_deny_1), no unknown session.
func TestAgentEventPerEventRejectMixedUnknown(t *testing.T) {
	db := agentEndpointTestDB(t)
	f := newAgentIngestFixture(t, db)
	batch := unksessBatch(t, f.session)
	var bad map[string]any
	_ = json.Unmarshal(batch.Events[5], &bad)
	bad["session"].(map[string]any)["session_id"] = "unknown"
	batch.Events[5], _ = json.Marshal(bad)
	result, err := NewAgentEndpointRepository(db).AcceptEventBatch(context.Background(), f.tenant, f.endpoint, batch)
	if err != nil || len(result.Accepted) != 7 || len(result.Rejected) != 1 || result.Rejected[0] != bad["event_id"] {
		t.Fatalf("mixed batch: %+v %v", result, err)
	}
	if rj := rejections(t, result); len(rj) != 2 || rj[0].Code != "invalid_session" || rj[0].EventID != bad["event_id"] {
		t.Fatalf("rejections: %+v", rj)
	}
	rows := perEventRows(t, db, f.tenant, f.endpoint)
	if rows["agent_events"] != 7 || rows["security_events"] != 0 || rows["agent_sessions"] != 1 {
		t.Fatalf("rows: %v", rows)
	}
	var denyLogs, unknownSessions int
	_ = db.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM tool_call_logs WHERE tenant_id=$1 AND tool_call_id='toolu_deny_1'),
		(SELECT count(*) FROM agent_sessions WHERE lower(btrim(session_id))='unknown' AND tenant_id=$1)`, f.tenant).Scan(&denyLogs, &unknownSessions)
	if denyLogs != 0 || unknownSessions != 0 {
		t.Fatalf("rejected event projected: tool_call_logs=%d unknown sessions=%d", denyLogs, unknownSessions)
	}
}
