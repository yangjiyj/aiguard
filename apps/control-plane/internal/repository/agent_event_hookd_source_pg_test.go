package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// F-EVSRC (e): real hookd a0296bf6 wire batches carrying local_decision.source
// agent_authorization / agent_approval must be ingested with the source preserved
// verbatim, projected as blocked, and visible in the admin session detail.
// Fixtures: packages/shared-go/endpointevents/testdata/hookd-a0296bf6 (README.md).
func loadRebasedHookdWireBatch(t *testing.T, name string) AgentEventBatchRequest {
	t.Helper()
	raw, err := os.ReadFile("../../../../packages/shared-go/endpointevents/testdata/hookd-a0296bf6/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var batch AgentEventBatchRequest
	if err := json.Unmarshal(raw, &batch); err != nil {
		t.Fatal(err)
	}
	sent, err := time.Parse(time.RFC3339Nano, batch.SentAt)
	if err != nil {
		t.Fatal(err)
	}
	shift := time.Since(sent)
	for i, rawEvent := range batch.Events {
		d := json.NewDecoder(bytes.NewReader(rawEvent))
		d.UseNumber()
		var event map[string]any
		if err := d.Decode(&event); err != nil {
			t.Fatal(err)
		}
		ts, err := time.Parse(time.RFC3339Nano, event["occurred_at"].(string))
		if err != nil {
			t.Fatal(err)
		}
		event["occurred_at"] = ts.Add(shift).UTC().Format(time.RFC3339Nano)
		if batch.Events[i], err = json.Marshal(event); err != nil {
			t.Fatal(err)
		}
	}
	return batch
}

func TestAgentEventIngestHookdA0296bf6DecisionSourcesPreserved(t *testing.T) {
	db := agentEndpointTestDB(t)
	ctx := context.Background()
	for _, tc := range []struct{ file, source, toolUseID string }{
		{"batch-a-cc-t13-deny.json", "agent_authorization", "toolu_deny_1"},
		{"batch-b-cc-t15-reject.json", "agent_approval", "toolu_appr_1"},
	} {
		t.Run(tc.source, func(t *testing.T) {
			f := newAgentIngestFixture(t, db)
			batch := loadRebasedHookdWireBatch(t, tc.file)
			repo := NewAgentEndpointRepository(db)
			result, err := repo.AcceptEventBatch(ctx, f.tenant, f.endpoint, batch)
			if err != nil || len(result.Accepted) != len(batch.Events) || len(result.Rejected) != 0 {
				t.Fatalf("batch not accepted whole: result=%+v err=%v", result, err)
			}
			var storedSource, payloadSource, effective string
			var sessionID string
			var securityLinked bool
			if err := db.QueryRow(ctx, `SELECT local_decision->>'source', payload->'local_decision'->>'source',
				local_decision->>'effective_decision', session_id, security_event_id IS NOT NULL
				FROM agent_events WHERE tenant_id=$1 AND tool_use_id=$2 AND event_type='tool.pre'`,
				f.tenant, tc.toolUseID).Scan(&storedSource, &payloadSource, &effective, &sessionID, &securityLinked); err != nil {
				t.Fatal(err)
			}
			if storedSource != tc.source || payloadSource != tc.source {
				t.Fatalf("source not preserved: local=%q payload=%q", storedSource, payloadSource)
			}
			if effective != "block" || !securityLinked {
				t.Fatalf("server-authorized denial not projected as block: effective=%q security_event=%v", effective, securityLinked)
			}
			detail, err := NewAgentAdminRepository(db).GetSessionDetail(ctx, f.tenant, sessionID)
			if err != nil || detail == nil {
				t.Fatalf("session detail missing: %v", err)
			}
			if len(detail.Events) != len(batch.Events) || detail.Overview.BlockedCount < 1 {
				t.Fatalf("session timeline incomplete: events=%d blocked=%d", len(detail.Events), detail.Overview.BlockedCount)
			}
			seen := false
			for _, event := range detail.Events {
				var local map[string]any
				_ = json.Unmarshal(event.LocalDecision, &local)
				if event.ToolUseID == tc.toolUseID && event.EventType == "tool.pre" && local["source"] == tc.source {
					seen = true
				}
			}
			if !seen {
				t.Fatalf("session detail does not show local_decision.source=%s", tc.source)
			}
		})
	}
}
