package repository

import (
	"encoding/json"
	"os"
	"testing"
)

func TestHookdProcessCapturedWireProjection(t *testing.T) {
	path := os.Getenv("HOOKD_CONTRACT_BATCH")
	if path == "" {
		t.Skip("explicit captured hookd batch required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var batch AgentEventBatchRequest
	if err := json.Unmarshal(raw, &batch); err != nil {
		t.Fatal(err)
	}
	if batch.SchemaVersion != "events.v1" || batch.EndpointID != "ep_wirefixture" || len(batch.Events) != 11 {
		t.Fatal("unexpected wire witness")
	}
	seen := map[string]bool{}
	for _, raw := range batch.Events {
		r, err := decodeAgentEvent(raw, batch.EndpointID)
		if err != nil {
			t.Fatal(err)
		}
		if r.Native == nil || r.SessionID == "" || r.EndpointID != batch.EndpointID || r.ID == "" {
			t.Fatal("lost nested identity")
		}
		if len(r.SessionID) <= 64 {
			t.Fatal("long session fixture lost")
		}
		var original, stored map[string]any
		_ = json.Unmarshal(raw, &original)
		_ = json.Unmarshal(r.Payload, &stored)
		if original["event_id"] != stored["event_id"] || original["event_type"] != stored["event_type"] {
			t.Fatal("raw event changed")
		}
		if r.EventType == "tool.post" || r.EventType == "tool.failure" {
			kind, execution, result := agentToolLifecycleFacts(r)
			if !r.HasResult || !execution || !result || kind != "result_observed" || r.ToolUseID != "wire-tool" {
				t.Fatal("lost actual tool result")
			}
		}
		if r.EventType == "tool.denied" && r.Status != "blocked" {
			t.Fatal("denied status missing")
		}
		seen[r.EventType] = true
	}
	if len(seen) != 11 {
		t.Fatal("lost actual event kind")
	}
}
