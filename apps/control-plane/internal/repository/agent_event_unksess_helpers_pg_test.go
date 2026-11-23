package repository

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// F-UNKSESS helpers: take a real hookd a0296bf6 wire batch and rewrite the nested session id and
// the event ids (fresh per call, so replays in one tenant do not collide as duplicates/conflicts).
func unksessBatch(t *testing.T, sessionID string) AgentEventBatchRequest {
	t.Helper()
	batch := loadRebasedHookdWireBatch(t, "batch-a-cc-t13-deny.json")
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	for i, raw := range batch.Events {
		var event map[string]any
		if err := json.Unmarshal(raw, &event); err != nil {
			t.Fatal(err)
		}
		id := event["event_id"].(string)
		event["event_id"] = id[:len(id)-12] + suffix[:11] + string("0123456789abcdef"[i])
		event["session"].(map[string]any)["session_id"] = sessionID
		var err error
		if batch.Events[i], err = json.Marshal(event); err != nil {
			t.Fatal(err)
		}
	}
	return batch
}
