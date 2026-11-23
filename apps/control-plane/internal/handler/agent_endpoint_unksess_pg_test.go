package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// F-UNKSESS (batch 6 semantics) through the real Events handler + repository + PostgreSQL:
// - session_id "unknown" -> 200, every id in rejected[], code invalid_session, 0 rows;
// - the same session id from a second endpoint -> 200, rejected[] session_ownership_conflict;
// - a normal session is accepted.
func TestAgentEndpointEventsUnknownSessionAndOwnershipConflict(t *testing.T) {
	db, tenant, eps := unksessSetup(t)
	w := unksessPost(t, db, tenant, eps[0], unksessWireBatch(t, "unknown"))
	if body := decodeEventsAck(t, w); w.Code != http.StatusOK || len(body.Accepted) != 0 || len(body.Rejected) != 8 || body.Rejections[0].Code != "invalid_session" {
		t.Fatalf("unknown session: %d %s", w.Code, w.Body.String())
	}
	var events int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM agent_events WHERE tenant_id=$1`, tenant).Scan(&events); err != nil || events != 0 {
		t.Fatalf("unknown session stored %d rows (%v)", events, err)
	}
	session := "unksess-" + uuid.NewString()
	if w := unksessPost(t, db, tenant, eps[0], unksessWireBatch(t, session)); w.Code != http.StatusOK {
		t.Fatalf("normal session: %d %s", w.Code, w.Body.String())
	}
	w = unksessPost(t, db, tenant, eps[1], unksessWireBatch(t, session))
	if body := decodeEventsAck(t, w); w.Code != http.StatusOK || len(body.Rejected) != 8 || body.Rejections[0].Code != "session_ownership_conflict" {
		t.Fatalf("second endpoint same session: %d %s", w.Code, w.Body.String())
	}
}

type eventsAck struct {
	Accepted, Duplicates, Rejected []string
	Rejections                     []eventsRejection `json:"rejections"`
	Error                          string            `json:"error"`
}

type eventsRejection struct {
	EventID string `json:"event_id"`
	Code    string `json:"code"`
}

// decodeEventsAck decodes the events ACK; Rejections is padded so tests can index [0] safely.
func decodeEventsAck(t *testing.T, w *httptest.ResponseRecorder) eventsAck {
	t.Helper()
	var body eventsAck
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	if len(body.Rejections) == 0 {
		body.Rejections = []eventsRejection{{}}
	}
	return body
}

func containsCode(body, code string) bool {
	return strings.Contains(body, `"`+code+`"`)
}
