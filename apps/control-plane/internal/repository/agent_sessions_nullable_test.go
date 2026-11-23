package repository

import (
	"database/sql"
	"os"
	"strings"
	"testing"
)

type nullableAgentSessionRow struct{}

func (nullableAgentSessionRow) Scan(dest ...any) error {
	*(dest[0].(*string)) = "row-1"
	*(dest[1].(*string)) = "tenant-a"
	*(dest[2].(*sql.NullString)) = sql.NullString{}
	*(dest[3].(*sql.NullString)) = sql.NullString{String: "user-a", Valid: true}
	*(dest[4].(*string)) = "session-a"
	*(dest[5].(*sql.NullString)) = sql.NullString{String: "claude-code", Valid: true}
	*(dest[6].(*sql.NullString)) = sql.NullString{}
	*(dest[7].(*sql.NullString)) = sql.NullString{}
	*(dest[8].(*sql.NullString)) = sql.NullString{}
	*(dest[9].(*sql.NullTime)) = sql.NullTime{}
	*(dest[10].(*sql.NullTime)) = sql.NullTime{}
	*(dest[11].(*int)) = 1
	*(dest[12].(*int)) = 0
	*(dest[13].(*string)) = "active"
	*(dest[14].(*sql.NullTime)) = sql.NullTime{}
	*(dest[15].(*sql.NullTime)) = sql.NullTime{}
	return nil
}

func TestScanAgentSessionAcceptsNullableProjectID(t *testing.T) {
	session, err := scanAgentSession(nullableAgentSessionRow{})
	if err != nil {
		t.Fatal(err)
	}
	if session.ProjectID != "" || session.SessionID != "session-a" || session.TenantID != "tenant-a" {
		t.Fatalf("unexpected session: %+v", session)
	}
}

func TestAgentSessionQueriesCoalesceNullableCounters(t *testing.T) {
	body, err := os.ReadFile("agent_sessions.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, required := range []string{"COALESCE(request_count, 0)", "COALESCE(risk_score, 0)"} {
		if count := strings.Count(source, required); count != 2 {
			t.Errorf("%s count=%d want 2", required, count)
		}
	}
}
