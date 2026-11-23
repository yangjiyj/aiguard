package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

type intentTaskGrantRows struct {
	rows    [][]any
	current []any
	index   int
	closed  bool
	err     error
}

func (rows *intentTaskGrantRows) Close()                                       { rows.closed = true }
func (rows *intentTaskGrantRows) Err() error                                   { return rows.err }
func (rows *intentTaskGrantRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (rows *intentTaskGrantRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *intentTaskGrantRows) Next() bool {
	if rows.closed || rows.index >= len(rows.rows) {
		return false
	}
	rows.current = rows.rows[rows.index]
	rows.index++
	return true
}
func (rows *intentTaskGrantRows) Scan(dest ...any) error {
	return (fakeAuthorizationRow{values: rows.current}).Scan(dest...)
}
func (rows *intentTaskGrantRows) Values() ([]any, error) { return rows.current, nil }
func (rows *intentTaskGrantRows) RawValues() [][]byte    { return nil }
func (rows *intentTaskGrantRows) Conn() *pgx.Conn        { return nil }

type intentTaskGrantQuerier struct {
	rows                *intentTaskGrantRows
	expiresAt           time.Time
	queryRowBeforeClose bool
	queryRowCalls       int
}

func (querier *intentTaskGrantQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return querier.rows, nil
}

func (querier *intentTaskGrantQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	querier.queryRowCalls++
	if !querier.rows.closed {
		querier.queryRowBeforeClose = true
		return fakeAuthorizationRow{err: errors.New("conn busy: rows are still open")}
	}
	return fakeAuthorizationRow{values: []any{
		"grant-1", "file_read", "file", "/workspace/notes.txt", querier.expiresAt,
	}}
}

func TestResolveIntentTaskGrantSnapshotsClosesRowsBeforeLiveGrantQuery(t *testing.T) {
	expiresAt := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	rows := &intentTaskGrantRows{rows: [][]any{{
		"grant-1", "file_read", "file", agentintent.DigestString("/workspace/notes.txt"), expiresAt,
	}}}
	querier := &intentTaskGrantQuerier{rows: rows, expiresAt: expiresAt}

	scopes, err := recheckIntentTaskGrantSnapshots(context.Background(), querier, "tenant-1", "principal-1", "task-1")
	if err != nil {
		t.Fatalf("recheck snapshots: %v", err)
	}
	if !rows.closed || querier.queryRowBeforeClose || querier.queryRowCalls != 1 {
		t.Fatalf("grant rows must be closed before live-grant query: closed=%v early_query=%v calls=%d",
			rows.closed, querier.queryRowBeforeClose, querier.queryRowCalls)
	}
	if len(scopes) != 1 || scopes[0].GrantID != "grant-1" || scopes[0].Action != "file_read" ||
		scopes[0].ResourceRefHash != agentintent.DigestString("/workspace/notes.txt") || !scopes[0].ExpiresAt.Equal(expiresAt) {
		t.Fatalf("unexpected active task grant snapshots: %#v", scopes)
	}
}
