package outbox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
)

type fakeDB struct {
	query string
	args  []any
	err   error
}

func (f *fakeDB) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	f.query = query
	f.args = args
	return pgconn.CommandTag{}, f.err
}

func (f *fakeDB) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	f.query = query
	f.args = args
	return fakeRows{}, f.err
}

func TestStoreEnqueuePersistsValidatedEvent(t *testing.T) {
	db := &fakeDB{}
	store := NewStore(db)
	occurredAt := time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC)
	event, err := eventbus.NewEvent(eventbus.EventTypeAuditContentLogRequested, "tenant_1", "trace_1", "req_1", occurredAt, map[string]any{"role": "user"})
	if err != nil {
		t.Fatalf("NewEvent: %v", err)
	}

	if err := store.Enqueue(context.Background(), event); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if !strings.Contains(db.query, "INSERT INTO outbox_events") {
		t.Fatalf("expected insert into outbox_events, got %s", db.query)
	}
	if got := db.args[0]; got != event.ID {
		t.Fatalf("id arg = %v, want %s", got, event.ID)
	}
	if got := db.args[2]; got != eventbus.EventTypeAuditContentLogRequested {
		t.Fatalf("event type arg = %v", got)
	}
	if got := db.args[7]; got != occurredAt {
		t.Fatalf("occurred_at arg = %v", got)
	}
}

func TestStoreEnqueueRejectsInvalidEvent(t *testing.T) {
	store := NewStore(&fakeDB{})
	if err := store.Enqueue(context.Background(), eventbus.Event{}); err == nil {
		t.Fatal("expected invalid event error")
	}
}

func TestStoreMarkFailedDefaultsMaxAttempts(t *testing.T) {
	db := &fakeDB{}
	store := NewStore(db)
	next := time.Date(2026, 6, 19, 10, 1, 0, 0, time.UTC)

	if err := store.MarkFailed(context.Background(), "evt_1", errors.New("boom"), 0, next); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	if !strings.Contains(db.query, "attempts >= $3") {
		t.Fatalf("query should dead-letter after max attempts: %s", db.query)
	}
	if got := db.args[2]; got != DefaultMaxAttempts {
		t.Fatalf("max attempts = %v, want %d", got, DefaultMaxAttempts)
	}
	if got := db.args[3]; got != next {
		t.Fatalf("next available = %v, want %v", got, next)
	}
}

func TestStoreClaimReclaimsStaleProcessingEvents(t *testing.T) {
	db := &fakeDB{}
	store := NewStore(db)

	_, err := store.Claim(context.Background(), "worker-a", 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if !strings.Contains(db.query, "status = 'processing'") || !strings.Contains(db.query, "INTERVAL '5 minutes'") {
		t.Fatalf("claim query should reclaim stale processing events: %s", db.query)
	}
}

func TestStoreClaimRequiresConsumer(t *testing.T) {
	store := NewStore(&fakeDB{})
	if _, err := store.Claim(context.Background(), "", 1); err == nil {
		t.Fatal("expected consumer validation error")
	}
}

type fakeRows struct{}

func (fakeRows) Close() {}

func (fakeRows) Err() error { return nil }

func (fakeRows) CommandTag() pgconn.CommandTag { return pgconn.CommandTag{} }

func (fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }

func (fakeRows) Next() bool { return false }

func (fakeRows) Scan(dest ...any) error { return errors.New("no row") }

func (fakeRows) Values() ([]any, error) { return nil, errors.New("no row") }

func (fakeRows) RawValues() [][]byte { return nil }

func (fakeRows) Conn() *pgx.Conn { return nil }
