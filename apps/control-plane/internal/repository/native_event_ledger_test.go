package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/agentidentity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const nativeTestID1 = "aaaaaaaa-1111-4111-8111-111111111111"
const nativeTestID2 = "bbbbbbbb-2222-4222-8222-222222222222"

func nativeTestEvent(id, name string) string {
	return `{"event_id":"` + id + `","occurred_at":"2026-09-25T00:00:00Z","event_type":"carrier.observed","carrier":{"kind":"carrier","namespace":"dify","native_id":"` + name + `"},"product":"dify","runtime":"service"}`
}
func nativeTestBatch(events ...string) []byte {
	return []byte(`{"schema_version":"1.0","producer":{"kind":"service","native_id":"install-A"},"events":[` + strings.Join(events, ",") + `]}`)
}

type nativeTestRow struct {
	value string
	err   error
}

func (r nativeTestRow) Scan(dst ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dst[0].(*string)) = r.value
	return nil
}

type nativeTestDB struct {
	tenant, endpoint, token    string
	stored                     map[string]string
	refs                       int
	begins, commits, rollbacks int
	commitErr                  error
}
type nativeTestTx struct {
	pgx.Tx
	db      *nativeTestDB
	pending map[string]string
	refs    int
	done    bool
}

func nativeTestRepo() (*NativeEventLedger, *nativeTestDB, NativeEventTransport) {
	db := &nativeTestDB{tenant: "tenant-a", endpoint: "ep-a", token: strings.Repeat("a", 64), stored: map[string]string{}}
	repo := &NativeEventLedger{begin: func(context.Context) (pgx.Tx, error) {
		db.begins++
		p := map[string]string{}
		for k, v := range db.stored {
			p[k] = v
		}
		return &nativeTestTx{db: db, pending: p, refs: db.refs}, nil
	}}
	return repo, db, NativeEventTransport{db.tenant, db.endpoint, db.token}
}
func (tx *nativeTestTx) QueryRow(_ context.Context, q string, a ...any) pgx.Row {
	if strings.Contains(q, "FROM agent_endpoints") {
		if !strings.Contains(q, "FOR UPDATE") || !strings.Contains(q, "token_hash=$3") || !strings.Contains(q, "tenant_id=$1") {
			return nativeTestRow{err: errors.New("missing locked credential scope")}
		}
		if a[0] != tx.db.tenant || a[1] != tx.db.endpoint || a[2] != tx.db.token {
			return nativeTestRow{err: pgx.ErrNoRows}
		}
		return nativeTestRow{value: tx.db.endpoint}
	}
	if strings.Contains(q, "SELECT payload_hash FROM agent_native_events") {
		if !strings.Contains(q, "tenant_id=$1 AND endpoint_id=$2 AND event_id=$3") {
			return nativeTestRow{err: errors.New("missing replay scope")}
		}
		key := a[0].(string) + "/" + a[1].(string) + "/" + strings.ToLower(a[2].(string))
		value, ok := tx.pending[key]
		if !ok {
			return nativeTestRow{err: pgx.ErrNoRows}
		}
		return nativeTestRow{value: value}
	}
	return nativeTestRow{err: errors.New("unexpected query")}
}
func (tx *nativeTestTx) Exec(_ context.Context, q string, a ...any) (pgconn.CommandTag, error) {
	if a[0] != tx.db.tenant || a[1] != tx.db.endpoint {
		return pgconn.CommandTag{}, errors.New("write lost transport scope")
	}
	if strings.Contains(q, "INSERT INTO agent_native_events") {
		key := a[0].(string) + "/" + a[1].(string) + "/" + strings.ToLower(a[2].(string))
		if _, ok := tx.pending[key]; ok {
			return pgconn.NewCommandTag("INSERT 0 0"), nil
		}
		tx.pending[key] = a[8].(string)
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}
	if strings.Contains(q, "INSERT INTO agent_native_event_refs") {
		tx.refs++
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}
	return pgconn.CommandTag{}, errors.New("unexpected exec")
}
func (tx *nativeTestTx) Commit(context.Context) error {
	if tx.db.commitErr != nil {
		return tx.db.commitErr
	}
	tx.db.stored = tx.pending
	tx.db.refs = tx.refs
	tx.db.commits++
	tx.done = true
	return nil
}
func (tx *nativeTestTx) Rollback(context.Context) error {
	if !tx.done {
		tx.db.rollbacks++
		tx.done = true
	}
	return nil
}

func TestNativeEventLedgerReplayAndAtomicConflict(t *testing.T) {
	repo, db, auth := nativeTestRepo()
	ctx := context.Background()
	first := nativeTestEvent(nativeTestID1, "carrier-a")
	got, err := repo.Ingest(ctx, auth, nativeTestBatch(first, first))
	if err != nil || len(got.Accepted) != 1 || len(got.Duplicates) != 0 || db.refs != 1 {
		t.Fatalf("first receipt=%+v err=%v refs=%d", got, err, db.refs)
	}
	got, err = repo.Ingest(ctx, auth, nativeTestBatch(first))
	if err != nil || len(got.Duplicates) != 1 || len(got.Accepted) != 0 || db.refs != 1 {
		t.Fatalf("replay receipt=%+v err=%v", got, err)
	}
	// A preceding fresh insert must disappear when a later event conflicts.
	got, err = repo.Ingest(ctx, auth, nativeTestBatch(nativeTestEvent(nativeTestID2, "new"), nativeTestEvent(nativeTestID1, "changed")))
	if !errors.Is(err, ErrNativeEventConflict) || got != nil || len(db.stored) != 1 || db.refs != 1 || db.rollbacks != 1 {
		t.Fatalf("atomic conflict receipt=%+v err=%v stored=%d refs=%d rolls=%d", got, err, len(db.stored), db.refs, db.rollbacks)
	}
}
func TestNativeEventLedgerRejectsChangedProducerAndInBatchConflict(t *testing.T) {
	repo, db, auth := nativeTestRepo()
	ctx := context.Background()
	first := nativeTestEvent(nativeTestID1, "carrier-a")
	_, err := repo.Ingest(ctx, auth, nativeTestBatch(first))
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(nativeTestBatch(first)), "install-A", "install-B", 1)
	if _, err = repo.Ingest(ctx, auth, []byte(changed)); !errors.Is(err, ErrNativeEventConflict) {
		t.Fatalf("producer reuse: %v", err)
	}
	before := db.begins
	if _, err = repo.Ingest(ctx, auth, nativeTestBatch(first, nativeTestEvent(nativeTestID1, "different"))); !errors.Is(err, ErrNativeEventConflict) {
		t.Fatalf("in-batch conflict: %v", err)
	}
	if db.begins != before {
		t.Fatal("in-batch conflict began transaction")
	}
}
func TestNativeEventLedgerRechecksTenantEndpointCredential(t *testing.T) {
	for _, field := range []string{"tenant", "endpoint", "credential"} {
		t.Run(field, func(t *testing.T) {
			repo, db, auth := nativeTestRepo()
			switch field {
			case "tenant":
				auth.TenantID = "tenant-b"
			case "endpoint":
				auth.EndpointID = "ep-b"
			case "credential":
				auth.CredentialHash = strings.Repeat("b", 64)
			}
			got, err := repo.Ingest(context.Background(), auth, nativeTestBatch(nativeTestEvent(nativeTestID1, "a")))
			if !errors.Is(err, ErrNativeEventUnauthorized) || got != nil || len(db.stored) != 0 || db.commits != 0 {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}
func TestNativeEventLedgerInvalidAndCommitFailureNeverACK(t *testing.T) {
	repo, db, auth := nativeTestRepo()
	if _, err := repo.Ingest(context.Background(), auth, []byte(`{"tenant_id":"forged"}`)); !errors.Is(err, ErrNativeEventInvalid) || db.begins != 0 {
		t.Fatalf("invalid=%v begins=%d", err, db.begins)
	}
	db.commitErr = errors.New("commit failed")
	got, err := repo.Ingest(context.Background(), auth, nativeTestBatch(nativeTestEvent(nativeTestID1, "a")))
	if err == nil || got != nil || len(db.stored) != 0 || db.rollbacks != 1 {
		t.Fatalf("commit got=%+v err=%v", got, err)
	}
}
func TestNativeEventLedgerIdentityTupleAndCanonicalReplay(t *testing.T) {
	p := agentidentity.Producer{Kind: "service", NativeID: "install"}
	if nativeSourceID("a", p) == nativeSourceID("b", p) {
		t.Fatal("cross-endpoint scope collapsed")
	}
	a := agentidentity.NativeRef{Kind: "run", Namespace: "a/b", NativeID: "c"}
	b := agentidentity.NativeRef{Kind: "run", Namespace: "a", NativeID: "b/c"}
	if nativeRefHash(a) == nativeRefHash(b) {
		t.Fatal("delimiter identities collapsed")
	}
	b = a
	b.Revision = "v2"
	if nativeRefHash(a) == nativeRefHash(b) {
		t.Fatal("revision identities collapsed")
	}
	raw := nativeTestBatch(nativeTestEvent(nativeTestID1, "a"))
	env, err := agentidentity.ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !env.Events[0].OccurredAt.Equal(time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("source time changed")
	}
	ordered := []byte(strings.Replace(string(raw), `"product":"dify","runtime":"service"`, `"runtime":"service","product":"dify"`, 1))
	repo, _, auth := nativeTestRepo()
	if _, err = repo.Ingest(context.Background(), auth, raw); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Ingest(context.Background(), auth, ordered)
	if err != nil || len(got.Duplicates) != 1 {
		t.Fatalf("canonical replay=%+v err=%v", got, err)
	}
}

func TestNativeEventLedgerUUIDCasePolicy(t *testing.T) {
	repo, db, auth := nativeTestRepo()
	lower := nativeTestEvent(nativeTestID1, "carrier")
	upper := nativeTestEvent(strings.ToUpper(nativeTestID1), "carrier")
	ctx := context.Background()
	if _, err := repo.Ingest(ctx, auth, nativeTestBatch(lower, upper)); !errors.Is(err, ErrNativeEventConflict) || db.begins != 0 {
		t.Fatalf("mixed case duplicate should conflict before transaction: %v", err)
	}
	if _, err := repo.Ingest(ctx, auth, nativeTestBatch(upper)); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Ingest(ctx, auth, nativeTestBatch(upper))
	if err != nil || len(got.Duplicates) != 1 || got.Duplicates[0] != strings.ToUpper(nativeTestID1) {
		t.Fatalf("source spelling not preserved: %+v %v", got, err)
	}
	if _, err = repo.Ingest(ctx, auth, nativeTestBatch(lower)); !errors.Is(err, ErrNativeEventConflict) || len(db.stored) != 1 {
		t.Fatalf("case change must not create a second UUID observation: %v rows=%d", err, len(db.stored))
	}
}
