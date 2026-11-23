package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupAuditChainTestDB(t *testing.T) (*pgxpool.Pool, *AuditChainRepository) {
	t.Helper()

	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
	})

	key := []byte("test-hmac-key-p8")
	repo := NewAuditChainRepository(db, key)
	return db, repo
}

func TestAuditChainAppendAndVerify(t *testing.T) {
	_, repo := setupAuditChainTestDB(t)
	ctx := context.Background()

	// Record max seq before our inserts
	stats0, err := repo.Stats(ctx)
	if err != nil {
		t.Fatalf("stats before: %v", err)
	}
	startMaxSeq := stats0.MaxSeq

	tenantID := fmt.Sprintf("tenant_ac_%d", time.Now().UnixNano())

	for i := 1; i <= 3; i++ {
		eventID := fmt.Sprintf("evt_%d_%d", i, time.Now().UnixNano())
		err := repo.Append(ctx, tenantID, "test_event", eventID, map[string]any{
			"index":  i,
			"tenant": tenantID,
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	stats1, err := repo.Stats(ctx)
	if err != nil {
		t.Fatalf("stats after: %v", err)
	}
	if stats1.Count < stats0.Count+3 {
		t.Fatalf("expected at least %d rows, got %d", stats0.Count+3, stats1.Count)
	}

	// Verify only the 3 rows we just inserted (seq range = startMaxSeq+1 to startMaxSeq+3)
	fromSeq := startMaxSeq + 1
	toSeq := startMaxSeq + 3

	result, err := repo.Verify(ctx, fromSeq, toSeq)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.OK {
		t.Fatalf("verify failed at seq %d: %s", result.FirstBreakAtSeq, result.Detail)
	}
}

func TestAuditChainStatsNonNegative(t *testing.T) {
	_, repo := setupAuditChainTestDB(t)
	ctx := context.Background()

	stats, err := repo.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Count < 0 {
		t.Fatalf("count should be non-negative, got %d", stats.Count)
	}
}

func TestAuditChainHeaderContractConflictOnceAndCollision(t *testing.T) {
	_, repo := setupAuditChainTestDB(t)
	ctx := context.Background()
	id := fmt.Sprintf("header-contract-conflict:%d", time.Now().UnixNano())
	payload := map[string]any{"service": "control-plane.internal", "header_kind": "tenant_id", "request_id": "req", "source_ip": ""}
	if err := repo.AppendHeaderContractConflictOnce(ctx, "", id, payload); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- repo.AppendHeaderContractConflictOnce(ctx, "", id, payload) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent same occurrence: %v", err)
		}
	}
	var count int
	if err := repo.db.QueryRow(ctx, `SELECT count(*) FROM audit_chain WHERE event_type='header_contract_conflict' AND event_id=$1`, id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("same occurrence WORM rows=%d err=%v", count, err)
	}
	secondID := fmt.Sprintf("header-contract-conflict:%d", time.Now().UnixNano()+1)
	if err := repo.AppendHeaderContractConflictOnce(ctx, "", secondID, payload); err != nil {
		t.Fatal(err)
	}
	if err := repo.AppendHeaderContractConflictOnce(ctx, "", id, payload); err != nil {
		t.Fatal(err)
	}
	changed := map[string]any{"service": "control-plane.internal", "header_kind": "tenant_id", "request_id": "changed", "source_ip": ""}
	if err := repo.AppendHeaderContractConflictOnce(ctx, "", id, changed); !errors.Is(err, ErrHeaderContractCollision) {
		t.Fatalf("collision=%v", err)
	}
	typedID := fmt.Sprintf("header-contract-conflict:%d", time.Now().UnixNano()+2)
	if err := repo.Append(ctx, "", "different_event_type", typedID, payload); err != nil {
		t.Fatal(err)
	}
	if err := repo.AppendHeaderContractConflictOnce(ctx, "", typedID, payload); !errors.Is(err, ErrHeaderContractCollision) {
		t.Fatalf("typed collision=%v", err)
	}
}

func TestAuditChainHeaderContractSequenceGapAndConcurrentDistinctConflictsRemainVerifiable(t *testing.T) {
	db, repo := setupAuditChainTestDB(t)
	ctx := context.Background()

	// PostgreSQL sequences are non-transactional: a rolled-back transaction
	// permanently consumes a value. The chain must hash the actual reserved seq,
	// not assume max(seq)+1.
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var burnedSeq int64
	if err := tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('audit_chain','seq'))`).Scan(&burnedSeq); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	prefix := fmt.Sprintf("header-contract-sequence-%d", time.Now().UnixNano())
	const n = 8
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("%s-%d", prefix, i)
			payload := map[string]any{
				"service": "gateway-core.api", "header_kind": "session_id",
				"request_id": fmt.Sprintf("req-%d", i), "source_ip": "203.0.113.9",
			}
			errs <- repo.AppendHeaderContractConflictOnce(ctx, "", id, payload)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent distinct append: %v", err)
		}
	}
	// Restored databases can also have a sequence behind max(seq). The append
	// path must realign it under the same lock before reserving the hash input.
	var lowered int64
	if err := db.QueryRow(ctx, `SELECT setval(pg_get_serial_sequence('audit_chain','seq'),1,true)`).Scan(&lowered); err != nil {
		t.Fatal(err)
	}

	if err := repo.Append(ctx, "", "post_gap_event", prefix+"-tail", map[string]any{"request_id": "tail"}); err != nil {
		t.Fatal(err)
	}

	var firstSeq, lastSeq int64
	var count int
	if err := db.QueryRow(ctx, `SELECT min(seq),max(seq),count(*) FROM audit_chain WHERE event_id LIKE $1`, prefix+"%").Scan(&firstSeq, &lastSeq, &count); err != nil {
		t.Fatal(err)
	}
	if count != n+1 || firstSeq <= burnedSeq {
		t.Fatalf("count=%d first=%d burned=%d last=%d", count, firstSeq, burnedSeq, lastSeq)
	}
	verified, err := repo.Verify(ctx, firstSeq, lastSeq)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.OK {
		t.Fatalf("sequence-gap chain broke at %d: %s", verified.FirstBreakAtSeq, verified.Detail)
	}
}
