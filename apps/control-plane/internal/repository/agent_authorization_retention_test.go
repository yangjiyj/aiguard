package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeAgentAuthorizationRetentionDB struct {
	agentAuthorizationDatabase
	mu                 sync.Mutex
	expiredRequests    int64
	expiredUsage       int64
	lockedRequests     int64
	lockedUsage        int64
	failUsageOnce      bool
	requestExecCalls   int
	usageExecCalls     int
	requestBatchLimits []int
	usageBatchLimits   []int
	cleanupAt          time.Time
	clockReads         int
}

func (db *fakeAgentAuthorizationRetentionDB) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if err := ctx.Err(); err != nil {
		return pgconn.CommandTag{}, err
	}
	db.mu.Lock()
	defer db.mu.Unlock()

	switch {
	case strings.Contains(query, "DELETE FROM agent_authorization_requests AS requests"):
		if len(args) != 2 {
			return pgconn.CommandTag{}, fmt.Errorf("request cleanup args=%d, want 2", len(args))
		}
		cutoff, cutoffOK := args[0].(time.Time)
		limit, limitOK := args[1].(int)
		if !cutoffOK || !cutoff.Equal(db.cleanupAt) || !limitOK || limit != agentAuthorizationCleanupBatchSize {
			return pgconn.CommandTag{}, fmt.Errorf("request cleanup cutoff=%v limit=%v", args[0], args[1])
		}
		db.requestExecCalls++
		db.requestBatchLimits = append(db.requestBatchLimits, limit)
		available := db.expiredRequests - db.lockedRequests
		if available < 0 {
			available = 0
		}
		deleted := min(int64(limit), available)
		db.expiredRequests -= deleted
		if db.lockedRequests > db.expiredRequests {
			db.lockedRequests = db.expiredRequests
		}
		return pgconn.NewCommandTag(fmt.Sprintf("DELETE %d", deleted)), nil
	case strings.Contains(query, "DELETE FROM agent_authorization_usage AS usage"):
		if len(args) != 3 {
			return pgconn.CommandTag{}, fmt.Errorf("usage cleanup args=%d, want 3", len(args))
		}
		cutoff, cutoffOK := args[0].(time.Time)
		windowSeconds, windowOK := args[1].(float64)
		limit, limitOK := args[2].(int)
		if !cutoffOK || !cutoff.Equal(db.cleanupAt) || !windowOK || windowSeconds != AgentAuthorizationMaxQuotaWindowSeconds || !limitOK || limit != agentAuthorizationCleanupBatchSize {
			return pgconn.CommandTag{}, fmt.Errorf("usage cleanup cutoff=%v window=%v limit=%v", args[0], args[1], args[2])
		}
		db.usageExecCalls++
		db.usageBatchLimits = append(db.usageBatchLimits, limit)
		if db.failUsageOnce {
			db.failUsageOnce = false
			return pgconn.CommandTag{}, errors.New("synthetic usage delete failure")
		}
		available := db.expiredUsage - db.lockedUsage
		if available < 0 {
			available = 0
		}
		deleted := min(int64(limit), available)
		db.expiredUsage -= deleted
		if db.lockedUsage > db.expiredUsage {
			db.lockedUsage = db.expiredUsage
		}
		return pgconn.NewCommandTag(fmt.Sprintf("DELETE %d", deleted)), nil
	default:
		return pgconn.CommandTag{}, fmt.Errorf("unexpected retention SQL: %s", query)
	}
}

func (db *fakeAgentAuthorizationRetentionDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	if err := ctx.Err(); err != nil {
		return fakeAuthorizationRow{err: err}
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	switch {
	case strings.TrimSpace(query) == agentAuthorizationCleanupClockSQL:
		if len(args) != 0 {
			return fakeAuthorizationRow{err: fmt.Errorf("cleanup clock args=%d, want 0", len(args))}
		}
		db.clockReads++
		if db.cleanupAt.IsZero() {
			db.cleanupAt = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
		}
		return fakeAuthorizationRow{values: []any{db.cleanupAt}}
	case strings.Contains(query, "FROM agent_authorization_requests"):
		if len(args) != 1 {
			return fakeAuthorizationRow{err: fmt.Errorf("request backlog args=%d, want 1", len(args))}
		}
		cutoff, ok := args[0].(time.Time)
		if !ok || !cutoff.Equal(db.cleanupAt) {
			return fakeAuthorizationRow{err: fmt.Errorf("request backlog cutoff=%v", args[0])}
		}
		return fakeAuthorizationRow{values: []any{db.expiredRequests > 0}}
	case strings.Contains(query, "FROM agent_authorization_usage"):
		if len(args) != 2 {
			return fakeAuthorizationRow{err: fmt.Errorf("usage backlog args=%d, want 2", len(args))}
		}
		cutoff, cutoffOK := args[0].(time.Time)
		windowSeconds, windowOK := args[1].(float64)
		if !cutoffOK || !cutoff.Equal(db.cleanupAt) || !windowOK || windowSeconds != AgentAuthorizationMaxQuotaWindowSeconds {
			return fakeAuthorizationRow{err: fmt.Errorf("usage backlog cutoff=%v window=%v", args[0], args[1])}
		}
		return fakeAuthorizationRow{values: []any{db.expiredUsage > 0}}
	default:
		return fakeAuthorizationRow{err: fmt.Errorf("unexpected retention backlog SQL: %s", query)}
	}
}

func TestAgentAuthorizationRetentionSQLIsBoundedAndUsesDatabaseClock(t *testing.T) {
	if agentAuthorizationCleanupClockSQL != "SELECT clock_timestamp()" {
		t.Fatalf("cleanup cutoff must be sampled from the database clock, got %q", agentAuthorizationCleanupClockSQL)
	}
	for name, query := range map[string]string{
		"requests": deleteExpiredAgentAuthorizationRequestsBatchSQL,
		"usage":    deleteOldAgentAuthorizationUsageBatchSQL,
	} {
		if strings.Contains(query, "clock_timestamp()") {
			t.Errorf("%s cleanup resamples its cutoff inside a batch", name)
		}
		if !strings.Contains(query, "FOR UPDATE SKIP LOCKED") {
			t.Errorf("%s cleanup does not skip rows in active transactions", name)
		}
		if !strings.Contains(query, "LIMIT $") {
			t.Errorf("%s cleanup is not batch bounded", name)
		}
	}
	if !strings.Contains(deleteExpiredAgentAuthorizationRequestsBatchSQL, "expires_at <= $1") {
		t.Fatal("request cleanup must preserve every receipt newer than its sampled DB cutoff")
	}
	if !strings.Contains(deleteOldAgentAuthorizationUsageBatchSQL, "window_start <= $1::timestamptz -") {
		t.Fatal("usage cleanup must use a stable sampled cutoff for closed quota windows")
	}
	if !strings.Contains(hasExpiredAgentAuthorizationRequestsSQL, "expires_at <= $1") ||
		!strings.Contains(hasOldAgentAuthorizationUsageSQL, "window_start <= $1::timestamptz -") {
		t.Fatal("backlog queries must use the same bound cutoff as deletion")
	}
	if AgentAuthorizationMaxQuotaWindowSeconds != 86400 {
		t.Fatalf("max quota window=%d, migration 861 permits 86400", AgentAuthorizationMaxQuotaWindowSeconds)
	}
}

func TestAgentAuthorizationRetentionPruneIsBoundedAndRetriesBacklog(t *testing.T) {
	db := &fakeAgentAuthorizationRetentionDB{expiredRequests: 2500, expiredUsage: 1800}
	repo := NewAgentAuthorizationRepository(db)

	first, err := repo.PruneExpiredData(context.Background())
	if err != nil {
		t.Fatalf("first cleanup failed: %v", err)
	}
	if first.DeletedRequests != 1000 || first.DeletedUsage != 1000 || first.Batches != agentAuthorizationCleanupMaxBatches || !first.Backlog {
		t.Fatalf("first cleanup was not bounded/observable: %+v", first)
	}
	if db.expiredRequests != 1500 || db.expiredUsage != 800 {
		t.Fatalf("first cleanup exceeded its cap or lost rows: remaining requests=%d usage=%d", db.expiredRequests, db.expiredUsage)
	}

	second, err := repo.PruneExpiredData(context.Background())
	if err != nil {
		t.Fatalf("retry cleanup failed: %v", err)
	}
	if second.DeletedRequests != 1000 || second.DeletedUsage != 800 || !second.Backlog {
		t.Fatalf("second cleanup result=%+v, want bounded remaining work", second)
	}
	third, err := repo.PruneExpiredData(context.Background())
	if err != nil {
		t.Fatalf("final cleanup retry failed: %v", err)
	}
	if third.DeletedRequests != 500 || third.DeletedUsage != 0 || third.Backlog {
		t.Fatalf("final cleanup result=%+v, want drained backlog", third)
	}
	if db.expiredRequests != 0 || db.expiredUsage != 0 {
		t.Fatalf("cleanup retries left rows: requests=%d usage=%d", db.expiredRequests, db.expiredUsage)
	}
	if db.clockReads != 3 {
		t.Fatalf("cleanup sampled the DB clock %d times for 3 runs, want one sample per run", db.clockReads)
	}
	for _, limit := range append(db.requestBatchLimits, db.usageBatchLimits...) {
		if limit != agentAuthorizationCleanupBatchSize {
			t.Fatalf("cleanup used unbounded batch limit %d", limit)
		}
	}
}

func TestAgentAuthorizationRetentionSkipsLockedRowsAndRetries(t *testing.T) {
	db := &fakeAgentAuthorizationRetentionDB{expiredRequests: 3, lockedRequests: 3}
	repo := NewAgentAuthorizationRepository(db)
	first, err := repo.PruneExpiredData(context.Background())
	if err != nil {
		t.Fatalf("cleanup with locked rows failed: %v", err)
	}
	if first.DeletedRequests != 0 || !first.Backlog {
		t.Fatalf("locked expired rows should remain observable: %+v", first)
	}

	db.mu.Lock()
	db.lockedRequests = 0
	db.mu.Unlock()
	retry, err := repo.PruneExpiredData(context.Background())
	if err != nil {
		t.Fatalf("retry after lock release failed: %v", err)
	}
	if retry.DeletedRequests != 3 || retry.Backlog {
		t.Fatalf("retry did not drain expired rows: %+v", retry)
	}
}

func TestAgentAuthorizationRetentionPartialFailureIsRetryable(t *testing.T) {
	db := &fakeAgentAuthorizationRetentionDB{expiredRequests: 150, expiredUsage: 50, failUsageOnce: true}
	repo := NewAgentAuthorizationRepository(db)
	first, err := repo.PruneExpiredData(context.Background())
	if err == nil || !strings.Contains(err.Error(), "synthetic usage delete failure") {
		t.Fatalf("first cleanup error=%v, want synthetic delete failure", err)
	}
	if first.DeletedRequests != 100 || first.DeletedUsage != 0 || !first.Backlog {
		t.Fatalf("partial cleanup result=%+v, want committed request batch and backlog", first)
	}

	retry, err := repo.PruneExpiredData(context.Background())
	if err != nil {
		t.Fatalf("cleanup retry failed: %v", err)
	}
	if retry.DeletedRequests != 50 || retry.DeletedUsage != 50 || retry.Backlog {
		t.Fatalf("cleanup retry result=%+v, want all remaining rows removed", retry)
	}
}

func TestAgentAuthorizationRetentionHonorsCancellationAndNilRepository(t *testing.T) {
	db := &fakeAgentAuthorizationRetentionDB{expiredRequests: 1}
	repo := NewAgentAuthorizationRepository(db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := repo.PruneExpiredData(ctx)
	if !errors.Is(err, context.Canceled) || !result.Backlog {
		t.Fatalf("canceled cleanup result=%+v error=%v, want canceled/backlog", result, err)
	}
	if db.requestExecCalls != 0 || db.usageExecCalls != 0 || db.clockReads != 0 {
		t.Fatalf("canceled cleanup executed SQL: request=%d usage=%d clock_reads=%d", db.requestExecCalls, db.usageExecCalls, db.clockReads)
	}
	if _, err := (*AgentAuthorizationRepository)(nil).PruneExpiredData(context.Background()); err == nil {
		t.Fatal("nil repository should return a safe error")
	}
}

func TestAgentAuthorizationRetentionConcurrentRunsDoNotDoubleCount(t *testing.T) {
	db := &fakeAgentAuthorizationRetentionDB{expiredRequests: 250, expiredUsage: 175}
	const workers = 8
	type result struct {
		cleanup AgentAuthorizationCleanupResult
		err     error
	}
	results := make(chan result, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cleanup, err := NewAgentAuthorizationRepository(db).PruneExpiredData(context.Background())
			results <- result{cleanup: cleanup, err: err}
		}()
	}
	wg.Wait()
	close(results)
	var deletedRequests, deletedUsage int64
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent cleanup failed: %v", result.err)
		}
		deletedRequests += result.cleanup.DeletedRequests
		deletedUsage += result.cleanup.DeletedUsage
	}
	if deletedRequests != 250 || deletedUsage != 175 || db.expiredRequests != 0 || db.expiredUsage != 0 {
		t.Fatalf("concurrent cleanup duplicated or lost work: deleted_requests=%d deleted_usage=%d remaining_requests=%d remaining_usage=%d", deletedRequests, deletedUsage, db.expiredRequests, db.expiredUsage)
	}
}

func TestAgentAuthorizationRetentionMigrationAddsUsageWindowIndex(t *testing.T) {
	migrations := filepath.Join("..", "..", "..", "..", "deploy", "migrations")
	retentionPath := filepath.Join(migrations, "864_agent_authorization_retention_index.sql")
	retentionSQL, err := os.ReadFile(retentionPath)
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(retentionSQL))
	if !strings.Contains(sql, "create index if not exists idx_agent_authorization_usage_window_start") ||
		!strings.Contains(sql, "on agent_authorization_usage (window_start)") {
		t.Fatalf("migration does not add the bounded usage cleanup index: %s", sql)
	}
	authorizationSQL, err := os.ReadFile(filepath.Join(migrations, "861_trusted_agent_authorization.sql"))
	if err != nil {
		t.Fatal(err)
	}
	authorizationSchema := strings.Join(strings.Fields(strings.ToLower(string(authorizationSQL))), " ")
	quotaBound := fmt.Sprintf("quota_window_seconds integer not null check (quota_window_seconds between 1 and %d)", AgentAuthorizationMaxQuotaWindowSeconds)
	if !strings.Contains(authorizationSchema, quotaBound) {
		t.Fatalf("cleanup window bound %d does not match migration 861 quota constraint", AgentAuthorizationMaxQuotaWindowSeconds)
	}
	for _, prior := range []string{"860_unified_agent_assets.sql", "861_trusted_agent_authorization.sql", "862_agent_native_events.sql", "863_agent_hook_event_projection.sql"} {
		if _, err := os.Stat(filepath.Join(migrations, prior)); err != nil {
			t.Fatalf("new cleanup migration must not replace prior migration %s: %v", prior, err)
		}
	}
	for _, forbidden := range []string{"drop table", "delete from", "truncate"} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("index migration contains destructive SQL %q", forbidden)
		}
	}
}
