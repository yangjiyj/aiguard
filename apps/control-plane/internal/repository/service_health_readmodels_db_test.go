package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newBillingReadModelTestRepo guards the real-PostgreSQL tests. Fixtures run
// against the one-off BILLING_TEST_DATABASE_URL database (full migrations,
// dedicated to this task); production data is never used.
func newBillingReadModelTestRepo(t *testing.T) (*ServiceHealthReadModelRepository, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("BILLING_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("BILLING_TEST_DATABASE_URL not set; skipping real-DB test")
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("connect billing read-model test pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return NewServiceHealthReadModelRepository(pool), pool
}

// newBillingUnsafeTestRepo returns a pool to a SEPARATE sacrificial database
// for tests that must insert constraint-violating rows. Such a test has to
// drop the table CHECKs and can only restore them NOT VALID (the foreign row
// is append-only and can never satisfy them again), which would permanently
// downgrade the main test database's constraints to convalidated=false.
// The sacrificial database is disposable: never point it at the main one.
func newBillingUnsafeTestRepo(t *testing.T) (*ServiceHealthReadModelRepository, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("BILLING_TEST_DATABASE_URL_UNSAFE")
	if databaseURL == "" {
		t.Skip("BILLING_TEST_DATABASE_URL_UNSAFE not set; skipping constraint-violating test")
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("connect billing unsafe test pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return NewServiceHealthReadModelRepository(pool), pool
}

// readModelRunSuffix gives every run its own tenant/user/wallet ids so tests
// stay rerun-safe on the shared one-off database even though the billing
// ledger is append-only and cannot be deleted.
var readModelRunSuffix = fmt.Sprintf("_%d", time.Now().UnixNano())

func mustExecReadModel(t *testing.T, pool *pgxpool.Pool, query string, args ...interface{}) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatalf("exec fixture %q: %v", query, err)
	}
}

// seedWallet creates tenant+user+wallet with an explicit created_at and live
// state so tests can position the wallet before or after period boundaries
// deterministically and keep the live wallet state consistent with the ledger
// history (every balance change in the store goes through the ledger, so the
// live balance/reserved must equal the final entry's *_after values).
func seedWallet(t *testing.T, pool *pgxpool.Pool, tenantID, userID, walletID string, walletCreatedAt time.Time, balanceMicros, reservedMicros int64) {
	t.Helper()
	mustExecReadModel(t, pool, `
		INSERT INTO tenants(id, name, edition, status) VALUES ($1, 'rb', 'enterprise', 'active')
		ON CONFLICT (id) DO NOTHING`, tenantID)
	mustExecReadModel(t, pool, `
		INSERT INTO users(id, tenant_id, username, role, status)
		VALUES ($1, $2, 'rb_user', 'developer', 'active')
		ON CONFLICT (id) DO NOTHING`, userID, tenantID)
	mustExecReadModel(t, pool, `
		INSERT INTO billing_wallets(id, tenant_id, user_id, currency, balance_micros, reserved_micros, created_at)
		VALUES ($1, $2, $3, 'CNY', $5, $6, $4)
		ON CONFLICT (id) DO NOTHING`, walletID, tenantID, userID, walletCreatedAt, balanceMicros, reservedMicros)
}

// insertLedgerEntry writes one append-only ledger row with an explicit
// created_at so period/boundary placement is deterministic.
func insertLedgerEntry(t *testing.T, pool *pgxpool.Pool, id, tenantID, walletID, eventType string, balanceDelta, reservedDelta, balanceAfter, reservedAfter int64, createdAt time.Time) {
	t.Helper()
	mustExecReadModel(t, pool, `
		INSERT INTO billing_ledger_entries(id, tenant_id, wallet_id, event_type,
			balance_delta_micros, reserved_delta_micros, balance_after_micros,
			reserved_after_micros, idempotency_key, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id+readModelRunSuffix, tenantID, walletID, eventType, balanceDelta, reservedDelta,
		balanceAfter, reservedAfter, id+readModelRunSuffix+"-idem", createdAt)
}

// findWallet picks one wallet out of a period result set.
func findWallet(t *testing.T, items []WalletReconciliationPeriod, walletID string) WalletReconciliationPeriod {
	t.Helper()
	for _, item := range items {
		if item.WalletID == walletID {
			return item
		}
	}
	t.Fatalf("wallet %s missing from result: %+v", walletID, items)
	return WalletReconciliationPeriod{}
}

// TestReconciliationPeriodIdentity pins the honest shape of a fully consistent
// ledger: the period deltas, event counts and the live in-flight total are
// exact, while every historical boundary is unavailable because created_at
// cannot order wallet states. A consistent ledger must NOT produce a trusted
// flat statement out of that.
func TestReconciliationPeriodIdentity(t *testing.T) {
	repo, pool := newBillingReadModelTestRepo(t)
	ctx := context.Background()
	tid := "rb_test_tenant" + readModelRunSuffix
	userID := "rb_user_1" + readModelRunSuffix
	walletID := "rb_wallet_1" + readModelRunSuffix
	seedWallet(t, pool, tid, userID, walletID, time.Now().UTC().AddDate(0, -2, 0), 7000000, 2000000)

	// Ledger history: reserve +3 reserved, credit 10, settle -2 (releasing
	// the 3 reserved), adjustment -1 (correction), reserve +3, release -1.
	now := time.Now().UTC()
	entries := []struct {
		id, ev    string
		delta     int64
		resDelta  int64
		after     int64
		resAfter  int64
		createdAt time.Time
	}{
		{"rb_e0", "reserve", 0, 3000000, 0, 3000000, now.Add(-96 * time.Hour)},
		{"rb_e1", "credit", 10000000, 0, 10000000, 3000000, now.Add(-72 * time.Hour)},
		{"rb_e2", "settle", -2000000, -3000000, 8000000, 0, now.Add(-48 * time.Hour)},
		{"rb_e3", "adjustment", -1000000, 0, 7000000, 0, now.Add(-24 * time.Hour)},
		{"rb_e4", "reserve", 0, 3000000, 7000000, 3000000, now.Add(-2 * time.Hour)},
		{"rb_e5", "release", 0, -1000000, 7000000, 2000000, now.Add(-1 * time.Hour)},
	}
	for _, e := range entries {
		insertLedgerEntry(t, pool, e.id, tid, walletID, e.ev, e.delta, e.resDelta,
			e.after, e.resAfter, e.createdAt)
	}
	mustExecReadModel(t, pool, `
		INSERT INTO billing_reservations(id, tenant_id, wallet_id, request_id, reserved_micros, status)
		VALUES ($1, $2, $3, $4, 2000000, 'reserved')`,
		"rb_res_1"+readModelRunSuffix, tid, walletID, "rb_req_1"+readModelRunSuffix)

	// Period covers the last 24h.
	start := now.Add(-24 * time.Hour).Truncate(time.Hour)
	end := start.AddDate(0, 1, 0)
	items, err := repo.ReconciliationPeriod(ctx, tid, "", start, end)
	if err != nil {
		t.Fatalf("ReconciliationPeriod: %v", err)
	}
	got := findWallet(t, items, walletID)

	// Period deltas and counts are real facts and stay exact.
	if got.AdjustmentMicros != -1000000 || got.AdjustmentCount != 1 {
		t.Fatalf("adjustment = %d/%d, want -1000000/1", got.AdjustmentMicros, got.AdjustmentCount)
	}
	if got.SettleMicros != 0 || got.SettleCount != 0 {
		t.Fatalf("settle inside period = %d/%d, want 0/0 (settle was before period)", got.SettleMicros, got.SettleCount)
	}
	if got.ReleaseCount != 1 || got.ReserveDeltaMicros != 0 || got.ReserveCount != 1 {
		t.Fatalf("reserve/release inside period wrong: reserve=%d/%d release=%d",
			got.ReserveDeltaMicros, got.ReserveCount, got.ReleaseCount)
	}
	if got.ReserveBalanceAnomalyCount != 0 || got.ReleaseBalanceAnomalyCount != 0 {
		t.Fatalf("clean ledger reported anomalies: reserve=%d release=%d",
			got.ReserveBalanceAnomalyCount, got.ReleaseBalanceAnomalyCount)
	}
	// Live in-flight is a real observation and is never withheld.
	if got.CurrentReserved != 2000000 || got.CurrentReservedCnt != 1 {
		t.Fatalf("live in-flight = %d/%d, want 2000000/1", got.CurrentReserved, got.CurrentReservedCnt)
	}
	// The wallet row's own live state is reported alongside the reservation
	// SUM, as a separate figure. This fixture keeps them consistent.
	if got.CurrentBalance != 7000000 || got.CurrentWalletReserved != 2000000 {
		t.Fatalf("live wallet = balance %d reserved %d, want 7000000/2000000",
			got.CurrentBalance, got.CurrentWalletReserved)
	}
	if got.Currency != "CNY" {
		t.Fatalf("currency = %s, want CNY", got.Currency)
	}

	// Every historical boundary is unverifiable: created_at is the
	// transaction-start timestamp and cannot prove wallet-lock order.
	if got.OpeningAvailable || got.OpeningBasis != "boundary_order_unverifiable" {
		t.Fatalf("opening = %d (%s, avail=%v), want unavailable (boundary_order_unverifiable)",
			got.OpeningBalance, got.OpeningBasis, got.OpeningAvailable)
	}
	if got.ClosingAvailable || got.ClosingBasis != "boundary_order_unverifiable" {
		t.Fatalf("closing = %d (%s, avail=%v), want unavailable (boundary_order_unverifiable)",
			got.ClosingBalance, got.ClosingBasis, got.ClosingAvailable)
	}
	if got.PeriodEndReservedAvailable || got.PeriodEndReservedBasis != "boundary_order_unverifiable" {
		t.Fatalf("period-end reserved = %d (%s, avail=%v), want unavailable (boundary_order_unverifiable)",
			got.PeriodEndReserved, got.PeriodEndReservedBasis, got.PeriodEndReservedAvailable)
	}
	if got.IdentityAvailable {
		t.Fatalf("identity must stay unavailable without provable boundaries")
	}

	// Currency filter selects wallets by currency; a currency with no wallets
	// yields no rows at all (unknown is never reported as zero).
	cnyOnly, err := repo.ReconciliationPeriod(ctx, tid, "CNY", start, end)
	if err != nil || len(cnyOnly) != 1 {
		t.Fatalf("CNY filter items = %d err=%v, want 1", len(cnyOnly), err)
	}
	usd, err := repo.ReconciliationPeriod(ctx, tid, "USD", start, end)
	if err != nil || len(usd) != 0 {
		t.Fatalf("USD filter items = %d err=%v, want 0 (unknown is not zero)", len(usd), err)
	}
}

// TestReconciliationPeriodReversedAdjacentDeltaUnknown is the core negative
// sample for the withdrawn heuristics. Two adjacent entries carry +5M and -5M
// balance deltas and their wallet-lock order is the reverse of their created_at
// order, which is exactly what lock contention on the same wallet produces:
// created_at is taken when the transaction starts, the wallet row lock is
// acquired later inside it.
//
// The physical history is e2 then e1: the wallet carried 5M, e2 settled 5M
// (5M -> 0), e1 credited 5M (0 -> 5M). The live wallet balance is therefore
// 5M. Both entries sit inside the period, so nothing precedes the opening
// boundary, and that is precisely where the withdrawn "first entry satisfies
// balance_after == balance_delta, therefore the wallet started at zero"
// inference fabricates a flat statement: sorting by created_at yields e1
// first, and e1.after == e1.delta (5M == 5M), so a zero opening is invented
// for a wallet that actually carried 5M. The true opening is 5M.
//
// The other two withdrawn heuristics cannot order wallet states either — they
// only fit numbers, which an adjacent +delta/-delta pair satisfies under
// either order — so all three are gone rather than tuned. What remains exact
// is what does not depend on order: the per-event deltas and counts, and the
// live in-flight total.
func TestReconciliationPeriodReversedAdjacentDeltaUnknown(t *testing.T) {
	repo, pool := newBillingReadModelTestRepo(t)
	ctx := context.Background()
	tid := "rb_test_tenant_rev" + readModelRunSuffix
	userID := "rb_user_rev" + readModelRunSuffix
	walletID := "rb_wallet_rev" + readModelRunSuffix
	createdLongAgo := time.Now().UTC().AddDate(0, -3, 0)
	// Live state 5M matches the physical order e2 then e1; created_at claims
	// the opposite order (e1 first).
	seedWallet(t, pool, tid, userID, walletID, createdLongAgo, 5000000, 0)
	now := time.Now().UTC()
	insertLedgerEntry(t, pool, "rb_rev1", tid, walletID, "adjustment",
		5000000, 0, 5000000, 0, now.Add(-24*time.Hour))
	insertLedgerEntry(t, pool, "rb_rev2", tid, walletID, "adjustment",
		-5000000, 0, 0, 0, now.Add(-12*time.Hour))

	start := now.Add(-48 * time.Hour).Truncate(time.Hour)
	items, err := repo.ReconciliationPeriod(ctx, tid, "", start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("ReconciliationPeriod: %v", err)
	}
	got := findWallet(t, items, walletID)

	// Deltas and counts are real regardless of the order ambiguity: both
	// entries are inside the period and they net to zero.
	if got.AdjustmentMicros != 0 || got.AdjustmentCount != 2 {
		t.Fatalf("adjustment = %d/%d, want 0/2 (both entries in period)", got.AdjustmentMicros, got.AdjustmentCount)
	}
	// The opening must NOT be reported as a zero: the wallet carried 5M, and
	// only the withdrawn inference claimed otherwise.
	if got.OpeningAvailable || got.OpeningBasis != "unknown" {
		t.Fatalf("opening = %d (%s, avail=%v), want unavailable (no prior ledger evidence, reversed adjacent deltas)",
			got.OpeningBalance, got.OpeningBasis, got.OpeningAvailable)
	}
	// The closing boundary has ledger history and cannot be ordered.
	if got.ClosingAvailable || got.ClosingBasis != "boundary_order_unverifiable" {
		t.Fatalf("closing = %d (%s, avail=%v), want unavailable (boundary_order_unverifiable, reversed adjacent deltas)",
			got.ClosingBalance, got.ClosingBasis, got.ClosingAvailable)
	}
	if got.PeriodEndReservedAvailable {
		t.Fatalf("period-end reserved must stay unavailable, got %d (%s)",
			got.PeriodEndReserved, got.PeriodEndReservedBasis)
	}
	if got.IdentityAvailable {
		t.Fatalf("identity must stay unavailable for a reversed adjacent +/-5M pair")
	}
}

// TestReconciliationPeriodEndReservedBases pins the period-end snapshot
// semantics: structural post-period creation, and unknown when the wallet
// existed but nothing in the ledger speaks for the boundary.
func TestReconciliationPeriodEndReservedBases(t *testing.T) {
	repo, pool := newBillingReadModelTestRepo(t)
	ctx := context.Background()
	tid := "rb_test_tenant3" + readModelRunSuffix
	userID := "rb_user_3" + readModelRunSuffix
	walletCreatedAfterEnd := "rb_wallet_after_end" + readModelRunSuffix
	walletNoEvidence := "rb_wallet_no_evidence" + readModelRunSuffix
	createdLongAgo := time.Now().UTC().AddDate(0, -3, 0)
	seedWallet(t, pool, tid, userID, walletCreatedAfterEnd, time.Now().UTC().AddDate(0, 0, -1), 0, 0)
	mustExecReadModel(t, pool, `
		INSERT INTO users(id, tenant_id, username, role, status)
		VALUES ($1, $2, 'rb_user4', 'developer', 'active')
		ON CONFLICT (id) DO NOTHING`, userID+"4", tid)
	mustExecReadModel(t, pool, `
		INSERT INTO billing_wallets(id, tenant_id, user_id, currency, balance_micros, reserved_micros, created_at)
		VALUES ($1, $2, $3, 'CNY', 0, 0, $4)
		ON CONFLICT (id) DO NOTHING`, walletNoEvidence, tid, userID+"4", createdLongAgo)

	// Period ends 48h ago: wallet_after_end was created 24h before now, i.e.
	// after that boundary, so its structural reserved total was 0.
	start := time.Now().UTC().AddDate(0, 0, -3)
	end := time.Now().UTC().AddDate(0, 0, -2)
	items, err := repo.ReconciliationPeriod(ctx, tid, "", start, end)
	if err != nil {
		t.Fatalf("ReconciliationPeriod: %v", err)
	}
	for _, item := range items {
		switch item.WalletID {
		case walletCreatedAfterEnd:
			if !item.PeriodEndReservedAvailable || item.PeriodEndReserved != 0 ||
				item.PeriodEndReservedBasis != "wallet_created_after_period_end" {
				t.Fatalf("post-period wallet reserved = %d (%s, avail=%v)",
					item.PeriodEndReserved, item.PeriodEndReservedBasis, item.PeriodEndReservedAvailable)
			}
			if !item.OpeningAvailable || item.OpeningBalance != 0 ||
				item.OpeningBasis != "wallet_created_after_period_start" {
				t.Fatalf("post-period wallet opening = %d (%s, avail=%v)",
					item.OpeningBalance, item.OpeningBasis, item.OpeningAvailable)
			}
			// With both boundaries structurally provable the carryover and the
			// identity are sound, and the period had no entries at all.
			if !item.ClosingAvailable || item.ClosingBasis != "opening_carryover" || item.ClosingBalance != 0 {
				t.Fatalf("post-period wallet closing = %d (%s, avail=%v)",
					item.ClosingBalance, item.ClosingBasis, item.ClosingAvailable)
			}
			if !item.IdentityAvailable || item.ClosingDiff != 0 {
				t.Fatalf("post-period wallet identity = avail=%v diff=%d, want available/0",
					item.IdentityAvailable, item.ClosingDiff)
			}
		case walletNoEvidence:
			if item.PeriodEndReservedAvailable || item.PeriodEndReservedBasis != "unknown" {
				t.Fatalf("no-evidence wallet reserved must be unknown, got %d (%s, avail=%v)",
					item.PeriodEndReserved, item.PeriodEndReservedBasis, item.PeriodEndReservedAvailable)
			}
			if item.OpeningAvailable || item.OpeningBasis != "unknown" {
				t.Fatalf("no-evidence wallet opening must be unknown, got %d (%s, avail=%v)",
					item.OpeningBalance, item.OpeningBasis, item.OpeningAvailable)
			}
			if item.IdentityAvailable {
				t.Fatalf("identity must be unavailable when the opening is unknown")
			}
		}
	}
}

// TestReconciliationPeriodOpeningUnknown pins the negative sample: a wallet
// that predates the period whose only ledger entry implies a non-zero prior
// balance must report an unknown opening, not a fabricated zero, and the
// closing identity must be marked unavailable.
func TestReconciliationPeriodOpeningUnknown(t *testing.T) {
	repo, pool := newBillingReadModelTestRepo(t)
	ctx := context.Background()
	tid := "rb_test_tenant4" + readModelRunSuffix
	userID := "rb_user_5" + readModelRunSuffix
	walletID := "rb_wallet_5" + readModelRunSuffix
	createdLongAgo := time.Now().UTC().AddDate(0, -3, 0)
	seedWallet(t, pool, tid, userID, walletID, createdLongAgo, 0, 0)
	// Entry inside the period: delta 1M but balance_after 1.5M — the wallet
	// carried 0.5M before this entry, so a zero opening would be a lie.
	now := time.Now().UTC()
	insertLedgerEntry(t, pool, "rb_e_bad", tid, walletID, "adjustment",
		1000000, 0, 1500000, 0, now.Add(-time.Hour))
	start := now.Add(-24 * time.Hour).Truncate(time.Hour)
	items, err := repo.ReconciliationPeriod(ctx, tid, "", start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("ReconciliationPeriod: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	got := items[0]
	if got.OpeningAvailable || got.OpeningBasis != "unknown" {
		t.Fatalf("opening = %d (%s, avail=%v), want unknown/unavailable",
			got.OpeningBalance, got.OpeningBasis, got.OpeningAvailable)
	}
	if got.IdentityAvailable {
		t.Fatalf("identity must be unavailable when the opening is unknown")
	}
	// The delta itself is still a real fact.
	if got.AdjustmentMicros != 1000000 || got.AdjustmentCount != 1 {
		t.Fatalf("adjustment = %d/%d, want 1000000/1", got.AdjustmentMicros, got.AdjustmentCount)
	}
}

// TestAuditPipelineAndCompensationStats sanity-checks the health evidence
// queries: non-negative counts and no errors on the dedicated test database.
func TestAuditPipelineAndCompensationStats(t *testing.T) {
	repo, _ := newBillingReadModelTestRepo(t)
	ctx := context.Background()
	stats, err := repo.AuditPipelineStats(ctx, 24)
	if err != nil {
		t.Fatalf("AuditPipelineStats: %v", err)
	}
	if stats.RequestCount < 0 || stats.PendingCount < 0 {
		t.Fatalf("negative counts: %+v", stats)
	}
	comp, err := repo.BillingCompensationStats(ctx, 15)
	if err != nil {
		t.Fatalf("BillingCompensationStats: %v", err)
	}
	if comp.StaleReservedCount < 0 || comp.ActiveLeaseCount < 0 {
		t.Fatalf("negative counts: %+v", comp)
	}
	faults, err := repo.SemanticFaultEventCount(ctx, 24)
	if err != nil {
		t.Fatalf("SemanticFaultEventCount: %v", err)
	}
	if faults < 0 {
		t.Fatalf("negative fault count: %d", faults)
	}
}

// TestReconciliationPeriodConsistentSnapshot is the concurrency negative
// sample: a concurrent credit committed while the REPEATABLE READ READ ONLY
// snapshot transaction is open must NOT leak into the aggregation. Without
// the snapshot, the late insert would land between the reads and change the
// period totals the read model reports as exact.
func TestReconciliationPeriodConsistentSnapshot(t *testing.T) {
	repo, pool := newBillingReadModelTestRepo(t)
	ctx := context.Background()
	tid := "rb_test_tenant6" + readModelRunSuffix
	userID := "rb_user_7" + readModelRunSuffix
	walletID := "rb_wallet_7" + readModelRunSuffix
	createdLongAgo := time.Now().UTC().AddDate(0, -3, 0)
	seedWallet(t, pool, tid, userID, walletID, createdLongAgo, 0, 0)
	now := time.Now().UTC()
	insertLedgerEntry(t, pool, "rb_e_snap1", tid, walletID, "credit",
		1000000, 0, 1000000, 0, now.Add(-time.Hour))
	// Keep the live wallet state consistent with the ledger (the store always
	// updates the wallet row in the same transaction as the ledger entry).
	mustExecReadModel(t, pool, `UPDATE billing_wallets SET balance_micros = 1000000 WHERE id = $1 AND tenant_id = $2`, walletID, tid)
	start := now.Add(-24 * time.Hour).Truncate(time.Hour)
	end := start.AddDate(0, 1, 0)

	// Open the same snapshot the public API uses and read the first stage.
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatalf("begin snapshot tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	before, err := reconciliationPeriodTx(ctx, tx, tid, "", start, end)
	if err != nil {
		t.Fatalf("snapshot read: %v", err)
	}

	// Concurrent writer: another connection commits a fresh credit into the
	// same period while the snapshot transaction is still open (the store
	// also moves the wallet balance in the same transaction).
	conc, err := pgxpool.New(ctx, os.Getenv("BILLING_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("connect concurrent pool: %v", err)
	}
	t.Cleanup(conc.Close)
	if _, err := conc.Exec(ctx, `
		INSERT INTO billing_ledger_entries(id, tenant_id, wallet_id, event_type,
			balance_delta_micros, reserved_delta_micros, balance_after_micros,
			reserved_after_micros, idempotency_key, created_at)
		VALUES ($1, $2, $3, 'credit', 5000000, 0, 6000000, 0, $4, $5)`,
		"rb_e_snap2"+readModelRunSuffix, tid, walletID,
		"rb_e_snap2"+readModelRunSuffix+"-idem", now.Add(-30*time.Minute)); err != nil {
		t.Fatalf("concurrent insert: %v", err)
	}
	if _, err := conc.Exec(ctx, `UPDATE billing_wallets SET balance_micros = 6000000 WHERE id = $1 AND tenant_id = $2`, walletID, tid); err != nil {
		t.Fatalf("concurrent wallet update: %v", err)
	}

	// The snapshot transaction must still see the pre-insert state.
	after, err := reconciliationPeriodTx(ctx, tx, tid, "", start, end)
	if err != nil {
		t.Fatalf("snapshot re-read: %v", err)
	}
	if len(before) != 1 || len(after) != 1 {
		t.Fatalf("items = %d/%d, want 1/1", len(before), len(after))
	}
	if after[0].CreditMicros != before[0].CreditMicros ||
		after[0].CreditCount != before[0].CreditCount ||
		after[0].ClosingBasis != before[0].ClosingBasis ||
		after[0].OpeningBasis != before[0].OpeningBasis {
		t.Fatalf("concurrent insert leaked into snapshot: before=%+v after=%+v", before[0], after[0])
	}
	if before[0].CreditMicros != 1000000 {
		t.Fatalf("snapshot credit = %d, want 1000000 (concurrent 5M credit excluded)", before[0].CreditMicros)
	}
	// Outside the snapshot, the concurrent credit IS visible: proving the
	// insert really happened and only the isolation hid it.
	live, err := repo.ReconciliationPeriod(ctx, tid, "", start, end)
	if err != nil {
		t.Fatalf("live read: %v", err)
	}
	if len(live) != 1 || live[0].CreditMicros != 6000000 {
		t.Fatalf("live credit = %+v, want 6000000 (both credits visible outside snapshot)", live)
	}
}

// TestReconciliationPeriodAmbiguousBoundary pins the same-timestamp verdict:
// two entries sharing created_at (a batch true-up writes several entries in
// one transaction, and created_at is the DEFAULT NOW() transaction
// timestamp) make "latest balance_after" an arbitrary pick, so the boundary
// is unavailable.
func TestReconciliationPeriodAmbiguousBoundary(t *testing.T) {
	repo, pool := newBillingReadModelTestRepo(t)
	ctx := context.Background()
	tid := "rb_test_tenant7" + readModelRunSuffix
	userID := "rb_user_8" + readModelRunSuffix
	walletID := "rb_wallet_8" + readModelRunSuffix
	createdLongAgo := time.Now().UTC().AddDate(0, -3, 0)
	seedWallet(t, pool, tid, userID, walletID, createdLongAgo, 0, 0)
	now := time.Now().UTC()
	sameTs := now.Add(-time.Hour).Truncate(time.Second)
	// Two same-timestamp entries with different balance_after values, as a
	// single-transaction batch true-up would produce.
	for i, after := range []int64{2000000, 3000000} {
		insertLedgerEntry(t, pool, fmt.Sprintf("rb_e_tie%d", i), tid, walletID,
			"adjustment", 1000000, 0, after, 0, sameTs)
	}
	start := now.Add(-24 * time.Hour).Truncate(time.Hour)
	items, err := repo.ReconciliationPeriod(ctx, tid, "", start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("ReconciliationPeriod: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	got := items[0]
	if got.ClosingAvailable || got.ClosingBasis != "boundary_order_unverifiable" {
		t.Fatalf("closing = %d (%s, avail=%v), want unavailable (boundary_order_unverifiable, same-timestamp tie)",
			got.ClosingBalance, got.ClosingBasis, got.ClosingAvailable)
	}
	if got.IdentityAvailable {
		t.Fatalf("identity must be unavailable when the closing boundary is ambiguous")
	}
}

// TestReconciliationPeriodUnsupportedEventType pins event-type coverage: a
// balance-bearing event type outside the contract set must surface as
// other_delta and its count/delta must stay exact, never vanish silently.
//
// This test runs against a SEPARATE sacrificial database: it must drop the
// table CHECKs and can only restore them NOT VALID (the foreign row is
// append-only and can never satisfy them again), which would permanently
// leave the main test database's constraints at convalidated=false.
func TestReconciliationPeriodUnsupportedEventType(t *testing.T) {
	repo, pool := newBillingUnsafeTestRepo(t)
	ctx := context.Background()
	tid := "rb_test_tenant8" + readModelRunSuffix
	userID := "rb_user_9" + readModelRunSuffix
	walletID := "rb_wallet_9" + readModelRunSuffix
	createdLongAgo := time.Now().UTC().AddDate(0, -3, 0)
	seedWallet(t, pool, tid, userID, walletID, createdLongAgo, 4000000, 0)
	now := time.Now().UTC()
	// A hypothetical future event type carrying a balance delta. The schema
	// CHECK restricts event_type to the contract set, so the test temporarily
	// drops it (sacrificial database) and restores it NOT VALID on cleanup:
	// the foreign row cannot be deleted (append-only), and NOT VALID keeps
	// enforcing both constraints for every future row while tolerating that
	// single pre-existing fixture row.
	mustExecReadModel(t, pool, `ALTER TABLE billing_ledger_entries DROP CONSTRAINT IF EXISTS ck_billing_ledger_event`)
	mustExecReadModel(t, pool, `ALTER TABLE billing_ledger_entries DROP CONSTRAINT IF EXISTS ck_billing_ledger_delta_shape`)
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `ALTER TABLE billing_ledger_entries DROP CONSTRAINT IF EXISTS ck_billing_ledger_event; ALTER TABLE billing_ledger_entries ADD CONSTRAINT ck_billing_ledger_event CHECK (event_type IN ('credit', 'adjustment', 'reserve', 'settle', 'release', 'refund')) NOT VALID`); err != nil {
			t.Errorf("restore event-type constraint: %v", err)
		}
		if _, err := pool.Exec(ctx, `ALTER TABLE billing_ledger_entries DROP CONSTRAINT IF EXISTS ck_billing_ledger_delta_shape; ALTER TABLE billing_ledger_entries ADD CONSTRAINT ck_billing_ledger_delta_shape CHECK (
			(event_type IN ('credit', 'refund') AND balance_delta_micros > 0 AND reserved_delta_micros = 0) OR
			(event_type = 'adjustment' AND balance_delta_micros <> 0 AND reserved_delta_micros = 0) OR
			(event_type = 'reserve' AND balance_delta_micros = 0 AND reserved_delta_micros > 0) OR
			(event_type = 'settle' AND balance_delta_micros <= 0 AND reserved_delta_micros < 0) OR
			(event_type = 'release' AND balance_delta_micros = 0 AND reserved_delta_micros < 0)) NOT VALID`); err != nil {
			t.Errorf("restore delta-shape constraint: %v", err)
		}
	})
	mustExecReadModel(t, pool, `
		INSERT INTO billing_ledger_entries(id, tenant_id, wallet_id, event_type,
			balance_delta_micros, reserved_delta_micros, balance_after_micros,
			reserved_after_micros, idempotency_key, created_at)
		VALUES ($1, $2, $3, 'migration_backfill', 4000000, 0, 4000000, 0, $4, $5)`,
		"rb_e_other"+readModelRunSuffix, tid, walletID,
		"rb_e_other"+readModelRunSuffix+"-idem", now.Add(-2*time.Hour))
	start := now.Add(-24 * time.Hour).Truncate(time.Hour)
	items, err := repo.ReconciliationPeriod(ctx, tid, "", start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("ReconciliationPeriod: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	got := items[0]
	if got.OtherDeltaMicros != 4000000 || got.OtherEventCount != 1 || len(got.OtherEventTypes) != 1 {
		t.Fatalf("other coverage = %+v, want delta 4000000 count 1", got.OtherEventTypes)
	}
	// The delta is exact, but no closing boundary is provable, so no flat
	// statement is issued.
	if got.IdentityAvailable {
		t.Fatalf("identity must stay unavailable without provable boundaries")
	}
	if got.ClosingAvailable {
		t.Fatalf("closing must stay unavailable, got %d (%s)", got.ClosingBalance, got.ClosingBasis)
	}
}

// TestReconciliationPeriodBrokenDatabasePropagates verifies a real query
// failure is propagated as an error instead of being disguised as a normal
// "unknown" boundary: the handler turns it into a stable reason code, so a
// database outage can never read like a clean statement.
func TestReconciliationPeriodBrokenDatabasePropagates(t *testing.T) {
	repo, pool := newBillingReadModelTestRepo(t)
	pool.Close()
	now := time.Now().UTC()
	start := now.Add(-24 * time.Hour).Truncate(time.Hour)
	if _, err := repo.ReconciliationPeriod(context.Background(), "rb_broken"+readModelRunSuffix, "", start, start.AddDate(0, 1, 0)); err == nil {
		t.Fatalf("ReconciliationPeriod on a closed pool must return an error, not unknown boundaries")
	}
}

// TestReconciliationPeriodLiveWalletVsReservationSum pins that the wallet
// row's live state and the SUM over live billing_reservations rows are two
// independent facts. The store keeps them equal (every reserve/release updates
// the wallet column in the same transaction), so a divergence can only mean the
// two sources really disagree — which must surface as two distinct numbers, not
// be collapsed into one. Neither may be substituted for the other, and neither
// may back-fill the unavailable historical period-end snapshot.
func TestReconciliationPeriodLiveWalletVsReservationSum(t *testing.T) {
	repo, pool := newBillingReadModelTestRepo(t)
	ctx := context.Background()
	tid := "rb_test_tenant_live" + readModelRunSuffix
	userID := "rb_user_live" + readModelRunSuffix
	walletID := "rb_wallet_live" + readModelRunSuffix
	createdLongAgo := time.Now().UTC().AddDate(0, -3, 0)
	// Wallet row says 1 reserved...
	seedWallet(t, pool, tid, userID, walletID, createdLongAgo, 4000000, 1000000)
	// ...while the live reservation rows sum to 3.5. The read model must report
	// both, and must not reconcile them into one number.
	mustExecReadModel(t, pool, `
		INSERT INTO billing_reservations(id, tenant_id, wallet_id, request_id, reserved_micros, status)
		VALUES ($1, $2, $3, $4, 3500000, 'reserved')`,
		"rb_res_live"+readModelRunSuffix, tid, walletID, "rb_req_live"+readModelRunSuffix)
	now := time.Now().UTC()
	insertLedgerEntry(t, pool, "rb_live1", tid, walletID, "adjustment",
		1000000, 0, 1000000, 0, now.Add(-2*time.Hour))

	start := now.Add(-24 * time.Hour).Truncate(time.Hour)
	items, err := repo.ReconciliationPeriod(ctx, tid, "", start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("ReconciliationPeriod: %v", err)
	}
	got := findWallet(t, items, walletID)

	// The wallet row's own columns, as read.
	if got.CurrentBalance != 4000000 || got.CurrentWalletReserved != 1000000 {
		t.Fatalf("live wallet = balance %d reserved %d, want 4000000/1000000",
			got.CurrentBalance, got.CurrentWalletReserved)
	}
	// The reservation SUM, as read. Distinct from the wallet column and not
	// overwritten by it.
	if got.CurrentReserved != 3500000 || got.CurrentReservedCnt != 1 {
		t.Fatalf("reservation sum = %d/%d, want 3500000/1", got.CurrentReserved, got.CurrentReservedCnt)
	}
	if got.CurrentWalletReserved == got.CurrentReserved {
		t.Fatalf("fixture must exercise divergence, but both figures are %d", got.CurrentReserved)
	}
	// The divergence must not leak into the historical period-end snapshot:
	// that boundary has no provable order, so it stays unavailable rather than
	// being back-filled from either live figure.
	if got.PeriodEndReservedAvailable || got.PeriodEndReservedBasis != "boundary_order_unverifiable" {
		t.Fatalf("period-end reserved = %d (%s, avail=%v), want unavailable (live figures must not back-fill it)",
			got.PeriodEndReserved, got.PeriodEndReservedBasis, got.PeriodEndReservedAvailable)
	}
	// The unknown event-type coverage of this fixture is empty, and the
	// caller must still be able to observe that (empty, not absent).
	if got.OtherDeltaMicros != 0 || got.OtherEventCount != 0 {
		t.Fatalf("other = %d/%d, want 0/0", got.OtherDeltaMicros, got.OtherEventCount)
	}
}

// TestOwnerWalletsEmptyUser verifies an empty user yields no rows and no
// error (callers must treat this as "no wallet evidence", not zero).
func TestOwnerWalletsEmptyUser(t *testing.T) {
	repo, _ := newBillingReadModelTestRepo(t)
	wallets, err := repo.OwnerWallets(context.Background(), "rb_test_tenant"+readModelRunSuffix, "")
	if err != nil || wallets != nil {
		t.Fatalf("OwnerWallets(empty user) = %v, %v; want nil, nil", wallets, err)
	}
}
