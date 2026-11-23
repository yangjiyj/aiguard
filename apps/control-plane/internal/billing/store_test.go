package billing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupBillingStoreTest(t *testing.T) (*Store, *pgxpool.Pool, string, string) {
	t.Helper()
	if os.Getenv("JJD_PROVIDER_SECRET_KEY") == "" {
		t.Setenv("JJD_PROVIDER_SECRET_KEY", "fixture-redemption-encryption-secret")
	}
	databaseURL := os.Getenv("BILLING_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("BILLING_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect billing test database: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "tenant_bill_" + suffix
	userID := "user_bill_" + suffix
	if _, err := db.Exec(ctx, `
		INSERT INTO tenants (id, name, edition, status,is_test)
		VALUES ($1, $1, 'enterprise', 'active',TRUE)
	`, tenantID); err != nil {
		db.Close()
		t.Fatalf("insert billing tenant fixture: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		VALUES ($2, $1, $2, $3, 'x', 'developer', 'active')
	`, tenantID, userID, userID+"@test.invalid"); err != nil {
		db.Close()
		t.Fatalf("insert billing user fixture: %v", err)
	}
	t.Cleanup(func() {
		for _, query := range []string{
			"DELETE FROM request_logs WHERE tenant_id=$1",
			"DELETE FROM billing_employee_reservations WHERE tenant_id=$1",
			"UPDATE billing_reservations SET status='released',settled_micros=NULL,finalized_at=NOW() WHERE tenant_id=$1 AND status='reserved'",
			"UPDATE tenants SET status='disabled' WHERE id=$1",
		} {
			if _, err := db.Exec(context.Background(), query, tenantID); err != nil {
				t.Errorf("billing fixture cleanup: %v", err)
			}
		}
		db.Close()
	})
	return NewStore(db), db, tenantID, userID
}

func TestStoreCreditReserveSettleIsIdempotent(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	sameWallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil || sameWallet.ID != wallet.ID {
		t.Fatalf("ensure wallet idempotency: wallet=%#v err=%v", sameWallet, err)
	}

	wallet, err = store.Credit(ctx, tenantID, wallet.ID, "admin-credit-1", 10_000_000, "admin-a")
	if err != nil {
		t.Fatalf("credit: %v", err)
	}
	wallet, err = store.Credit(ctx, tenantID, wallet.ID, "admin-credit-1", 10_000_000, "admin-a")
	if err != nil || wallet.BalanceMicros != 10_000_000 {
		t.Fatalf("idempotent credit: wallet=%#v err=%v", wallet, err)
	}
	if _, err := store.Credit(ctx, tenantID, wallet.ID, "admin-credit-1", 1, "admin-a"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("mismatched credit error = %v, want ErrIdempotencyConflict", err)
	}

	reservation, wallet, err := store.Reserve(ctx, tenantID, wallet.ID, "req-billing-1", 3_000_000)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	sameReservation, wallet, err := store.Reserve(ctx, tenantID, wallet.ID, "req-billing-1", 3_000_000)
	if err != nil || sameReservation.ID != reservation.ID || wallet.ReservedMicros != 3_000_000 {
		t.Fatalf("idempotent reserve: reservation=%#v wallet=%#v err=%v", sameReservation, wallet, err)
	}

	reservation, wallet, err = store.Settle(ctx, tenantID, "req-billing-1", 3_500_000)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if reservation.Status != ReservationSettled || wallet.BalanceMicros != 6_500_000 || wallet.ReservedMicros != 0 {
		t.Fatalf("settled state: reservation=%#v wallet=%#v", reservation, wallet)
	}
	sameReservation, wallet, err = store.Settle(ctx, tenantID, "req-billing-1", 3_500_000)
	if err != nil || sameReservation.ID != reservation.ID || wallet.BalanceMicros != 6_500_000 {
		t.Fatalf("idempotent settlement: reservation=%#v wallet=%#v err=%v", sameReservation, wallet, err)
	}
	if _, _, err := store.Settle(ctx, tenantID, "req-billing-1", 3_500_001); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("mismatched settlement error = %v, want ErrIdempotencyConflict", err)
	}

	var ledgerCount int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_ledger_entries WHERE tenant_id = $1`, tenantID).Scan(&ledgerCount); err != nil {
		t.Fatalf("count ledger: %v", err)
	}
	if ledgerCount != 3 {
		t.Fatalf("ledger count = %d, want 3", ledgerCount)
	}
	if _, err := db.Exec(ctx, `
		UPDATE billing_ledger_entries SET balance_after_micros = 0
		WHERE tenant_id = $1
	`, tenantID); err == nil {
		t.Fatal("append-only ledger unexpectedly accepted an update")
	}
}

func TestStoreEnforcesCustomerRPMAndConcurrencyLimits(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "request-limit-credit", 100, "admin-a"); err != nil {
		t.Fatalf("credit wallet: %v", err)
	}

	limits, err := store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{RPMLimit: 1})
	if err != nil || limits.RPMLimit != 1 {
		t.Fatalf("set rpm limit: limits=%#v err=%v", limits, err)
	}
	first, _, err := store.Reserve(ctx, tenantID, wallet.ID, "req-rpm-1", 1)
	if err != nil {
		t.Fatalf("first rpm reservation: %v", err)
	}
	same, _, err := store.Reserve(ctx, tenantID, wallet.ID, "req-rpm-1", 1)
	if err != nil || same.ID != first.ID {
		t.Fatalf("idempotent rpm reservation: reservation=%#v err=%v", same, err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-rpm-2", 1); !errors.Is(err, ErrCustomerRPMLimitExceeded) {
		t.Fatalf("second rpm reservation error = %v, want ErrCustomerRPMLimitExceeded", err)
	}
	if _, _, err = store.Release(ctx, tenantID, "req-rpm-1"); err != nil {
		t.Fatalf("release rpm reservation: %v", err)
	}

	limits, err = store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{ConcurrencyLimit: 1})
	if err != nil || limits.ConcurrencyLimit != 1 {
		t.Fatalf("set concurrency limit: limits=%#v err=%v", limits, err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-concurrency-1", 1); err != nil {
		t.Fatalf("first concurrency reservation: %v", err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-concurrency-2", 1); !errors.Is(err, ErrCustomerConcurrencyLimitExceeded) {
		t.Fatalf("second concurrency reservation error = %v, want ErrCustomerConcurrencyLimitExceeded", err)
	}
	if _, _, err = store.Release(ctx, tenantID, "req-concurrency-1"); err != nil {
		t.Fatalf("release concurrency reservation: %v", err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-concurrency-2", 1); err != nil {
		t.Fatalf("concurrency slot must recover after release: %v", err)
	}

	summary, err := store.GetCustomerLimitSummary(ctx, tenantID, userID, time.Now())
	if err != nil || summary.RPMLimit != 0 || summary.ConcurrencyLimit != 1 {
		t.Fatalf("request limits summary=%#v err=%v", summary, err)
	}
}

func TestStoreExpiredExecutionLeaseDoesNotHoldConcurrencySlot(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "lease-expiry-credit", 100, "admin-a"); err != nil {
		t.Fatalf("credit wallet: %v", err)
	}
	if _, err = store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{ConcurrencyLimit: 1}); err != nil {
		t.Fatalf("set limits: %v", err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-stale-financial-reservation", 1); err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	if _, err = db.Exec(ctx, `
		UPDATE billing_request_leases
		SET acquired_at=NOW()-INTERVAL '2 hours', expires_at=NOW()-INTERVAL '1 second'
		WHERE tenant_id=$1 AND request_id=$2
	`, tenantID, "req-stale-financial-reservation"); err != nil {
		t.Fatalf("expire execution lease: %v", err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-after-expired-lease", 1); err != nil {
		t.Fatalf("expired execution lease kept concurrency occupied: %v", err)
	}
	var status string
	if err = db.QueryRow(ctx, `SELECT status FROM billing_reservations WHERE tenant_id=$1 AND request_id=$2`, tenantID, "req-stale-financial-reservation").Scan(&status); err != nil || status != ReservationReserved {
		t.Fatalf("financial reservation status=%q err=%v, want reserved", status, err)
	}
}

func TestStoreFinalizationReleasesExecutionLeases(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "lease-finalize-credit", 100, "admin-a"); err != nil {
		t.Fatalf("credit wallet: %v", err)
	}
	if _, err = store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{ConcurrencyLimit: 1}); err != nil {
		t.Fatalf("set limits: %v", err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-lease-release", 1); err != nil {
		t.Fatalf("reserve for release: %v", err)
	}
	if _, _, err = store.Release(ctx, tenantID, "req-lease-release"); err != nil {
		t.Fatalf("release reservation: %v", err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-lease-settle", 1); err != nil {
		t.Fatalf("reserve for settlement: %v", err)
	}
	if _, _, err = store.Settle(ctx, tenantID, "req-lease-settle", 1); err != nil {
		t.Fatalf("settle reservation: %v", err)
	}
	var active int
	if err = db.QueryRow(ctx, `
		SELECT COUNT(*) FROM billing_request_leases
		WHERE tenant_id=$1 AND user_id=$2 AND released_at IS NULL AND expires_at>NOW()
	`, tenantID, userID).Scan(&active); err != nil || active != 0 {
		t.Fatalf("active execution leases=%d err=%v, want 0", active, err)
	}
}

func TestStoreDisablingRequestLimitsDeletesExecutionLeases(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "disable-limits-credit", 100, "admin-a"); err != nil {
		t.Fatalf("credit wallet: %v", err)
	}
	if _, err = store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{ConcurrencyLimit: 1}); err != nil {
		t.Fatalf("set request limit: %v", err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-disable-limits", 1); err != nil {
		t.Fatalf("reserve request: %v", err)
	}
	if _, err = store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{}); err != nil {
		t.Fatalf("disable request limits: %v", err)
	}
	var leases int
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_request_leases WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID).Scan(&leases); err != nil || leases != 0 {
		t.Fatalf("execution leases after disabling limits=%d err=%v, want 0", leases, err)
	}
}

func TestStoreScheduledCleanupPrunesTenantStaleExecutionLeases(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_request_leases
			(tenant_id, user_id, request_id, acquired_at, expires_at, released_at)
		VALUES ($1,$2,$3,NOW()-INTERVAL '2 hours',NOW()-INTERVAL '1 hour',NOW()-INTERVAL '119 minutes')
	`, tenantID, userID, "req-stale-lease"); err != nil {
		t.Fatalf("insert stale lease: %v", err)
	}
	if _, err := store.pruneRequestLeases(ctx, time.Now().UTC()); err != nil {
		t.Fatalf("scheduled request lease cleanup: %v", err)
	}
	var leases int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_request_leases WHERE tenant_id=$1 AND request_id=$2`, tenantID, "req-stale-lease").Scan(&leases); err != nil || leases != 0 {
		t.Fatalf("stale execution leases=%d err=%v, want 0", leases, err)
	}
}

func TestStoreReleasedExecutionLeaseStillCountsWithinRPMWindow(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "recent-release-credit", 100, "admin-a"); err != nil {
		t.Fatalf("credit wallet: %v", err)
	}
	if _, err = store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{RPMLimit: 1}); err != nil {
		t.Fatalf("set rpm limit: %v", err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-recent-release", 1); err != nil {
		t.Fatalf("reserve request: %v", err)
	}
	if _, _, err = store.Release(ctx, tenantID, "req-recent-release"); err != nil {
		t.Fatalf("release request: %v", err)
	}
	if _, err = db.Exec(ctx, `
		UPDATE billing_request_leases
		SET acquired_at=NOW()-INTERVAL '30 seconds', expires_at=NOW()-INTERVAL '1 second'
		WHERE tenant_id=$1 AND request_id=$2
	`, tenantID, "req-recent-release"); err != nil {
		t.Fatalf("age recent released lease: %v", err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-within-rpm-window", 1); !errors.Is(err, ErrCustomerRPMLimitExceeded) {
		t.Fatalf("request inside rpm window error=%v, want ErrCustomerRPMLimitExceeded", err)
	}
}

func TestCustomerRequestLeaseCountsUseBoundedIndexes(t *testing.T) {
	_, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	otherTenantID := tenantID + "_other"
	otherUserID := userID + "_other"
	if _, err := db.Exec(ctx, `
		INSERT INTO tenants (id, name, edition, status)
		VALUES ($1, $1, 'enterprise', 'active')
	`, otherTenantID); err != nil {
		t.Fatalf("insert other active lease tenant: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		VALUES ($2, $1, $2, $3, 'x', 'developer', 'active')
	`, otherTenantID, otherUserID, otherUserID+"@test.invalid"); err != nil {
		t.Fatalf("insert other active lease user: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_request_leases
			(tenant_id, user_id, request_id, acquired_at, expires_at, released_at)
		SELECT $1, $2, 'req-history-' || value,
			$3::timestamptz - INTERVAL '2 hours' - value * INTERVAL '1 second',
			$3::timestamptz - INTERVAL '90 minutes' - value * INTERVAL '1 second',
			$3::timestamptz - INTERVAL '119 minutes' - value * INTERVAL '1 second'
		FROM generate_series(1, 5000) AS value
	`, tenantID, userID, now); err != nil {
		t.Fatalf("insert historical request leases: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_request_leases
			(tenant_id, user_id, request_id, acquired_at, expires_at, released_at)
		VALUES
			($1,$2,'req-recent',$3::timestamptz-INTERVAL '30 seconds',$3::timestamptz+INTERVAL '30 minutes',$3::timestamptz-INTERVAL '29 seconds'),
			($1,$2,'req-active',$3::timestamptz-INTERVAL '2 hours',$3::timestamptz+INTERVAL '30 minutes',NULL)
	`, tenantID, userID, now); err != nil {
		t.Fatalf("insert bounded request leases: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_request_leases
			(tenant_id, user_id, request_id, acquired_at, expires_at)
		SELECT $1, $2, 'req-other-active-' || value,
			$3::timestamptz - INTERVAL '2 hours',
			$3::timestamptz + INTERVAL '30 minutes'
		FROM generate_series(1, 5000) AS value
	`, otherTenantID, otherUserID, now); err != nil {
		t.Fatalf("insert other users active request leases: %v", err)
	}
	if _, err := db.Exec(ctx, `ANALYZE billing_request_leases`); err != nil {
		t.Fatalf("analyze request leases: %v", err)
	}

	var recent, active int64
	if err := db.QueryRow(ctx, customerRequestLeaseCountsSQL,
		tenantID, userID, now.Add(-time.Minute), now).Scan(&recent, &active); err != nil {
		t.Fatalf("count bounded request leases: %v", err)
	}
	if recent != 1 || active != 1 {
		t.Fatalf("bounded request counts=%d/%d, want 1/1", recent, active)
	}

	rows, err := db.Query(ctx, "EXPLAIN (COSTS OFF) "+customerRequestLeaseCountsSQL,
		tenantID, userID, now.Add(-time.Minute), now)
	if err != nil {
		t.Fatalf("explain bounded request lease counts: %v", err)
	}
	defer rows.Close()
	var planLines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan request lease plan: %v", err)
		}
		planLines = append(planLines, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate request lease plan: %v", err)
	}
	plan := strings.Join(planLines, "\n")
	if !strings.Contains(plan, "idx_billing_request_leases_user_acquired") {
		t.Fatalf("request lease plan does not use the bounded RPM index:\n%s", plan)
	}
	if !strings.Contains(plan, "idx_billing_request_leases_user_active") {
		t.Fatalf("request lease plan does not use the employee-scoped active-lease index:\n%s", plan)
	}
	if strings.Contains(plan, "Seq Scan on billing_request_leases") {
		t.Fatalf("request lease plan scans unbounded history:\n%s", plan)
	}
}

func TestStoreRequestLeaseCleanupDrainsMultipleBatches(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	wantDeleted := requestLeaseCleanupBatchSize + 250
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_request_leases
			(tenant_id, user_id, request_id, acquired_at, expires_at, released_at)
		SELECT $1, $2, 'req-cleanup-backlog-' || value,
			$3::timestamptz - INTERVAL '2 hours' - value * INTERVAL '1 second',
			$3::timestamptz - INTERVAL '90 minutes' - value * INTERVAL '1 second',
			$3::timestamptz - INTERVAL '119 minutes' - value * INTERVAL '1 second'
		FROM generate_series(1, $4) AS value
	`, tenantID, userID, now, wantDeleted); err != nil {
		t.Fatalf("insert cleanup backlog: %v", err)
	}
	result, err := store.pruneRequestLeases(ctx, now)
	if err != nil {
		t.Fatalf("drain cleanup backlog: %v", err)
	}
	if result.Deleted < int64(wantDeleted) || result.Batches < 2 || result.Backlog {
		t.Fatalf("cleanup result=%+v, want deleted>=%d batches>=2 backlog=false", result, wantDeleted)
	}
	stats := store.RequestLeaseCleanupStats()
	if stats.DeletedTotal != result.Deleted || stats.Backlog || stats.LastRunUnix == 0 {
		t.Fatalf("cleanup stats=%+v result=%+v", stats, result)
	}
	var remaining int
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*) FROM billing_request_leases
		WHERE tenant_id=$1 AND user_id=$2 AND request_id LIKE 'req-cleanup-backlog-%'
	`, tenantID, userID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("cleanup backlog remaining=%d err=%v, want 0", remaining, err)
	}
}

func TestStoreRequestLeaseCleanupReportsBacklogWhenBudgetExpires(t *testing.T) {
	store, _, _, _ := setupBillingStoreTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := store.pruneRequestLeases(ctx, time.Now().UTC())
	if !errors.Is(err, context.Canceled) || !result.Backlog {
		t.Fatalf("cleanup result=%+v err=%v, want canceled backlog", result, err)
	}
	if stats := store.RequestLeaseCleanupStats(); !stats.Backlog || stats.LastRunUnix == 0 {
		t.Fatalf("cleanup backlog stats=%+v", stats)
	}
}

func TestStoreRequestLeaseCleanupRecordsCommittedBatchWhenNextLockIsBusy(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC()
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_request_leases
			(tenant_id, user_id, request_id, acquired_at, expires_at, released_at)
		SELECT $1, $2, 'req-cleanup-lock-handoff-' || value,
			$3::timestamptz - INTERVAL '24 hours' - value * INTERVAL '1 second',
			$3::timestamptz - INTERVAL '23 hours' - value * INTERVAL '1 second',
			$3::timestamptz - INTERVAL '24 hours' - value * INTERVAL '1 second'
		FROM generate_series(1, $4) AS value
	`, tenantID, userID, now, requestLeaseCleanupBatchSize+1); err != nil {
		t.Fatalf("insert cleanup lock handoff backlog: %v", err)
	}

	const pauseLockKey int64 = 80620260817
	if _, err := db.Exec(ctx, `
		DROP TRIGGER IF EXISTS billing_test_pause_cleanup_batch ON billing_request_leases;
		DROP FUNCTION IF EXISTS billing_test_pause_cleanup_batch();
		CREATE FUNCTION billing_test_pause_cleanup_batch() RETURNS trigger AS $$
		BEGIN
			IF OLD.request_id LIKE 'req-cleanup-lock-handoff-%' THEN
				PERFORM pg_advisory_xact_lock(80620260817);
			END IF;
			RETURN OLD;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER billing_test_pause_cleanup_batch
			BEFORE DELETE ON billing_request_leases
			FOR EACH ROW EXECUTE FUNCTION billing_test_pause_cleanup_batch();
	`); err != nil {
		t.Fatalf("install cleanup pause trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `
			DROP TRIGGER IF EXISTS billing_test_pause_cleanup_batch ON billing_request_leases;
			DROP FUNCTION IF EXISTS billing_test_pause_cleanup_batch();
		`)
	})

	pauseBlocker, err := db.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire cleanup pause connection: %v", err)
	}
	defer pauseBlocker.Release()
	if _, err := pauseBlocker.Exec(ctx, `SELECT pg_advisory_lock($1)`, pauseLockKey); err != nil {
		t.Fatalf("hold cleanup pause lock: %v", err)
	}
	pauseHeld := true
	defer func() {
		if pauseHeld {
			_, _ = pauseBlocker.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, pauseLockKey)
		}
	}()

	type cleanupOutcome struct {
		result RequestLeaseCleanupResult
		err    error
	}
	cleanupDone := make(chan cleanupOutcome, 1)
	go func() {
		result, err := store.pruneRequestLeases(ctx, now)
		cleanupDone <- cleanupOutcome{result: result, err: err}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err := db.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE datname=current_database()
				  AND wait_event_type='Lock'
				  AND wait_event='advisory'
				  AND query LIKE '%DELETE FROM billing_request_leases%'
			)
		`).Scan(&waiting); err != nil {
			t.Fatalf("observe paused cleanup batch: %v", err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cleanup did not pause inside the first committed batch")
		}
		time.Sleep(10 * time.Millisecond)
	}

	var cleanupLockKey int64
	if err := db.QueryRow(ctx, `
		SELECT hashtextextended('jjdguard:billing-request-leases-cleanup', 0)
	`).Scan(&cleanupLockKey); err != nil {
		t.Fatalf("resolve cleanup advisory lock key: %v", err)
	}
	competitor, err := db.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire competing cleanup connection: %v", err)
	}
	defer competitor.Release()
	var competitorPID int
	if err := competitor.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&competitorPID); err != nil {
		t.Fatalf("resolve competing cleanup backend: %v", err)
	}
	competitorDone := make(chan error, 1)
	go func() {
		_, err := competitor.Exec(ctx, `SELECT pg_advisory_lock($1)`, cleanupLockKey)
		competitorDone <- err
	}()

	deadline = time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err := db.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory'
			)
		`, competitorPID).Scan(&waiting); err != nil {
			t.Fatalf("observe competing cleanup lock wait: %v", err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("competing cleanup did not queue for the advisory lock")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, err := pauseBlocker.Exec(ctx, `SELECT pg_advisory_unlock($1)`, pauseLockKey); err != nil {
		t.Fatalf("release cleanup pause lock: %v", err)
	}
	pauseHeld = false
	if err := <-competitorDone; err != nil {
		t.Fatalf("acquire competing cleanup advisory lock: %v", err)
	}
	competitorHeld := true
	defer func() {
		if competitorHeld {
			_, _ = competitor.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, cleanupLockKey)
		}
	}()

	var outcome cleanupOutcome
	select {
	case outcome = <-cleanupDone:
	case <-ctx.Done():
		t.Fatalf("cleanup did not finish after advisory lock handoff: %v", ctx.Err())
	}
	if outcome.err != nil {
		t.Fatalf("cleanup after advisory lock handoff: %v", outcome.err)
	}
	if !outcome.result.Acquired || outcome.result.Batches != 1 || outcome.result.Deleted != requestLeaseCleanupBatchSize || !outcome.result.Backlog {
		t.Fatalf("cleanup result=%+v, want one committed batch with backlog", outcome.result)
	}
	stats := store.RequestLeaseCleanupStats()
	if stats.DeletedTotal != outcome.result.Deleted || stats.LastRunUnix != now.Unix() || !stats.Backlog {
		t.Fatalf("cleanup stats=%+v result=%+v, want committed batch recorded with backlog", stats, outcome.result)
	}

	if _, err := competitor.Exec(ctx, `SELECT pg_advisory_unlock($1)`, cleanupLockKey); err != nil {
		t.Fatalf("release competing cleanup advisory lock: %v", err)
	}
	competitorHeld = false
}

func TestStoreRequestLeaseCleanupAndDisableDoNotDeadlock(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{ConcurrencyLimit: 1}); err != nil {
		t.Fatalf("set request limit: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.Exec(ctx, `
		INSERT INTO billing_request_leases
			(tenant_id, user_id, request_id, acquired_at, expires_at, released_at)
		VALUES ($1,$2,$3,$4,$5,$6)
	`, tenantID, userID, "req-cleanup-disable-race", now.Add(-2*time.Minute), now.Add(-time.Minute), now.Add(-119*time.Second)); err != nil {
		t.Fatalf("insert stale lease: %v", err)
	}

	const advisoryLockKey int64 = 80620260816
	if _, err := db.Exec(ctx, `
		DROP TRIGGER IF EXISTS billing_test_block_disable_delete ON billing_request_leases;
		DROP FUNCTION IF EXISTS billing_test_block_disable_delete();
		CREATE FUNCTION billing_test_block_disable_delete() RETURNS trigger AS $$
		BEGIN
			IF OLD.request_id = 'req-cleanup-disable-race' THEN
				PERFORM pg_advisory_xact_lock(80620260816);
			END IF;
			RETURN OLD;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER billing_test_block_disable_delete
			BEFORE DELETE ON billing_request_leases
			FOR EACH ROW EXECUTE FUNCTION billing_test_block_disable_delete();
	`); err != nil {
		t.Fatalf("install delete lock trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `
			DROP TRIGGER IF EXISTS billing_test_block_disable_delete ON billing_request_leases;
			DROP FUNCTION IF EXISTS billing_test_block_disable_delete();
		`)
	})
	blocker, err := db.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire advisory lock connection: %v", err)
	}
	defer blocker.Release()
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		t.Fatalf("hold advisory lock: %v", err)
	}
	lockHeld := true
	defer func() {
		if lockHeld {
			_, _ = blocker.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, advisoryLockKey)
		}
	}()

	disableDone := make(chan error, 1)
	go func() {
		_, err := store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{})
		disableDone <- err
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		var waiting bool
		if err := db.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE datname=current_database()
				  AND wait_event_type='Lock'
				  AND wait_event='advisory'
				  AND query LIKE '%DELETE FROM billing_request_leases%'
			)
		`).Scan(&waiting); err != nil {
			t.Fatalf("observe disable lock wait: %v", err)
		}
		if waiting {
			break
		}
		select {
		case err := <-disableDone:
			t.Fatalf("disable returned before reaching lease row lock: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("disable did not reach the lease row lock")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(ctx, time.Second)
	defer cleanupCancel()
	if _, err := store.pruneRequestLeases(cleanupCtx, now); err != nil {
		t.Fatalf("cleanup must skip the lease row locked by disable: %v", err)
	}
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_unlock($1)`, advisoryLockKey); err != nil {
		t.Fatalf("release advisory lock: %v", err)
	}
	lockHeld = false
	if err := <-disableDone; err != nil {
		t.Fatalf("disable limits after cleanup contention: %v", err)
	}
}

func TestBillingRequestLeaseSchemaSupportsLifecycleCleanup(t *testing.T) {
	_, db, _, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	var deleteAction string
	if err := db.QueryRow(ctx, `
		SELECT confdeltype::text
		FROM pg_constraint
		WHERE conname='fk_billing_request_lease_user'
	`).Scan(&deleteAction); err != nil || deleteAction != "c" {
		t.Fatalf("request lease user foreign key delete action=%q err=%v, want cascade", deleteAction, err)
	}
	for _, indexName := range []string{
		"idx_billing_request_leases_expiry",
		"idx_billing_request_leases_released",
	} {
		var exists bool
		if err := db.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, indexName).Scan(&exists); err != nil || !exists {
			t.Fatalf("cleanup index %q exists=%v err=%v, want true", indexName, exists, err)
		}
	}
	var obsoleteIndexExists bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('idx_billing_reservations_wallet_created') IS NOT NULL`).Scan(&obsoleteIndexExists); err != nil || obsoleteIndexExists {
		t.Fatalf("obsolete reservation index exists=%v err=%v, want false", obsoleteIndexExists, err)
	}
}

func TestStoreRPMLimitIsAtomicUnderConcurrentAdmission(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	firstWallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure first wallet: %v", err)
	}
	secondWallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure second wallet: %v", err)
	}
	if _, err = store.Credit(ctx, tenantID, firstWallet.ID, "rpm-race-credit-cny", 100, "admin-a"); err != nil {
		t.Fatalf("credit first wallet: %v", err)
	}
	if _, err = store.Credit(ctx, tenantID, secondWallet.ID, "rpm-race-credit-usd", 100, "admin-a"); err != nil {
		t.Fatalf("credit second wallet: %v", err)
	}
	if _, err = store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{RPMLimit: 1}); err != nil {
		t.Fatalf("set limits: %v", err)
	}

	walletIDs := []string{firstWallet.ID, secondWallet.ID}
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			<-start
			_, _, reserveErr := store.Reserve(ctx, tenantID, walletIDs[i], fmt.Sprintf("req-rpm-race-%d", i), 1)
			results <- reserveErr
		}(i)
	}
	close(start)
	assertConcurrentLimitResults(t, results, ErrCustomerRPMLimitExceeded)
}

func TestStoreConcurrencyLimitIsAtomicUnderConcurrentAdmission(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	firstWallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure first wallet: %v", err)
	}
	secondWallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure second wallet: %v", err)
	}
	if _, err = store.Credit(ctx, tenantID, firstWallet.ID, "concurrency-race-credit-cny", 100, "admin-a"); err != nil {
		t.Fatalf("credit first wallet: %v", err)
	}
	if _, err = store.Credit(ctx, tenantID, secondWallet.ID, "concurrency-race-credit-usd", 100, "admin-a"); err != nil {
		t.Fatalf("credit second wallet: %v", err)
	}
	if _, err = store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{ConcurrencyLimit: 1}); err != nil {
		t.Fatalf("set limits: %v", err)
	}

	walletIDs := []string{firstWallet.ID, secondWallet.ID}
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			<-start
			_, _, reserveErr := store.Reserve(ctx, tenantID, walletIDs[i], fmt.Sprintf("req-concurrency-race-%d", i), 1)
			results <- reserveErr
		}(i)
	}
	close(start)
	assertConcurrentLimitResults(t, results, ErrCustomerConcurrencyLimitExceeded)
}

func TestStoreConcurrentSameRequestDoesNotDuplicateExecutionLease(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	if _, err = store.Credit(ctx, tenantID, wallet.ID, "same-request-credit", 100, "admin-a"); err != nil {
		t.Fatalf("credit wallet: %v", err)
	}
	if _, err = store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{RPMLimit: 1, ConcurrencyLimit: 1}); err != nil {
		t.Fatalf("set limits: %v", err)
	}

	type reserveResult struct {
		reservationID string
		err           error
	}
	start := make(chan struct{})
	results := make(chan reserveResult, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			reservation, _, reserveErr := store.Reserve(ctx, tenantID, wallet.ID, "req-same-concurrent", 1)
			result := reserveResult{err: reserveErr}
			if reservation != nil {
				result.reservationID = reservation.ID
			}
			results <- result
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.reservationID == "" || first.reservationID != second.reservationID {
		t.Fatalf("same request results=%#v %#v", first, second)
	}
	var leases int
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_request_leases WHERE tenant_id=$1 AND request_id=$2`, tenantID, "req-same-concurrent").Scan(&leases); err != nil || leases != 1 {
		t.Fatalf("execution leases=%d err=%v, want 1", leases, err)
	}
}

func assertConcurrentLimitResults(t *testing.T, results <-chan error, limitErr error) {
	t.Helper()
	var succeeded, limited, unexpected int
	for i := 0; i < 2; i++ {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, limitErr):
			limited++
		default:
			unexpected++
		}
	}
	if succeeded != 1 || limited != 1 || unexpected != 0 {
		t.Fatalf("concurrent admissions succeeded=%d limited=%d unexpected=%d, want 1/1/0", succeeded, limited, unexpected)
	}
}

func TestStoreReserveFailsClosedUnderConcurrency(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	wallet, err = store.Credit(ctx, tenantID, wallet.ID, "seed-concurrency", 5_000_000, "admin-a")
	if err != nil {
		t.Fatalf("credit: %v", err)
	}

	var succeeded atomic.Int64
	var unexpected atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, reserveErr := store.Reserve(ctx, tenantID, wallet.ID, fmt.Sprintf("req-concurrent-%d", i), 1_000_000)
			switch {
			case reserveErr == nil:
				succeeded.Add(1)
			case errors.Is(reserveErr, ErrInsufficientBalance):
			default:
				unexpected.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if unexpected.Load() != 0 || succeeded.Load() != 5 {
		t.Fatalf("concurrent reserves: succeeded=%d unexpected=%d, want 5/0", succeeded.Load(), unexpected.Load())
	}
	wallet, err = store.GetWallet(ctx, tenantID, wallet.ID)
	if err != nil {
		t.Fatalf("get wallet: %v", err)
	}
	if wallet.AvailableMicros() != 0 || wallet.ReservedMicros != 5_000_000 {
		t.Fatalf("wallet after concurrent reserves: %#v", wallet)
	}
}

func TestStoreReleaseIsIdempotent(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	wallet, err = store.Credit(ctx, tenantID, wallet.ID, "seed-release", 2_000_000, "admin-a")
	if err != nil {
		t.Fatalf("credit: %v", err)
	}
	reservation, _, err := store.Reserve(ctx, tenantID, wallet.ID, "req-release", 1_000_000)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	released, wallet, err := store.Release(ctx, tenantID, "req-release")
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if released.ID != reservation.ID || released.Status != ReservationReleased || wallet.ReservedMicros != 0 || wallet.BalanceMicros != 2_000_000 {
		t.Fatalf("released state: reservation=%#v wallet=%#v", released, wallet)
	}
	released, wallet, err = store.Release(ctx, tenantID, "req-release")
	if err != nil || released.Status != ReservationReleased || wallet.ReservedMicros != 0 {
		t.Fatalf("idempotent release: reservation=%#v wallet=%#v err=%v", released, wallet, err)
	}
}

func ledgerSettleMetadata(t *testing.T, db *pgxpool.Pool, tenantID, requestID string) (string, int64, int64) {
	t.Helper()
	var metadata string
	var balanceDelta, balanceAfter int64
	if err := db.QueryRow(context.Background(), `
		SELECT metadata_json::text, balance_delta_micros, balance_after_micros
		FROM billing_ledger_entries
		WHERE tenant_id = $1 AND request_id = $2 AND event_type = 'settle'
	`, tenantID, requestID).Scan(&metadata, &balanceDelta, &balanceAfter); err != nil {
		t.Fatalf("read settle ledger for %s: %v", requestID, err)
	}
	return metadata, balanceDelta, balanceAfter
}

// D5 (7.3): a settlement larger than the remaining balance books the actual
// amount, may drive the balance negative, marks the ledger overdraft, keeps
// the exception queue clean, and the next admission is refused.
func TestStoreSettleOverdraftBooksActualAndRefusesNextReserve(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	if wallet, err = store.Credit(ctx, tenantID, wallet.ID, "seed-overdraft", 1_000_000, "admin-a"); err != nil {
		t.Fatalf("credit: %v", err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-overdraft-a", 600_000); err != nil {
		t.Fatalf("reserve a: %v", err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-overdraft-b", 400_000); err != nil {
		t.Fatalf("reserve b: %v", err)
	}
	// A consumes more than its estimate while B is still in flight.
	_, wallet, err = store.Settle(ctx, tenantID, "req-overdraft-a", 800_000)
	if err != nil {
		t.Fatalf("overdrawing settlement must succeed: %v", err)
	}
	if wallet.BalanceMicros != 200_000 || wallet.ReservedMicros != 400_000 {
		t.Fatalf("wallet after overdraft settle = %#v", wallet)
	}
	metadata, delta, after := ledgerSettleMetadata(t, db, tenantID, "req-overdraft-a")
	if delta != -800_000 || after != 200_000 || !strings.Contains(metadata, `"overdraft": true`) || !strings.Contains(metadata, `"available_after_micros": -200000`) {
		t.Fatalf("overdraft ledger delta=%d after=%d metadata=%s", delta, after, metadata)
	}
	// B finishes and drives the balance negative; the actual amount is booked.
	_, wallet, err = store.Settle(ctx, tenantID, "req-overdraft-b", 500_000)
	if err != nil {
		t.Fatalf("settlement below zero must succeed: %v", err)
	}
	if wallet.BalanceMicros != -300_000 || wallet.ReservedMicros != 0 {
		t.Fatalf("wallet after negative settle = %#v", wallet)
	}
	metadata, delta, after = ledgerSettleMetadata(t, db, tenantID, "req-overdraft-b")
	if delta != -500_000 || after != -300_000 || !strings.Contains(metadata, `"overdraft": true`) {
		t.Fatalf("negative ledger delta=%d after=%d metadata=%s", delta, after, metadata)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-overdraft-next", 1); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("reserve on overdrawn wallet error = %v, want ErrInsufficientBalance", err)
	}
	exceptions, err := store.ListBillingExceptions(ctx, tenantID, 100)
	if err != nil {
		t.Fatalf("list exceptions: %v", err)
	}
	if len(exceptions) != 0 {
		t.Fatalf("overdraft settlements must not enter the exception queue: %#v", exceptions)
	}
	// A positive correction on an overdrawn wallet is accepted; admission stays
	// closed until the balance is back above zero.
	if wallet, err = store.Adjust(ctx, tenantID, wallet.ID, "fix-overdraft", 100_000, "admin-a"); err != nil || wallet.BalanceMicros != -200_000 {
		t.Fatalf("positive adjustment on overdrawn wallet = %#v err=%v", wallet, err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-overdraft-next", 1); !errors.Is(err, ErrInsufficientBalance) {
		t.Fatalf("reserve on still-negative wallet error = %v, want ErrInsufficientBalance", err)
	}
	if wallet, err = store.Credit(ctx, tenantID, wallet.ID, "topup-overdraft", 1_000_000, "admin-a"); err != nil || wallet.BalanceMicros != 800_000 {
		t.Fatalf("top-up after overdraft = %#v err=%v", wallet, err)
	}
	if _, _, err = store.Reserve(ctx, tenantID, wallet.ID, "req-overdraft-next", 1); err != nil {
		t.Fatalf("reserve after top-up: %v", err)
	}
}

// D5 (7.3) on the gateway settlement path: SettleCharge books a priced charge
// that exceeds the balance, and the idempotent retry returns the same charge.
func TestStoreSettleChargeOverdraftIsBookedAndIdempotent(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	if wallet, err = store.Credit(ctx, tenantID, wallet.ID, "seed-charge-overdraft", 1_000, "admin-a"); err != nil {
		t.Fatalf("credit: %v", err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "overdraft-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 4_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("create price: %v", err)
	}
	if _, _, err = store.ReservePricedWithUsageForGroup(ctx, tenantID, wallet.ID, "req-charge-overdraft", 1_000, 100, price, DefaultCustomerGroup, ratioScale); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// 1000 prompt + 500 output = 1000 + 2000 = 3000 micros against a 1000 balance.
	usage := Usage{PromptTokens: 1_000, OutputTokens: 500}
	charge, wallet, err := store.SettleCharge(ctx, tenantID, "req-charge-overdraft", price, usage, []byte(`{}`), nil)
	if err != nil {
		t.Fatalf("overdrawing charge must settle: %v", err)
	}
	if charge.AmountMicros != 3_000 || wallet.BalanceMicros != -2_000 || wallet.ReservedMicros != 0 {
		t.Fatalf("charge=%d wallet=%#v, want 3000 and balance -2000", charge.AmountMicros, wallet)
	}
	metadata, delta, _ := ledgerSettleMetadata(t, db, tenantID, "req-charge-overdraft")
	if delta != -3_000 || !strings.Contains(metadata, `"overdraft": true`) {
		t.Fatalf("charge ledger delta=%d metadata=%s", delta, metadata)
	}
	same, wallet, err := store.SettleCharge(ctx, tenantID, "req-charge-overdraft", price, usage, []byte(`{}`), nil)
	if err != nil || same.ID != charge.ID || wallet.BalanceMicros != -2_000 {
		t.Fatalf("idempotent overdraft retry: charge=%#v wallet=%#v err=%v", same, wallet, err)
	}
}
