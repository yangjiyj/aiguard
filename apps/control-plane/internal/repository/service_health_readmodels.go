package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ServiceHealthReadModelRepository provides read-only evidence queries for the
// service-health and reconciliation read models. It never writes and never
// mutates billing core tables; every query is a SELECT over existing tables.
type ServiceHealthReadModelRepository struct {
	db *pgxpool.Pool
}

// NewServiceHealthReadModelRepository creates the repository.
func NewServiceHealthReadModelRepository(db *pgxpool.Pool) *ServiceHealthReadModelRepository {
	return &ServiceHealthReadModelRepository{db: db}
}

// readModelQuerier abstracts the snapshot source: either the pool (no
// transaction) or a pgx.Tx. Both satisfy this interface.
type readModelQuerier interface {
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}

// AuditPipelineStats is the DB evidence for the audit pipeline component.
// PendingCount counts request_logs rows still awaiting audit outcome inside
// the window; RequestCount is the total rows in the same window so callers
// can distinguish "no backlog" from "no traffic" (no samples means unknown).
type AuditPipelineStats struct {
	RequestCount     int64
	PendingCount     int64
	OldestPendingAge *int64 // seconds, nil when no pending rows
}

var excludeNonBusinessRequestLogs = ExcludeNonBusinessEndpointsSQL("request_logs")

// auditPipelineStatsSQL 不含平台自建的请求日志（运行告警等不经审计管线）。
var auditPipelineStatsSQL = `
		SELECT
			COUNT(*)::bigint,
			COUNT(*) FILTER (WHERE audit_outcome = 'pending')::bigint,
			(SELECT EXTRACT(EPOCH FROM (NOW() - MIN(created_at)))::bigint
			 FROM request_logs
			 WHERE ` + excludeNonBusinessRequestLogs + ` AND audit_outcome = 'pending'
			   AND created_at > NOW() - make_interval(mins => $1 * 60))
		FROM request_logs
		WHERE ` + excludeNonBusinessRequestLogs + ` AND created_at > NOW() - make_interval(mins => $1 * 60)
	`

// AuditPipelineStats reads audit pipeline evidence over the last windowHours.
func (r *ServiceHealthReadModelRepository) AuditPipelineStats(ctx context.Context, windowHours int) (*AuditPipelineStats, error) {
	if windowHours <= 0 || windowHours > 24*30 {
		windowHours = 24
	}
	stats := &AuditPipelineStats{}
	err := r.db.QueryRow(ctx, auditPipelineStatsSQL, windowHours).Scan(&stats.RequestCount, &stats.PendingCount, &stats.OldestPendingAge)
	if err != nil {
		return nil, fmt.Errorf("audit pipeline stats: %w", err)
	}
	return stats, nil
}

// BillingCompensationStats is the DB evidence for the billing compensation
// component. The background reconciliation worker only logs its results and
// keeps no persisted heartbeat, so the worker itself is always unknown here;
// only the backlog is observable.
type BillingCompensationStats struct {
	StaleReservedCount      int64  // reserved longer than staleAfterMinutes
	OldestStaleReservedAge  *int64 // seconds, nil when none
	ActiveLeaseCount        int64  // request execution leases not released
	ExpiredUnreleasedLeases int64  // past expiry but not released nor pruned
	OldestExpiredUnreleased *int64 // seconds past expiry, nil when none
}

// BillingCompensationStats reads compensation backlog evidence.
func (r *ServiceHealthReadModelRepository) BillingCompensationStats(ctx context.Context, staleAfterMinutes int) (*BillingCompensationStats, error) {
	if staleAfterMinutes <= 0 {
		staleAfterMinutes = 15
	}
	stats := &BillingCompensationStats{}
	err := r.db.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*)::bigint FROM billing_reservations
			  WHERE status = 'reserved' AND created_at < NOW() - make_interval(mins => $1)),
			(SELECT EXTRACT(EPOCH FROM (NOW() - MIN(created_at)))::bigint FROM billing_reservations
			  WHERE status = 'reserved' AND created_at < NOW() - make_interval(mins => $1)),
			(SELECT COUNT(*)::bigint FROM billing_request_leases WHERE released_at IS NULL),
			(SELECT COUNT(*)::bigint FROM billing_request_leases WHERE released_at IS NULL AND expires_at < NOW()),
			(SELECT EXTRACT(EPOCH FROM (NOW() - MIN(expires_at)))::bigint FROM billing_request_leases
			  WHERE released_at IS NULL AND expires_at < NOW())
	`, staleAfterMinutes).Scan(
		&stats.StaleReservedCount,
		&stats.OldestStaleReservedAge,
		&stats.ActiveLeaseCount,
		&stats.ExpiredUnreleasedLeases,
		&stats.OldestExpiredUnreleased,
	)
	if err != nil {
		return nil, fmt.Errorf("billing compensation stats: %w", err)
	}
	return stats, nil
}

// SemanticFaultEventCount counts runtime-fault security events inside the
// window. Fault events are semantic_attack/security_check rows whose
// matched_summary carries a semantic_reason or inspection_reason, matching
// the fault-alert classification. Zero means no fault samples, not health.
func (r *ServiceHealthReadModelRepository) SemanticFaultEventCount(ctx context.Context, windowHours int) (int64, error) {
	if windowHours <= 0 || windowHours > 24*30 {
		windowHours = 24
	}
	var n int64
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)::bigint
		FROM security_events
		WHERE event_type IN ('semantic_attack', 'security_check')
		  AND created_at > NOW() - make_interval(mins => $1 * 60)
		  AND (
			NULLIF(matched_summary->>'semantic_reason', '') IS NOT NULL
			OR NULLIF(matched_summary->>'inspection_reason', '') IS NOT NULL
		  )
	`, windowHours).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("semantic fault event count: %w", err)
	}
	return n, nil
}

// OwnerWallet is a user-owned prepaid wallet as seen by read models.
type OwnerWallet struct {
	WalletID       string
	UserID         string
	Currency       string
	BalanceMicros  int64
	ReservedMicros int64
	CreatedAt      time.Time
}

// OwnerWallets lists the prepaid wallets of one user inside a tenant. A user
// may hold several currencies; read models must not pick one silently.
func (r *ServiceHealthReadModelRepository) OwnerWallets(ctx context.Context, tenantID, userID string) ([]OwnerWallet, error) {
	if tenantID == "" || userID == "" {
		return nil, nil
	}
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, currency, balance_micros, reserved_micros, created_at
		FROM billing_wallets
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY currency
	`, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("owner wallets: %w", err)
	}
	defer rows.Close()
	var out []OwnerWallet
	for rows.Next() {
		var w OwnerWallet
		if err := rows.Scan(&w.WalletID, &w.UserID, &w.Currency, &w.BalanceMicros, &w.ReservedMicros, &w.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan owner wallet: %w", err)
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// WalletReconciliationPeriod is the per-wallet period aggregation for the
// reconciliation read model. All amounts are integer micros in the wallet's
// own currency; periods are compared in UTC against ledger created_at.
//
// Opening/closing/period-end-reserved carry an explicit availability flag and
// basis. billing_ledger_entries.created_at is DEFAULT NOW(), the
// transaction-START timestamp, and the wallet row lock is taken later inside
// the transaction, so created_at order does NOT prove wallet-state order: two
// concurrent wallet transactions can start in one order and take the lock in
// the opposite one. An adjacent +delta/-delta pair is numerically
// indistinguishable whichever order actually ran, so no local successor-chain
// check and no live-state anchor can prove a pick — they only fit numbers.
// Without trustworthy historical order evidence a boundary is reported as
// unknown ("boundary_order_unverifiable"), never as a silent zero or an
// arbitrary balance_after. The closing identity is only meaningful when both
// endpoints are available.
//
// The period deltas, event counts and the live in-flight reservation total
// below are unaffected: those aggregate real rows and stay exact.
type WalletReconciliationPeriod struct {
	WalletID string
	UserID   string
	Currency string

	OpeningAvailable bool
	OpeningBalance   int64
	OpeningBasis     string // wallet_created_after_period_start | boundary_order_unverifiable | unknown

	ClosingAvailable bool
	ClosingBalance   int64
	ClosingBasis     string // opening_carryover | boundary_order_unverifiable | unknown

	// Period-end reserved snapshot. Only structurally provable values are
	// reported: the wallet did not exist at the boundary, so its reserved
	// total was 0. With any ledger history the snapshot is unknown for the
	// same ordering reason as the balance boundaries.
	PeriodEndReservedAvailable bool
	PeriodEndReserved          int64
	PeriodEndReservedBasis     string // wallet_created_after_period_end | boundary_order_unverifiable | unknown

	// Live in-flight as of NOW (adjunct evidence, not a period-end value).
	// CurrentReserved/CurrentReservedCnt are the SUM over live
	// billing_reservations rows; CurrentBalance/CurrentWalletReserved are the
	// wallet row's own columns read in the same snapshot. The two are reported
	// separately and never substituted for one another: the reservation rows
	// and the wallet column are independent evidence, and a divergence between
	// them is itself a fact the console must be able to show.
	CurrentReserved       int64
	CurrentReservedCnt    int64
	CurrentBalance        int64
	CurrentWalletReserved int64

	IdentityAvailable bool
	ExpectedClosing   int64
	ClosingDiff       int64

	// Event-type coverage: any balance-bearing event type outside the known
	// contract set (credit/adjustment/refund/settle) is surfaced here instead
	// of being silently dropped, which would manufacture a fake diff.
	OtherDeltaMicros   int64
	OtherEventCount    int64
	OtherEventTypes    []string
	CreditMicros       int64
	CreditCount        int64
	AdjustmentMicros   int64
	AdjustmentCount    int64
	RefundMicros       int64
	RefundCount        int64
	SettleMicros       int64
	SettleCount        int64
	ReleaseCount       int64
	ReserveDeltaMicros int64
	ReserveCount       int64

	// Anomalous reserve/release entries carry a non-zero balance_delta (the
	// schema CHECK forbids it, but the read model must not silently fold a
	// constraint-violating row into a clean zero). They participate in the
	// closing identity explicitly.
	ReserveBalanceAnomalyMicros int64
	ReserveBalanceAnomalyCount  int64
	ReleaseBalanceAnomalyMicros int64
	ReleaseBalanceAnomalyCount  int64
}

// knownBalanceEventTypes is the ledger event-type contract enforced by the
// ck_billing_ledger_event constraint: balance-bearing types are credited,
// adjusted, refunded and settled; reserve/release only move reserved_micros.
var knownBalanceEventTypes = map[string]bool{
	"credit": true, "adjustment": true, "refund": true, "settle": true,
	"reserve": true, "release": true,
}

// ReconciliationPeriod aggregates billing_ledger_entries per wallet for the
// half-open interval [start, end). All reads run inside a single REPEATABLE
// READ READ ONLY transaction so concurrent credits/settlements cannot land
// between the opening, aggregation and closing reads and manufacture a fake
// diff. On error the transaction is rolled back and nothing partial escapes.
func (r *ServiceHealthReadModelRepository) ReconciliationPeriod(ctx context.Context, tenantID, currency string, start, end time.Time) ([]WalletReconciliationPeriod, error) {
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("reconciliation snapshot begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	items, err := reconciliationPeriodTx(ctx, tx, tenantID, currency, start, end)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("reconciliation snapshot commit: %w", err)
	}
	return items, nil
}

// reconciliationPeriodTx runs the full aggregation against one querier. Call
// it with a REPEATABLE READ READ ONLY transaction for a consistent snapshot;
// tests use it directly to pin snapshot semantics under concurrent writes.
func reconciliationPeriodTx(ctx context.Context, q readModelQuerier, tenantID, currency string, start, end time.Time) ([]WalletReconciliationPeriod, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("reconciliation period: empty tenant")
	}
	walletQ := `
		SELECT id, user_id, currency, COALESCE(balance_micros, 0), COALESCE(reserved_micros, 0), created_at
		FROM billing_wallets
		WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	if currency != "" {
		walletQ += ` AND currency = $2`
		args = append(args, currency)
	}
	walletQ += `
		ORDER BY created_at, id`
	rows, err := q.Query(ctx, walletQ, args...)
	if err != nil {
		return nil, fmt.Errorf("reconciliation wallets: %w", err)
	}
	type walletRow struct {
		id, userID, currency string
		balance, reserved    int64
		createdAt            time.Time
	}
	wallets := []walletRow{}
	for rows.Next() {
		var w walletRow
		if err := rows.Scan(&w.id, &w.userID, &w.currency, &w.balance, &w.reserved, &w.createdAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan reconciliation wallet: %w", err)
		}
		wallets = append(wallets, w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(wallets) == 0 {
		return []WalletReconciliationPeriod{}, nil
	}
	rangeEnd := end
	if !rangeEnd.After(start) {
		rangeEnd = start.Add(time.Nanosecond)
	}

	// walletsWithLedgerBefore lists the wallets that have at least one ledger
	// entry whose transaction STARTED before the boundary.
	//
	// This is deliberately the only boundary input. Picking "the latest entry
	// before the boundary" would need created_at to order wallet states, and
	// created_at is the transaction-start timestamp taken before the wallet row
	// lock is acquired, so it cannot. Corroborating such a pick with the
	// adjacent successor's chain (succ.after == pick.after + succ.delta) or
	// with the live wallet state does not help: an adjacent +delta/-delta pair
	// fits those equalities under either real order, so the check confirms
	// numbers rather than order. The same inversion fools a "first entry
	// satisfies after == delta, therefore the wallet started at zero"
	// inference. Both heuristics are removed: with prior ledger history the
	// boundary is unverifiable and is reported as unknown.
	walletsWithLedgerBefore := func(before time.Time) (map[string]bool, error) {
		rows, err := q.Query(ctx, `
			SELECT DISTINCT wallet_id
			FROM billing_ledger_entries
			WHERE tenant_id = $1 AND created_at < $2
		`, tenantID, before)
		if err != nil {
			return nil, fmt.Errorf("reconciliation boundary history: %w", err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var wid string
			if err := rows.Scan(&wid); err != nil {
				return nil, fmt.Errorf("scan reconciliation boundary history: %w", err)
			}
			out[wid] = true
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return out, nil
	}

	openingHasLedger, err := walletsWithLedgerBefore(start)
	if err != nil {
		return nil, err
	}
	closingHasLedger, err := walletsWithLedgerBefore(rangeEnd)
	if err != nil {
		return nil, err
	}

	// Period entries aggregated per wallet and event type. Unknown event
	// types are collected (never dropped) so a foreign balance-bearing entry
	// cannot silently manufacture a fake closing diff.
	type aggRow struct {
		sumMicros           int64
		count               int64
		balanceAnomalyCount int64
	}
	aggs := map[string]map[string]*aggRow{}
	aggRows, err := q.Query(ctx, `
		SELECT wallet_id, event_type, SUM(balance_delta_micros)::bigint, COUNT(*)::bigint,
		       SUM(CASE WHEN balance_delta_micros <> 0 THEN 1 ELSE 0 END)::bigint
		FROM billing_ledger_entries
		WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3
		GROUP BY wallet_id, event_type
	`, tenantID, start, rangeEnd)
	if err != nil {
		return nil, fmt.Errorf("reconciliation entries: %w", err)
	}
	for aggRows.Next() {
		var wid, ev string
		var sum, cnt, anom int64
		if err := aggRows.Scan(&wid, &ev, &sum, &cnt, &anom); err != nil {
			aggRows.Close()
			return nil, fmt.Errorf("scan reconciliation entry: %w", err)
		}
		if aggs[wid] == nil {
			aggs[wid] = map[string]*aggRow{}
		}
		aggs[wid][ev] = &aggRow{sumMicros: sum, count: cnt, balanceAnomalyCount: anom}
	}
	aggRows.Close()
	if err := aggRows.Err(); err != nil {
		return nil, err
	}

	// Live in-flight reservations per wallet (adjunct, NOT period-end).
	reserved := map[string]int64{}
	reservedCnt := map[string]int64{}
	resRows, err := q.Query(ctx, `
		SELECT wallet_id, COALESCE(SUM(reserved_micros), 0)::bigint, COUNT(*)::bigint
		FROM billing_reservations
		WHERE tenant_id = $1 AND status = 'reserved'
		GROUP BY wallet_id
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("reconciliation reservations: %w", err)
	}
	for resRows.Next() {
		var wid string
		var sum, cnt int64
		if err := resRows.Scan(&wid, &sum, &cnt); err != nil {
			resRows.Close()
			return nil, fmt.Errorf("scan reconciliation reservation: %w", err)
		}
		reserved[wid] = sum
		reservedCnt[wid] = cnt
	}
	resRows.Close()
	if err := resRows.Err(); err != nil {
		return nil, err
	}

	out := make([]WalletReconciliationPeriod, 0, len(wallets))
	for _, w := range wallets {
		item := WalletReconciliationPeriod{
			WalletID: w.id, UserID: w.userID, Currency: w.currency,
			// Live wallet-row state, read in the same REPEATABLE READ
			// snapshot as the period aggregation and the reservation sum.
			CurrentBalance:        w.balance,
			CurrentWalletReserved: w.reserved,
			CurrentReserved:       reserved[w.id],
			CurrentReservedCnt:    reservedCnt[w.id],
		}

		// Opening balance. Without trustworthy historical order there is
		// exactly one provable case: the wallet did not exist yet at the
		// boundary, so the opening is structurally 0.
		switch {
		case openingHasLedger[w.id]:
			// Ledger history exists before the boundary but created_at cannot
			// order it against the wallet lock, so the state at the boundary
			// is unknown. Never a picked balance_after, never a silent zero.
			item.OpeningBasis = "boundary_order_unverifiable"
		case !w.createdAt.Before(start):
			// Wallet did not exist before the period: opening is structurally
			// 0. Contract evidence: EnsureWallet (billing store.go) inserts
			// without balance columns, so creation balance is the column
			// default 0, and every balance change goes through the ledger.
			item.OpeningBalance = 0
			item.OpeningBasis = "wallet_created_after_period_start"
			item.OpeningAvailable = true
		default:
			// The wallet existed before the period but nothing in the ledger
			// speaks for the state at the boundary. Even "the earliest entry
			// satisfies balance_after == balance_delta, therefore the wallet
			// started at zero" is not evidence: an adjacent +delta/-delta pair
			// inverted under lock contention satisfies that equality for
			// whichever entry happens to sort first by created_at. No entries
			// and no proof means unknown.
			item.OpeningBasis = "unknown"
		}

		// Period entries with full event-type coverage.
		get := func(ev string) (int64, int64) {
			if a := aggs[w.id][ev]; a != nil {
				return a.sumMicros, a.count
			}
			return 0, 0
		}
		item.CreditMicros, item.CreditCount = get("credit")
		item.AdjustmentMicros, item.AdjustmentCount = get("adjustment")
		item.RefundMicros, item.RefundCount = get("refund")
		item.SettleMicros, item.SettleCount = get("settle")
		_, item.ReleaseCount = get("release")
		item.ReserveDeltaMicros, item.ReserveCount = get("reserve")
		// Reserve/release must never move the balance: a non-zero balance
		// delta on either is a constraint-violating anomaly and must not be
		// silently dropped from the identity.
		if a := aggs[w.id]["reserve"]; a != nil && a.balanceAnomalyCount > 0 {
			item.ReserveBalanceAnomalyMicros = a.sumMicros
			item.ReserveBalanceAnomalyCount = a.balanceAnomalyCount
		}
		if a := aggs[w.id]["release"]; a != nil && a.balanceAnomalyCount > 0 {
			item.ReleaseBalanceAnomalyMicros = a.sumMicros
			item.ReleaseBalanceAnomalyCount = a.balanceAnomalyCount
		}
		for ev, a := range aggs[w.id] {
			if knownBalanceEventTypes[ev] {
				continue
			}
			item.OtherEventTypes = append(item.OtherEventTypes, ev)
			item.OtherDeltaMicros += a.sumMicros
			item.OtherEventCount += a.count
		}

		// Closing balance.
		switch {
		case closingHasLedger[w.id]:
			item.ClosingBasis = "boundary_order_unverifiable"
		case item.OpeningAvailable:
			// No ledger entry started before the period end, so no balance
			// change was committed before it: the closing state is the
			// opening state. Sound without ordering, because every balance
			// change goes through the ledger in the wallet-locking
			// transaction, and an entry whose transaction starts at/after the
			// boundary can only take the lock at/after the boundary.
			item.ClosingBalance = item.OpeningBalance
			item.ClosingBasis = "opening_carryover"
			item.ClosingAvailable = true
		default:
			item.ClosingBasis = "unknown"
		}

		// Period-end reserved snapshot (ledger evidence only).
		switch {
		case closingHasLedger[w.id]:
			item.PeriodEndReservedBasis = "boundary_order_unverifiable"
		case !w.createdAt.Before(rangeEnd):
			item.PeriodEndReserved = 0
			item.PeriodEndReservedBasis = "wallet_created_after_period_end"
			item.PeriodEndReservedAvailable = true
		default:
			item.PeriodEndReservedBasis = "unknown"
		}

		// Identity: opening + credit + adjustment + refund + settle +
		// other_delta + reserve/release balance anomalies = closing. release
		// does not change balance; reserve moves reserved only. The identity
		// is only reported when both endpoints carry evidence; other_delta
		// and anomalies participate so a foreign event type cannot masquerade
		// as a bookkeeping error.
		item.IdentityAvailable = item.OpeningAvailable && item.ClosingAvailable
		if item.IdentityAvailable {
			item.ExpectedClosing = item.OpeningBalance + item.CreditMicros + item.AdjustmentMicros +
				item.RefundMicros + item.SettleMicros + item.OtherDeltaMicros +
				item.ReserveBalanceAnomalyMicros + item.ReleaseBalanceAnomalyMicros
			item.ClosingDiff = item.ClosingBalance - item.ExpectedClosing
		}
		out = append(out, item)
	}
	return out, nil
}
