package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Zero enforcement markers are not financial denomination evidence. Once any
// actual balance mutation exists, even a fully spent account retains its unit.
const fundedWalletPredicate = `(w.balance_micros<>0 OR w.reserved_micros<>0 OR EXISTS(SELECT 1 FROM billing_ledger_entries e WHERE e.tenant_id=w.tenant_id AND e.wallet_id=w.id AND e.balance_delta_micros<>0))`

// MonthlyWalletStatus describes money actually credited, never an independent cap.
type MonthlyWalletStatus struct {
	ConfiguredMicros *int64    `json:"configured_micros"`
	GrantedMicros    int64     `json:"granted_micros"`
	RemainingMicros  int64     `json:"remaining_micros"`
	ReservedMicros   int64     `json:"reserved_micros"`
	UsedMicros       int64     `json:"used_micros"`
	ExpiredMicros    int64     `json:"expired_micros"`
	AdjustedMicros   int64     `json:"adjusted_micros"`
	Currency         string    `json:"currency"`
	Timezone         string    `json:"timezone"`
	MonthStart       time.Time `json:"month_start"`
	MonthEnd         time.Time `json:"month_end"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type MonthlyWalletGrantResult struct {
	Attempted    int  `json:"attempted"`
	Synchronized int  `json:"synchronized"`
	Failed       int  `json:"failed"`
	Backlog      bool `json:"backlog"`
}

// EnsureMonthlyWalletGrant serializes configuration, user state and wallet money.
// Both lazy admission and the background worker call this exact transaction.
// fundingNow is the actual money time after acquiring the wallet lock. The
// optional test clock cannot be set by HTTP input. Price admittedAt stays separate.
func (s *Store) fundingNow() time.Time {
	if s.fundingClock != nil {
		return s.fundingClock().UTC()
	}
	return time.Now().UTC()
}

func (s *Store) walletFundingContextTx(ctx context.Context, tx pgx.Tx, tenantID, userID, currency string) (EmployeeSettings, *int64, bool, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, "allowance-settings:"+tenantID); err != nil {
		return EmployeeSettings{}, nil, false, err
	}
	cfg, err := s.employeeSettings(ctx, tx, tenantID)
	if err != nil {
		return EmployeeSettings{}, nil, false, err
	}
	cfg.Currency, err = s.billingCurrencyForTenant(ctx, tx, tenantID)
	if err != nil {
		return EmployeeSettings{}, nil, false, err
	}
	if currency != cfg.Currency {
		return EmployeeSettings{}, nil, false, ErrAllowanceCurrency
	}
	var tenantStatus string
	if err = tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR SHARE`, tenantID).Scan(&tenantStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EmployeeSettings{}, nil, false, ErrInvalidWalletState
		}
		return EmployeeSettings{}, nil, false, err
	}
	var status, role string
	err = tx.QueryRow(ctx, `SELECT status,role FROM users WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenantID, userID).Scan(&status, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return EmployeeSettings{}, nil, false, ErrInvalidWalletState
	}
	if err != nil {
		return EmployeeSettings{}, nil, false, err
	}
	var amount *int64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(a.monthly_micros,c.default_monthly_micros) FROM users u LEFT JOIN billing_employee_settings c ON c.tenant_id=u.tenant_id LEFT JOIN billing_employee_allowances a ON a.tenant_id=u.tenant_id AND a.user_id=u.id WHERE u.tenant_id=$1 AND u.id=$2`, tenantID, userID).Scan(&amount); err != nil {
		return EmployeeSettings{}, nil, false, err
	}
	var foreignMoney bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_wallets w WHERE w.tenant_id=$1 AND w.user_id=$2 AND w.currency<>$3 AND `+fundedWalletPredicate+`)`, tenantID, userID, currency).Scan(&foreignMoney); err != nil {
		return EmployeeSettings{}, nil, false, err
	}
	if foreignMoney {
		return EmployeeSettings{}, nil, false, ErrAllowanceCurrency
	}

	return cfg, amount, role != "platform_connector" && status == "active" && tenantStatus == "active", nil
}

func (s *Store) syncMonthlyWalletTx(ctx context.Context, tx pgx.Tx, wallet *Wallet, cfg EmployeeSettings, amount *int64, eligible bool, at time.Time) (*Wallet, error) {
	var err error
	if eligible {
		if _, err = tx.Exec(ctx, `UPDATE billing_wallets SET prepaid_configured=true WHERE tenant_id=$1 AND id=$2`, wallet.TenantID, wallet.ID); err != nil {
			return nil, err
		}
	}
	wallet, err = expireMonthlyGrantsTx(ctx, tx, wallet, at)
	if err != nil {
		return nil, err
	}
	if eligible && amount != nil && *amount > 0 {
		start, end, e := allowanceMonth(at, cfg.Timezone)
		if e != nil {
			return nil, e
		}
		var existing bool
		// Never resurrect an earlier month after a newer cycle has been synchronized.
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_wallet_monthly_grants WHERE tenant_id=$1 AND wallet_id=$2 AND month_start >= $3)`, wallet.TenantID, wallet.ID, start).Scan(&existing); err != nil {
			return nil, err
		}
		if !existing {
			balance, e := addMicros(wallet.BalanceMicros, Micros(*amount))
			if e != nil {
				return nil, e
			}
			grantID := "monthly_" + uuid.NewString()
			if _, err = tx.Exec(ctx, `INSERT INTO billing_wallet_monthly_grants(id,tenant_id,wallet_id,user_id,currency,month_start,month_end,timezone,amount_micros,remaining_micros) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, grantID, wallet.TenantID, wallet.ID, wallet.UserID, wallet.Currency, start, end, cfg.Timezone, *amount); err != nil {
				return nil, err
			}
			wallet, err = updateWallet(ctx, tx, wallet, WalletState{BalanceMicros: balance, ReservedMicros: wallet.ReservedMicros})
			if err != nil {
				return nil, err
			}
			if err = insertLedger(ctx, tx, ledgerInsert{TenantID: wallet.TenantID, WalletID: wallet.ID, EventType: "credit", BalanceDelta: Micros(*amount), BalanceAfter: wallet.BalanceMicros, ReservedAfter: wallet.ReservedMicros, IdempotencyKey: "monthly-grant:" + start.Format(time.RFC3339), ActorType: "system", Metadata: map[string]any{"monthly_wallet_event": "grant", "grant_id": grantID, "month_start": start, "month_end": end, "timezone": cfg.Timezone, "carryover": false}}); err != nil {
				return nil, err
			}
		}
	}
	return wallet, nil
}

// at remains an admission/tick compatibility argument. Monetary validity is
// always determined by fundingNow after the wallet lock, never caller time.
func (s *Store) EnsureMonthlyWalletGrant(ctx context.Context, tenantID, userID, currency string, at time.Time) (*Wallet, error) {
	if tenantID == "" || userID == "" || !currencyPattern.MatchString(currency) || at.IsZero() {
		return nil, ErrInvalidWalletState
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	cfg, amount, eligible, err := s.walletFundingContextTx(ctx, tx, tenantID, userID, currency)
	if err != nil {
		return nil, err
	}
	var wallet *Wallet
	if eligible {
		wallet, err = ensureWalletTx(ctx, tx, tenantID, userID, currency)
	} else {
		wallet, err = scanWallet(tx.QueryRow(ctx, `SELECT id,tenant_id,user_id,currency,balance_micros,reserved_micros,version,created_at,updated_at FROM billing_wallets WHERE tenant_id=$1 AND user_id=$2 AND currency=$3 FOR UPDATE`, tenantID, userID, currency))
		if errors.Is(err, pgx.ErrNoRows) {
			if e := tx.Commit(ctx); e != nil {
				return nil, e
			}
			return nil, nil
		}
	}
	if err != nil {
		return nil, err
	}
	wallet, err = getWalletForUpdate(ctx, tx, tenantID, wallet.ID)
	if err != nil {
		return nil, err
	}
	wallet, err = s.syncMonthlyWalletTx(ctx, tx, wallet, cfg, amount, eligible, s.fundingNow())
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return wallet, nil
}

// claimMonthlyWalletPage holds the durable cursor only while claiming a page.
// Money transactions happen after commit. Failed users remain pending but a
// bounded next call advances past them; restarts and multiple instances share
// traversal progress and wrap at most once per invocation.
func (s *Store) claimMonthlyWalletPage(ctx context.Context, at time.Time, limit int) ([]monthlyWalletTarget, bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO billing_wallet_monthly_worker_cursor(worker_name) VALUES('monthly-wallet') ON CONFLICT DO NOTHING`); err != nil {
		return nil, false, err
	}
	var tenantCursor, userCursor string
	if err = tx.QueryRow(ctx, `SELECT cursor_tenant_id,cursor_user_id FROM billing_wallet_monthly_worker_cursor WHERE worker_name='monthly-wallet' FOR UPDATE`).Scan(&tenantCursor, &userCursor); err != nil {
		return nil, false, err
	}
	at = s.fundingNow()
	query := `SELECT u.tenant_id,u.id FROM users u JOIN tenants t ON t.id=u.tenant_id LEFT JOIN billing_employee_settings c ON c.tenant_id=u.tenant_id LEFT JOIN billing_employee_allowances a ON a.tenant_id=u.tenant_id AND a.user_id=u.id
 WHERE t.status='active' AND (u.tenant_id,u.id)>($3,$4) AND (
 (u.status='active' AND u.role<>'platform_connector' AND COALESCE(a.monthly_micros,c.default_monthly_micros,0)>0
 AND NOT EXISTS(SELECT 1 FROM billing_wallet_monthly_grants g WHERE g.tenant_id=u.tenant_id AND g.user_id=u.id AND g.month_start >= (date_trunc('month',$1::timestamptz AT TIME ZONE COALESCE(c.timezone,'Asia/Shanghai')) AT TIME ZONE COALESCE(c.timezone,'Asia/Shanghai'))))
 OR EXISTS(SELECT 1 FROM billing_wallet_monthly_grants g WHERE g.tenant_id=u.tenant_id AND g.user_id=u.id AND g.month_end<=$1 AND (g.expired_at IS NULL OR g.remaining_micros>g.reserved_micros)))
 ORDER BY u.tenant_id,u.id LIMIT $2`
	items := []monthlyWalletTarget{}
	for attempt := 0; attempt < 2; attempt++ {
		rows, e := tx.Query(ctx, query, at, limit+1, tenantCursor, userCursor)
		if e != nil {
			return nil, false, e
		}
		for rows.Next() {
			var v monthlyWalletTarget
			if e = rows.Scan(&v.tenant, &v.user); e != nil {
				rows.Close()
				return nil, false, e
			}
			items = append(items, v)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, false, e
		}
		if len(items) > 0 || (tenantCursor == "" && userCursor == "") {
			break
		}
		tenantCursor, userCursor = "", ""
	}
	backlog := len(items) > limit
	if backlog {
		items = items[:limit]
	}
	if len(items) > 0 {
		tenantCursor, userCursor = items[len(items)-1].tenant, items[len(items)-1].user
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_wallet_monthly_worker_cursor SET cursor_tenant_id=$1,cursor_user_id=$2,updated_at=clock_timestamp() WHERE worker_name='monthly-wallet'`, tenantCursor, userCursor); err != nil {
		return nil, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return items, backlog, nil
}

type monthlyWalletTarget struct{ tenant, user string }

func (s *Store) GrantMonthlyWallets(ctx context.Context, at time.Time, limit int) (MonthlyWalletGrantResult, error) {
	out := MonthlyWalletGrantResult{}
	if at.IsZero() {
		return out, ErrInvalidUsage
	}
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	items, backlog, err := s.claimMonthlyWalletPage(ctx, at, limit)
	if err != nil {
		return out, err
	}
	out.Backlog = backlog
	for _, v := range items {
		out.Attempted++
		cfg, e := s.GetEmployeeSettings(ctx, v.tenant)
		if e != nil {
			out.Failed++
			continue
		}
		if _, e = s.EnsureMonthlyWalletGrant(ctx, v.tenant, v.user, cfg.Currency, at); e != nil {
			out.Failed++
		} else {
			out.Synchronized++
		}
	}
	if out.Failed > 0 {
		return out, fmt.Errorf("monthly wallet synchronization failed for %d users", out.Failed)
	}
	return out, nil
}

func (s *Store) MonthlyWalletStatus(ctx context.Context, tenantID, userID string, at time.Time) (*MonthlyWalletStatus, error) {
	cfg, err := s.GetEmployeeSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	w, err := s.EnsureMonthlyWalletGrant(ctx, tenantID, userID, cfg.Currency, at)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return nil, nil
	}
	start, end, err := allowanceMonth(s.fundingNow(), cfg.Timezone)
	if err != nil {
		return nil, err
	}
	out := &MonthlyWalletStatus{Currency: cfg.Currency, Timezone: cfg.Timezone, MonthStart: start, MonthEnd: end, ExpiresAt: end}
	if err = s.db.QueryRow(ctx, `SELECT COALESCE(a.monthly_micros,c.default_monthly_micros) FROM users u LEFT JOIN billing_employee_settings c ON c.tenant_id=u.tenant_id LEFT JOIN billing_employee_allowances a ON a.tenant_id=u.tenant_id AND a.user_id=u.id WHERE u.tenant_id=$1 AND u.id=$2`, tenantID, userID).Scan(&out.ConfiguredMicros); err != nil {
		return nil, err
	}
	err = s.db.QueryRow(ctx, `SELECT amount_micros,remaining_micros,reserved_micros,amount_micros-remaining_micros-expired_micros-adjusted_micros,expired_micros,adjusted_micros FROM billing_wallet_monthly_grants WHERE tenant_id=$1 AND wallet_id=$2 AND month_start=$3`, tenantID, w.ID, start).Scan(&out.GrantedMicros, &out.RemainingMicros, &out.ReservedMicros, &out.UsedMicros, &out.ExpiredMicros, &out.AdjustedMicros)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	return out, err
}

// All helpers below require the wallet row lock first. The original amount and
// admission allocations are immutable; only remaining/reserved/expired move.
func expireMonthlyGrantsTx(ctx context.Context, tx pgx.Tx, w *Wallet, at time.Time) (*Wallet, error) {
	rows, err := tx.Query(ctx, `SELECT id,remaining_micros-reserved_micros,expired_micros FROM billing_wallet_monthly_grants WHERE tenant_id=$1 AND wallet_id=$2 AND (month_end<=$3 OR expired_at IS NOT NULL) ORDER BY month_start,id FOR UPDATE`, w.TenantID, w.ID, at)
	if err != nil {
		return nil, err
	}
	type expiry struct {
		id            string
		amount, total int64
	}
	items := []expiry{}
	for rows.Next() {
		var v expiry
		if err = rows.Scan(&v.id, &v.amount, &v.total); err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, v := range items {
		if _, err = tx.Exec(ctx, `UPDATE billing_wallet_monthly_grants SET remaining_micros=remaining_micros-$3,expired_micros=expired_micros+$3,expired_at=COALESCE(expired_at,$4),updated_at=NOW() WHERE tenant_id=$1 AND id=$2`, w.TenantID, v.id, v.amount, at); err != nil {
			return nil, err
		}
		if v.amount == 0 {
			continue
		}
		balance, e := addMicros(w.BalanceMicros, -Micros(v.amount))
		if e != nil {
			return nil, e
		}
		w, err = updateWallet(ctx, tx, w, WalletState{BalanceMicros: balance, ReservedMicros: w.ReservedMicros})
		if err != nil {
			return nil, err
		}
		if err = insertLedger(ctx, tx, ledgerInsert{TenantID: w.TenantID, WalletID: w.ID, EventType: "adjustment", BalanceDelta: -Micros(v.amount), BalanceAfter: w.BalanceMicros, ReservedAfter: w.ReservedMicros, IdempotencyKey: fmt.Sprintf("monthly-expire:%s:%d", v.id, v.total+v.amount), ActorType: "system", Metadata: map[string]any{"monthly_wallet_event": "expire", "grant_id": v.id, "expired_micros": v.amount}}); err != nil {
			return nil, err
		}
	}
	return w, nil
}

func reserveMonthlyGrantTx(ctx context.Context, tx pgx.Tx, w *Wallet, r *Reservation, at time.Time) (Micros, error) {
	left := r.ReservedMicros
	used := Micros(0)
	rows, err := tx.Query(ctx, `SELECT id,remaining_micros-reserved_micros FROM billing_wallet_monthly_grants WHERE tenant_id=$1 AND wallet_id=$2 AND expired_at IS NULL AND month_start<=$3 AND month_end>$3 AND remaining_micros>reserved_micros ORDER BY month_start,id FOR UPDATE`, w.TenantID, w.ID, at)
	if err != nil {
		return 0, err
	}
	type lot struct {
		id        string
		available Micros
	}
	items := []lot{}
	for rows.Next() {
		var v lot
		if err = rows.Scan(&v.id, &v.available); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for index, v := range items {
		// Preserve the original gift source even when the price rounds the
		// quote to zero and only token units are frozen. Legacy rows have none.
		if left <= 0 && !(r.ReservedMicros == 0 && index == 0) {
			break
		}
		take := v.available
		if take > left {
			take = left
		}
		if _, err = tx.Exec(ctx, `UPDATE billing_wallet_monthly_grants SET reserved_micros=reserved_micros+$3,updated_at=NOW() WHERE tenant_id=$1 AND id=$2`, w.TenantID, v.id, take); err != nil {
			return 0, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO billing_wallet_monthly_allocations(tenant_id,wallet_id,reservation_id,grant_id,amount_micros) VALUES($1,$2,$3,$4,$5)`, w.TenantID, w.ID, r.ID, v.id, take); err != nil {
			return 0, err
		}
		left -= take
		used += take
	}
	return used, nil
}

func consumeMonthlyAllocationTx(ctx context.Context, tx pgx.Tx, w *Wallet, r *Reservation, actual Micros, at time.Time) (Micros, error) {
	rows, err := tx.Query(ctx, `SELECT g.id,a.amount_micros,g.remaining_micros,g.reserved_micros,g.expired_at IS NOT NULL OR g.month_end<=$4 FROM billing_wallet_monthly_allocations a JOIN billing_wallet_monthly_grants g ON g.id=a.grant_id AND g.tenant_id=a.tenant_id AND g.wallet_id=a.wallet_id WHERE a.tenant_id=$1 AND a.wallet_id=$2 AND a.reservation_id=$3 ORDER BY g.month_start,g.id FOR UPDATE OF g`, w.TenantID, w.ID, r.ID, at)
	if err != nil {
		return 0, err
	}
	type allocation struct {
		id                          string
		amount, remaining, reserved Micros
		expired                     bool
	}
	items := []allocation{}
	for rows.Next() {
		var v allocation
		if err = rows.Scan(&v.id, &v.amount, &v.remaining, &v.reserved, &v.expired); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	left := actual
	used := Micros(0)
	for _, v := range items {
		take := v.amount
		if take > left {
			take = left
		}
		left -= take
		// A same-period underestimate can use that period's still-unreserved gift.
		// An old request may never use a newer month's gift, nor a legacy request
		// with no admission allocation acquire gift money retrospectively.
		if left > 0 && !v.expired {
			extra := v.remaining - v.reserved
			if extra > left {
				extra = left
			}
			take += extra
			left -= extra
		}
		if _, err = tx.Exec(ctx, `UPDATE billing_wallet_monthly_grants SET reserved_micros=reserved_micros-$3,remaining_micros=remaining_micros-$4,updated_at=NOW() WHERE tenant_id=$1 AND id=$2`, w.TenantID, v.id, v.amount, take); err != nil {
			return 0, err
		}
		used += take
	}
	return used, nil
}

func settleWalletFundingTx(ctx context.Context, tx pgx.Tx, w *Wallet, r *Reservation, actual Micros, estimated bool, at time.Time) (*Wallet, error) {
	before := WalletState{BalanceMicros: w.BalanceMicros, ReservedMicros: w.ReservedMicros}
	next := before
	var err error
	if r.ReservedMicros > 0 {
		next, err = before.Settle(r.ReservedMicros, actual)
	} else {
		next.BalanceMicros, err = addMicros(before.BalanceMicros, -actual)
	}
	if err != nil {
		return nil, err
	}
	gift, err := consumeMonthlyAllocationTx(ctx, tx, w, r, actual, at)
	if err != nil {
		return nil, err
	}
	w, err = updateWallet(ctx, tx, w, next)
	if err != nil {
		return nil, err
	}
	metadata := withEstimatedLedgerMetadata(OverdraftLedgerMetadata(before, next), estimated)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["monthly_grant_consumed_micros"] = gift
	metadata["permanent_consumed_micros"] = actual - gift
	if err = insertLedger(ctx, tx, ledgerInsert{TenantID: w.TenantID, WalletID: w.ID, ReservationID: r.ID, RequestID: r.RequestID, EventType: "settle", BalanceDelta: -actual, ReservedDelta: -r.ReservedMicros, BalanceAfter: w.BalanceMicros, ReservedAfter: w.ReservedMicros, IdempotencyKey: "settle:" + r.RequestID, ActorType: "gateway", Metadata: metadata}); err != nil {
		return nil, err
	}
	return expireMonthlyGrantsTx(ctx, tx, w, at)
}

func releaseWalletFundingTx(ctx context.Context, tx pgx.Tx, w *Wallet, r *Reservation, at time.Time) (*Wallet, error) {
	next := WalletState{BalanceMicros: w.BalanceMicros, ReservedMicros: w.ReservedMicros}
	var err error
	if r.ReservedMicros > 0 {
		next, err = next.Release(r.ReservedMicros)
		if err != nil {
			return nil, err
		}
	}
	gift, err := consumeMonthlyAllocationTx(ctx, tx, w, r, 0, at)
	if err != nil {
		return nil, err
	}
	w, err = updateWallet(ctx, tx, w, next)
	if err != nil {
		return nil, err
	}
	if err = insertLedger(ctx, tx, ledgerInsert{TenantID: w.TenantID, WalletID: w.ID, ReservationID: r.ID, RequestID: r.RequestID, EventType: "release", ReservedDelta: -r.ReservedMicros, BalanceAfter: w.BalanceMicros, ReservedAfter: w.ReservedMicros, IdempotencyKey: "release:" + r.RequestID, ActorType: "gateway", Metadata: map[string]any{"monthly_grant_consumed_micros": gift}}); err != nil {
		return nil, err
	}
	return expireMonthlyGrantsTx(ctx, tx, w, at)
}

// Re-read the mutable reservation after acquiring the immutable owner's wallet
// lock. Every reserve/settle/release/rollover uses wallet-first ordering.
func lockWalletReservation(ctx context.Context, tx pgx.Tx, tenantID, requestID string) (*Wallet, *Reservation, error) {
	r, err := getReservation(ctx, tx, tenantID, requestID, false)
	if err != nil {
		return nil, nil, err
	}
	w, err := getWalletForUpdate(ctx, tx, tenantID, r.WalletID)
	if err != nil {
		return nil, nil, err
	}
	r, err = getReservation(ctx, tx, tenantID, requestID, true)
	if err != nil {
		return nil, nil, err
	}
	if r.WalletID != w.ID {
		return nil, nil, ErrIdempotencyConflict
	}
	return w, r, nil
}

// A negative operator correction consumes only unfrozen gift money first.
// It is recorded as a correction, not customer usage or monthly expiration.
func adjustMonthlyGrantTx(ctx context.Context, tx pgx.Tx, w *Wallet, amount Micros, at time.Time) (Micros, error) {
	if amount <= 0 {
		return 0, nil
	}
	rows, err := tx.Query(ctx, `SELECT id,remaining_micros-reserved_micros FROM billing_wallet_monthly_grants WHERE tenant_id=$1 AND wallet_id=$2 AND expired_at IS NULL AND month_start<=$3 AND month_end>$3 AND remaining_micros>reserved_micros ORDER BY month_start,id FOR UPDATE`, w.TenantID, w.ID, at)
	if err != nil {
		return 0, err
	}
	type gift struct {
		id        string
		available Micros
	}
	gifts := []gift{}
	for rows.Next() {
		var v gift
		if err = rows.Scan(&v.id, &v.available); err != nil {
			rows.Close()
			return 0, err
		}
		gifts = append(gifts, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	left := amount
	used := Micros(0)
	for _, v := range gifts {
		if left <= 0 {
			break
		}
		take := v.available
		if take > left {
			take = left
		}
		if _, err = tx.Exec(ctx, `UPDATE billing_wallet_monthly_grants SET remaining_micros=remaining_micros-$3,adjusted_micros=adjusted_micros+$3,updated_at=NOW() WHERE tenant_id=$1 AND id=$2`, w.TenantID, v.id, take); err != nil {
			return 0, err
		}
		used += take
		left -= take
	}
	return used, nil
}
