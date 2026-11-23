package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrAllowanceExhausted = errors.New("monthly employee allowance exhausted")

// AllowanceExhaustedError 在 ErrAllowanceExhausted 之上携带“哪位员工、用了多少、何时重置”，
// 供预算断流开启时生成中文提示；errors.Is(err, ErrAllowanceExhausted) 仍然成立。
type AllowanceExhaustedError struct {
	UserID, Username, DepartmentName, Currency, Timezone     string
	LimitMicros, UsedMicros, ReservedMicros, RequestedMicros int64
	MonthStart, MonthEnd                                     time.Time
}

func (e *AllowanceExhaustedError) Error() string { return ErrAllowanceExhausted.Error() }
func (e *AllowanceExhaustedError) Unwrap() error { return ErrAllowanceExhausted }

var ErrAllowanceCurrency = errors.New("employee allowance and model price currencies differ")

type EmployeeSettings struct {
	Currency             string `json:"currency"`
	Timezone             string `json:"timezone"`
	DefaultMonthlyMicros *int64 `json:"default_monthly_micros"`
}

type EmployeeAllowance struct {
	UserID          string               `json:"user_id"`
	Username        string               `json:"username"`
	DepartmentName  string               `json:"department_name"`
	MonthlyMicros   *int64               `json:"monthly_micros"`
	EffectiveMicros *int64               `json:"effective_micros"`
	UsedMicros      int64                `json:"used_micros"`
	ReservedMicros  int64                `json:"reserved_micros"`
	Currency        string               `json:"currency"`
	MonthStart      time.Time            `json:"month_start"`
	MonthEnd        time.Time            `json:"month_end"`
	MonthlyStatus   *MonthlyWalletStatus `json:"monthly_status"`
}

func validateEmployeeSettings(v EmployeeSettings) error {
	if v.Currency != "CNY" && v.Currency != "USD" {
		return ErrInvalidPrice
	}
	if _, err := time.LoadLocation(v.Timezone); err != nil {
		return fmt.Errorf("%w: invalid allowance timezone: %v", ErrInvalidPrice, err)
	}
	if v.DefaultMonthlyMicros != nil && (*v.DefaultMonthlyMicros < 0 || *v.DefaultMonthlyMicros > 1_000_000_000_000_000) {
		return ErrInvalidPrice
	}
	return nil
}

func allowanceMonth(at time.Time, timezone string) (time.Time, time.Time, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	local := at.In(loc)
	start := time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, loc)
	return start.UTC(), start.AddDate(0, 1, 0).UTC(), nil
}

func (s *Store) GetEmployeeSettings(ctx context.Context, tenantID string) (EmployeeSettings, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return EmployeeSettings{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, "allowance-settings:"+tenantID); err != nil {
		return EmployeeSettings{}, err
	}
	cfg, err := s.employeeSettings(ctx, tx, tenantID)
	if err != nil {
		return EmployeeSettings{}, err
	}
	cfg.Currency, err = s.billingCurrencyForTenant(ctx, tx, tenantID)
	if err != nil {
		return EmployeeSettings{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return EmployeeSettings{}, err
	}
	return cfg, nil
}

type employeeSettingsQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Store) employeeSettings(ctx context.Context, q employeeSettingsQuerier, tenantID string) (EmployeeSettings, error) {
	result := EmployeeSettings{Currency: s.DefaultCurrency(), Timezone: "Asia/Shanghai"}
	err := q.QueryRow(ctx, `SELECT currency,timezone,default_monthly_micros FROM billing_employee_settings WHERE tenant_id=$1`, tenantID).Scan(&result.Currency, &result.Timezone, &result.DefaultMonthlyMicros)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	}
	return result, err
}

func (s *Store) SaveEmployeeSettings(ctx context.Context, tenantID string, v EmployeeSettings) error {
	if err := validateEmployeeSettings(v); err != nil {
		return err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "allowance-settings:"+tenantID); err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)`, tenantID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrInvalidUsage
	}
	var currencyConflict bool
	if err = tx.QueryRow(ctx, `WITH current_prices AS (SELECT DISTINCT ON(model_name) currency FROM billing_model_prices WHERE tenant_id=$1 AND customer_group='default' AND status='active' AND effective_at<=NOW() AND (expires_at IS NULL OR expires_at>NOW()) ORDER BY model_name,effective_at DESC,version DESC) SELECT EXISTS(SELECT 1 FROM current_prices WHERE currency<>$2) OR EXISTS(SELECT 1 FROM billing_upstream_rates WHERE tenant_id=$1 AND currency<>$2) OR EXISTS(SELECT 1 FROM billing_channel_fixed_costs WHERE tenant_id=$1 AND currency<>$2)`, tenantID, v.Currency).Scan(&currencyConflict); err != nil {
		return err
	}
	if currencyConflict {
		return ErrAllowanceCurrency
	}
	old, err := s.employeeSettings(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	old.Currency, err = s.billingCurrencyForTenant(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if old.Currency != v.Currency {
		var fundedCurrencyConflict bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_wallets w WHERE w.tenant_id=$1 AND w.currency<>$2 AND `+fundedWalletPredicate+`)`, tenantID, v.Currency).Scan(&fundedCurrencyConflict); err != nil {
			return err
		}
		if fundedCurrencyConflict {
			return ErrAllowanceCurrency
		}
	}
	if old.Currency != v.Currency || old.Timezone != v.Timezone {
		var cycleIssued bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_wallet_monthly_grants WHERE tenant_id=$1 AND month_start<=NOW() AND month_end>NOW())`, tenantID).Scan(&cycleIssued); err != nil {
			return err
		}
		if cycleIssued {
			return fmt.Errorf("%w: current monthly wallet funding fixes the denomination and calendar", ErrAllowanceCurrency)
		}

		// Freeze denomination while any allowance is enabled or a current-period
		// request remains in flight. Settled facts and expired holds stay durable
		// but no longer consume a live allowance or freeze future configuration.
		var active bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_employee_reservations r WHERE r.tenant_id=$1 AND r.month_end>NOW() AND NOT EXISTS(SELECT 1 FROM billing_usage_facts f WHERE f.tenant_id=r.tenant_id AND f.request_id=r.request_id)) OR EXISTS(SELECT 1 FROM billing_employee_allowances WHERE tenant_id=$1 AND monthly_micros>0)`, tenantID).Scan(&active)
		if err != nil {
			return err
		}
		if active || (old.DefaultMonthlyMicros != nil && *old.DefaultMonthlyMicros > 0) {
			return ErrAllowanceCurrency
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_employee_settings(tenant_id,currency,timezone,default_monthly_micros) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id) DO UPDATE SET currency=EXCLUDED.currency,timezone=EXCLUDED.timezone,default_monthly_micros=EXCLUDED.default_monthly_micros,updated_at=NOW()`, tenantID, v.Currency, v.Timezone, v.DefaultMonthlyMicros)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) SetEmployeeAllowances(ctx context.Context, tenantID string, userIDs []string, amount *int64) error {
	if len(userIDs) == 0 || len(userIDs) > 500 || (amount != nil && (*amount < 0 || *amount > 1_000_000_000_000_000)) {
		return ErrInvalidUsage
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Coordinate individual overrides with denomination changes and admissions.
	// This exclusive lock pairs with the shared settings lock used by readers.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "allowance-settings:"+tenantID); err != nil {
		return err
	}
	for _, userID := range userIDs {
		var owned bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$2 AND tenant_id=$1)`, tenantID, userID).Scan(&owned); err != nil {
			return err
		}
		if !owned {
			return ErrInvalidWalletState
		}
		if _, err = tx.Exec(ctx, `INSERT INTO billing_employee_allowances(tenant_id,user_id,monthly_micros) VALUES($1,$2,$3) ON CONFLICT(tenant_id,user_id) DO UPDATE SET monthly_micros=EXCLUDED.monthly_micros,updated_at=NOW()`, tenantID, userID, amount); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// HasEmployeeAllowance is retained as the fail-closed money-subject signal.
// Every human user has a wallet, including users with automatic funding off.
func (s *Store) HasEmployeeAllowance(ctx context.Context, tenantID, userID string) (bool, error) {
	if userID == "" {
		return false, nil
	}
	var funded bool
	err := s.db.QueryRow(ctx, `SELECT u.role<>'platform_connector' OR EXISTS(SELECT 1 FROM billing_wallets w WHERE w.tenant_id=u.tenant_id AND w.user_id=u.id AND (w.prepaid_configured OR w.balance_micros<>0)) FROM users u WHERE u.tenant_id=$1 AND u.id=$2`, tenantID, userID).Scan(&funded)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return funded, err
}

// ReserveEmployeeAllowance is a compatibility funding guard. Monthly settings
// credit a wallet; settled history is never a separate hard monthly quota.
// The actual request freezes money once, in ReservePricedWithUsage... .
func (s *Store) ReserveEmployeeAllowance(ctx context.Context, tenantID, userID, requestID, currency string, amount int64, at time.Time) error {
	if userID == "" {
		return nil
	}
	if requestID == "" || amount < 0 {
		return ErrInvalidUsage
	}
	wallet, err := s.EnsureMonthlyWalletGrant(ctx, tenantID, userID, currency, at)
	if err != nil {
		return err
	}
	if existing, e := s.GetReservation(ctx, tenantID, requestID); e == nil {
		if wallet == nil || existing.WalletID != wallet.ID || int64(existing.ReservedMicros) != amount {
			return ErrIdempotencyConflict
		}
		return nil
	} else if !errors.Is(e, ErrReservationNotFound) {
		return e
	}
	if wallet != nil && (wallet.AvailableMicros() <= 0 || Micros(amount) > wallet.AvailableMicros()) {
		return ErrInsufficientBalance
	}
	return nil
}

func (s *Store) ReleaseEmployeeAllowance(ctx context.Context, tenantID, requestID string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM billing_employee_reservations WHERE tenant_id=$1 AND request_id=$2`, tenantID, requestID)
	return err
}

func (s *Store) ListEmployeeAllowances(ctx context.Context, tenantID string, at time.Time) ([]EmployeeAllowance, error) {
	cfg, err := s.GetEmployeeSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	start, end, err := allowanceMonth(at, cfg.Timezone)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT u.id,u.username,COALESCE(t.name,''),a.monthly_micros,COALESCE(a.monthly_micros,c.default_monthly_micros),
 COALESCE((SELECT SUM(f.billable_amount_micros) FROM billing_usage_facts f WHERE f.tenant_id=u.tenant_id AND f.user_id=u.id AND f.currency=$2 AND f.status='settled' AND f.usage_source NOT IN ('forward_proxy','reverse_proxy') AND COALESCE(f.admitted_at,f.occurred_at)>=$3 AND COALESCE(f.admitted_at,f.occurred_at)<$4),0)::bigint,
 COALESCE((SELECT SUM(r.amount_micros) FROM billing_employee_reservations r WHERE r.tenant_id=u.tenant_id AND r.user_id=u.id AND r.month_start=$3 AND NOT EXISTS(SELECT 1 FROM billing_usage_facts f WHERE f.tenant_id=r.tenant_id AND f.request_id=r.request_id)),0)::bigint
 FROM users u LEFT JOIN teams t ON t.id=u.department_id AND t.tenant_id=u.tenant_id LEFT JOIN billing_employee_settings c ON c.tenant_id=u.tenant_id LEFT JOIN billing_employee_allowances a ON a.tenant_id=u.tenant_id AND a.user_id=u.id WHERE u.tenant_id=$1 AND u.role<>'platform_connector' AND u.status NOT IN ('deleted','retired') ORDER BY u.username LIMIT 500`, tenantID, cfg.Currency, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []EmployeeAllowance{}
	for rows.Next() {
		var item EmployeeAllowance
		if err = rows.Scan(&item.UserID, &item.Username, &item.DepartmentName, &item.MonthlyMicros, &item.EffectiveMicros, &item.UsedMicros, &item.ReservedMicros); err != nil {
			return nil, err
		}
		item.Currency = cfg.Currency
		item.MonthStart = start
		item.MonthEnd = end
		result = append(result, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for i := range result {
		result[i].MonthlyStatus, err = s.MonthlyWalletStatus(ctx, tenantID, result[i].UserID, at)
		if err != nil {
			return nil, err
		}
		if w, e := s.GetWalletByUser(ctx, tenantID, result[i].UserID, cfg.Currency); e == nil {
			result[i].ReservedMicros = int64(w.ReservedMicros)
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return nil, e
		}
	}
	return result, nil
}

// EmployeeReservationPruneResult 是一轮过期预占清理的结果。
type EmployeeReservationPruneResult struct {
	Deleted int64
	// Backlog 表示本轮删满了批量上限，可能还有残留，等下一轮继续。
	Backlog bool
	// ByTenant 是各租户被释放的预占数，用于产生“预占泄漏清理”告警。
	ByTenant map[string]int64
}

// PruneStaleEmployeeReservations 删除超过 maxAge（最大请求时长 + 5 分钟）且没有对应 usage fact 的员工额度预占。
// 预占的 TTL 之前不存在：gateway finalize 失败（崩溃、网络分区）会把额度永久占住，直到下个月重置。
// 已有 fact 的预占不删（fact 已经替代它计入已用）；未过期的不动。幂等，单次最多删 limit 条。
func (s *Store) PruneStaleEmployeeReservations(ctx context.Context, maxAge time.Duration, now time.Time, limit int) (EmployeeReservationPruneResult, error) {
	result := EmployeeReservationPruneResult{}
	if s == nil || s.db == nil {
		return result, errors.New("billing store is not initialized")
	}
	if maxAge <= 0 {
		return result, errors.New("employee reservation max age must be positive")
	}
	if limit <= 0 {
		limit = 500
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// 用 MATERIALIZED CTE 固定“先选出至多 limit 条再删除”：直接写 IN (子查询 LIMIT) 会被规划器展开成半连接，
	// 让 LIMIT 失效、一次删光。
	rows, err := s.db.Query(ctx, `
		WITH doomed AS MATERIALIZED (
		  SELECT s.tenant_id, s.request_id
		  FROM billing_employee_reservations s
		  WHERE s.created_at < $1
		    AND NOT EXISTS (
		      SELECT 1 FROM billing_usage_facts f
		      WHERE f.tenant_id = s.tenant_id AND f.request_id = s.request_id
		    )
		  ORDER BY s.created_at
		  LIMIT $2
		  FOR UPDATE SKIP LOCKED
		)
		DELETE FROM billing_employee_reservations r
		USING doomed d
		WHERE r.tenant_id = d.tenant_id AND r.request_id = d.request_id
		RETURNING r.tenant_id
	`, now.Add(-maxAge), limit)
	if err != nil {
		return result, fmt.Errorf("prune stale employee reservations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return result, fmt.Errorf("prune stale employee reservations: %w", err)
		}
		if result.ByTenant == nil {
			result.ByTenant = map[string]int64{}
		}
		result.ByTenant[tenantID]++
		result.Deleted++
	}
	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("prune stale employee reservations: %w", err)
	}
	result.Backlog = result.Deleted >= int64(limit)
	return result, nil
}
