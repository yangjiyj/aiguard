package billing

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrCustomerLimitExceeded            = errors.New("customer billing limit exceeded")
	ErrCustomerRPMLimitExceeded         = errors.New("customer rpm limit exceeded")
	ErrCustomerConcurrencyLimitExceeded = errors.New("customer concurrency limit exceeded")
	ErrInvalidCustomerLimit             = errors.New("invalid customer billing limit")
)

const (
	defaultBillingRequestLeaseTTL = 35 * time.Minute
	requestLeaseCleanupBatchSize  = 1000
)

const customerRequestLeaseCountsSQL = `
	SELECT
		(
			SELECT COUNT(*)
			FROM billing_request_leases
			WHERE tenant_id = $1 AND user_id = $2 AND acquired_at >= $3
		),
		(
			SELECT COUNT(*)
			FROM billing_request_leases
			WHERE tenant_id = $1 AND user_id = $2
			  AND released_at IS NULL AND expires_at > $4
		)
`

// CustomerLimits are customer-managed hard caps. A zero field is unset.
type CustomerLimits struct {
	DailyAmountMicros   Micros     `json:"daily_amount_micros"`
	MonthlyAmountMicros Micros     `json:"monthly_amount_micros"`
	DailyTokenLimit     int64      `json:"daily_token_limit"`
	MonthlyTokenLimit   int64      `json:"monthly_token_limit"`
	RPMLimit            int64      `json:"rpm_limit"`
	ConcurrencyLimit    int64      `json:"concurrency_limit"`
	UpdatedAt           *time.Time `json:"updated_at,omitempty"`
}

type CustomerLimitWindow struct {
	AmountLimitMicros    Micros `json:"amount_limit_micros"`
	TokenLimit           int64  `json:"token_limit"`
	SettledAmountMicros  Micros `json:"settled_amount_micros"`
	ReservedAmountMicros Micros `json:"reserved_amount_micros"`
	SettledTokens        int64  `json:"settled_tokens"`
	ReservedTokens       int64  `json:"reserved_tokens"`
}

func (w CustomerLimitWindow) UsedAmountMicros() Micros {
	return w.SettledAmountMicros + w.ReservedAmountMicros
}

func (w CustomerLimitWindow) UsedTokens() int64 {
	return w.SettledTokens + w.ReservedTokens
}

func (w CustomerLimitWindow) RemainingAmountMicros() Micros {
	if w.AmountLimitMicros <= 0 {
		return 0
	}
	value := w.AmountLimitMicros - w.UsedAmountMicros()
	if value < 0 {
		return 0
	}
	return value
}

func (w CustomerLimitWindow) RemainingTokens() int64 {
	if w.TokenLimit <= 0 {
		return 0
	}
	value := w.TokenLimit - w.UsedTokens()
	if value < 0 {
		return 0
	}
	return value
}

type CustomerLimitSummary struct {
	Daily            CustomerLimitWindow `json:"daily"`
	Monthly          CustomerLimitWindow `json:"monthly"`
	RPMLimit         int64               `json:"rpm_limit"`
	ConcurrencyLimit int64               `json:"concurrency_limit"`
}

type usageLimitCounter struct {
	SettledAmountMicros  Micros
	ReservedAmountMicros Micros
	SettledTokens        int64
	ReservedTokens       int64
}

func UsageTotalTokens(usage Usage) (int64, error) {
	if err := validateUsage(usage); err != nil {
		return 0, err
	}
	if usage.PromptTokens > math.MaxInt64-usage.OutputTokens {
		return 0, ErrAmountOverflow
	}
	return usage.PromptTokens + usage.OutputTokens, nil
}

func (s *Store) SetCustomerLimits(ctx context.Context, tenantID, userID string, input CustomerLimits) (*CustomerLimits, error) {
	if tenantID == "" || userID == "" || input.DailyAmountMicros < 0 || input.MonthlyAmountMicros < 0 ||
		input.DailyTokenLimit < 0 || input.MonthlyTokenLimit < 0 || input.RPMLimit < 0 || input.ConcurrencyLimit < 0 {
		return nil, ErrInvalidCustomerLimit
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin set customer billing limits: %w", err)
	}
	defer tx.Rollback(ctx)
	result := &CustomerLimits{}
	err = tx.QueryRow(ctx, `
		INSERT INTO billing_customer_limits (
			tenant_id, user_id, daily_amount_micros, monthly_amount_micros, daily_token_limit, monthly_token_limit,
			rpm_limit, concurrency_limit
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET
			daily_amount_micros=EXCLUDED.daily_amount_micros,
			monthly_amount_micros=EXCLUDED.monthly_amount_micros,
			daily_token_limit=EXCLUDED.daily_token_limit,
			monthly_token_limit=EXCLUDED.monthly_token_limit,
			rpm_limit=EXCLUDED.rpm_limit,
			concurrency_limit=EXCLUDED.concurrency_limit,
			updated_at=NOW()
		RETURNING daily_amount_micros, monthly_amount_micros, daily_token_limit, monthly_token_limit,
			rpm_limit, concurrency_limit, updated_at
	`, tenantID, userID, input.DailyAmountMicros, input.MonthlyAmountMicros, input.DailyTokenLimit, input.MonthlyTokenLimit,
		input.RPMLimit, input.ConcurrencyLimit).Scan(
		&result.DailyAmountMicros, &result.MonthlyAmountMicros, &result.DailyTokenLimit, &result.MonthlyTokenLimit,
		&result.RPMLimit, &result.ConcurrencyLimit, &result.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("set customer billing limits: %w", err)
	}
	if input.RPMLimit == 0 && input.ConcurrencyLimit == 0 {
		if _, err := tx.Exec(ctx, `
			DELETE FROM billing_request_leases WHERE tenant_id=$1 AND user_id=$2
		`, tenantID, userID); err != nil {
			return nil, fmt.Errorf("clear disabled customer request limits: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit customer billing limits: %w", err)
	}
	return result, nil
}

func (s *Store) GetCustomerLimitSummary(ctx context.Context, tenantID, userID string, at time.Time) (CustomerLimitSummary, error) {
	if tenantID == "" || userID == "" {
		return CustomerLimitSummary{}, ErrInvalidCustomerLimit
	}
	limits, _, err := s.getCustomerLimits(ctx, tenantID, userID)
	if err != nil {
		return CustomerLimitSummary{}, err
	}
	dailyDate, monthlyDate := billingPeriodDates(at)
	daily, err := s.getLimitCounter(ctx, tenantID, userID, "daily", dailyDate)
	if err != nil {
		return CustomerLimitSummary{}, err
	}
	monthly, err := s.getLimitCounter(ctx, tenantID, userID, "monthly", monthlyDate)
	if err != nil {
		return CustomerLimitSummary{}, err
	}
	return CustomerLimitSummary{
		Daily: CustomerLimitWindow{
			AmountLimitMicros: limits.DailyAmountMicros, TokenLimit: limits.DailyTokenLimit,
			SettledAmountMicros: daily.SettledAmountMicros, ReservedAmountMicros: daily.ReservedAmountMicros,
			SettledTokens: daily.SettledTokens, ReservedTokens: daily.ReservedTokens,
		},
		Monthly: CustomerLimitWindow{
			AmountLimitMicros: limits.MonthlyAmountMicros, TokenLimit: limits.MonthlyTokenLimit,
			SettledAmountMicros: monthly.SettledAmountMicros, ReservedAmountMicros: monthly.ReservedAmountMicros,
			SettledTokens: monthly.SettledTokens, ReservedTokens: monthly.ReservedTokens,
		},
		RPMLimit: limits.RPMLimit, ConcurrencyLimit: limits.ConcurrencyLimit,
	}, nil
}

func (s *Store) getCustomerLimits(ctx context.Context, tenantID, userID string) (CustomerLimits, bool, error) {
	limits := CustomerLimits{}
	err := s.db.QueryRow(ctx, `
		SELECT daily_amount_micros, monthly_amount_micros, daily_token_limit, monthly_token_limit,
			rpm_limit, concurrency_limit, updated_at
		FROM billing_customer_limits WHERE tenant_id=$1 AND user_id=$2
	`, tenantID, userID).Scan(&limits.DailyAmountMicros, &limits.MonthlyAmountMicros,
		&limits.DailyTokenLimit, &limits.MonthlyTokenLimit, &limits.RPMLimit, &limits.ConcurrencyLimit, &limits.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return CustomerLimits{}, false, nil
	}
	if err != nil {
		return CustomerLimits{}, false, fmt.Errorf("get customer billing limits: %w", err)
	}
	return limits, true, nil
}

func (s *Store) getLimitCounter(ctx context.Context, tenantID, userID, kind, start string) (usageLimitCounter, error) {
	counter := usageLimitCounter{}
	err := s.db.QueryRow(ctx, `
		SELECT settled_amount_micros, reserved_amount_micros, settled_tokens, reserved_tokens
		FROM billing_limit_counters WHERE tenant_id=$1 AND user_id=$2 AND period_kind=$3 AND period_start=$4::date
	`, tenantID, userID, kind, start).Scan(&counter.SettledAmountMicros, &counter.ReservedAmountMicros, &counter.SettledTokens, &counter.ReservedTokens)
	if errors.Is(err, pgx.ErrNoRows) {
		return usageLimitCounter{}, nil
	}
	if err != nil {
		return usageLimitCounter{}, fmt.Errorf("get billing limit counter: %w", err)
	}
	return counter, nil
}

func billingPeriodDates(at time.Time) (string, string) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	zone := billingTimeZone()
	loc, err := time.LoadLocation(zone)
	if err != nil {
		loc = time.FixedZone("Asia/Shanghai", 8*60*60)
	}
	local := at.In(loc)
	return local.Format("2006-01-02"), time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, loc).Format("2006-01-02")
}

func billingTimeZone() string {
	value := os.Getenv("BILLING_TIMEZONE")
	if value == "" {
		return "Asia/Shanghai"
	}
	if _, err := time.LoadLocation(value); err != nil {
		return "Asia/Shanghai"
	}
	return value
}

func getCustomerLimitsForUpdate(ctx context.Context, tx pgx.Tx, tenantID, userID string) (CustomerLimits, bool, error) {
	limits := CustomerLimits{}
	err := tx.QueryRow(ctx, `
		SELECT daily_amount_micros, monthly_amount_micros, daily_token_limit, monthly_token_limit,
			rpm_limit, concurrency_limit, updated_at
		FROM billing_customer_limits WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE
	`, tenantID, userID).Scan(&limits.DailyAmountMicros, &limits.MonthlyAmountMicros,
		&limits.DailyTokenLimit, &limits.MonthlyTokenLimit, &limits.RPMLimit, &limits.ConcurrencyLimit, &limits.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return CustomerLimits{}, false, nil
	}
	if err != nil {
		return CustomerLimits{}, false, fmt.Errorf("lock customer billing limits: %w", err)
	}
	return limits, true, nil
}

func getLimitCounterForUpdate(ctx context.Context, tx pgx.Tx, tenantID, userID, kind, start string) (usageLimitCounter, error) {
	if _, err := tx.Exec(ctx, `
		INSERT INTO billing_limit_counters (tenant_id, user_id, period_kind, period_start)
		VALUES ($1,$2,$3,$4::date) ON CONFLICT DO NOTHING
	`, tenantID, userID, kind, start); err != nil {
		return usageLimitCounter{}, fmt.Errorf("ensure billing limit counter: %w", err)
	}
	counter := usageLimitCounter{}
	err := tx.QueryRow(ctx, `
		SELECT settled_amount_micros, reserved_amount_micros, settled_tokens, reserved_tokens
		FROM billing_limit_counters WHERE tenant_id=$1 AND user_id=$2 AND period_kind=$3 AND period_start=$4::date FOR UPDATE
	`, tenantID, userID, kind, start).Scan(&counter.SettledAmountMicros, &counter.ReservedAmountMicros, &counter.SettledTokens, &counter.ReservedTokens)
	if err != nil {
		return usageLimitCounter{}, fmt.Errorf("lock billing limit counter: %w", err)
	}
	return counter, nil
}

func limitWouldExceed(counter usageLimitCounter, amount Micros, tokens int64, amountLimit Micros, tokenLimit int64) (bool, error) {
	total, err := addMicros(counter.SettledAmountMicros, counter.ReservedAmountMicros, amount)
	if err != nil {
		return false, err
	}
	if counter.SettledTokens > math.MaxInt64-counter.ReservedTokens ||
		counter.SettledTokens+counter.ReservedTokens > math.MaxInt64-tokens {
		return false, ErrAmountOverflow
	}
	tokensTotal := counter.SettledTokens + counter.ReservedTokens + tokens
	return (amountLimit > 0 && total > amountLimit) || (tokenLimit > 0 && tokensTotal > tokenLimit), nil
}

func customerRequestLimitError(recentRequests, activeRequests int64, limits CustomerLimits) error {
	if limits.RPMLimit > 0 && recentRequests >= limits.RPMLimit {
		return ErrCustomerRPMLimitExceeded
	}
	if limits.ConcurrencyLimit > 0 && activeRequests >= limits.ConcurrencyLimit {
		return ErrCustomerConcurrencyLimitExceeded
	}
	return nil
}

func billingRequestLeaseTTL() time.Duration {
	ttl, err := time.ParseDuration(os.Getenv("BILLING_REQUEST_LEASE_TTL"))
	if err != nil || ttl < time.Minute || ttl > 24*time.Hour {
		return defaultBillingRequestLeaseTTL
	}
	return ttl
}

func acquireCustomerRequestLease(ctx context.Context, tx pgx.Tx, tenantID, userID, requestID string, at time.Time, limits CustomerLimits) error {
	if limits.RPMLimit == 0 && limits.ConcurrencyLimit == 0 {
		return nil
	}
	var recentRequests, activeRequests int64
	err := tx.QueryRow(ctx, customerRequestLeaseCountsSQL,
		tenantID, userID, at.Add(-time.Minute), at).Scan(&recentRequests, &activeRequests)
	if err != nil {
		return fmt.Errorf("count customer request limits: %w", err)
	}
	if err := customerRequestLimitError(recentRequests, activeRequests, limits); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO billing_request_leases
			(tenant_id, user_id, request_id, acquired_at, expires_at)
		VALUES ($1,$2,$3,$4,$5)
	`, tenantID, userID, requestID, at, at.Add(billingRequestLeaseTTL())); err != nil {
		if isUniqueViolation(err) {
			return ErrIdempotencyConflict
		}
		return fmt.Errorf("acquire customer request lease: %w", err)
	}
	return nil
}

func reserveLimitUsage(ctx context.Context, tx pgx.Tx, tenantID, userID, requestID string, at time.Time, amount Micros, tokens int64) error {
	limits, exists, err := getCustomerLimitsForUpdate(ctx, tx, tenantID, userID)
	if err != nil || !exists {
		return err
	}
	if err := acquireCustomerRequestLease(ctx, tx, tenantID, userID, requestID, at, limits); err != nil {
		return err
	}
	daily, monthly := billingPeriodDates(at)
	for _, item := range []struct {
		kind, start string
		amountLimit Micros
		tokenLimit  int64
	}{{"daily", daily, limits.DailyAmountMicros, limits.DailyTokenLimit}, {"monthly", monthly, limits.MonthlyAmountMicros, limits.MonthlyTokenLimit}} {
		if item.amountLimit == 0 && item.tokenLimit == 0 {
			continue
		}
		counter, err := getLimitCounterForUpdate(ctx, tx, tenantID, userID, item.kind, item.start)
		if err != nil {
			return err
		}
		exceeded, err := limitWouldExceed(counter, amount, tokens, item.amountLimit, item.tokenLimit)
		if err != nil {
			return err
		}
		if exceeded {
			return ErrCustomerLimitExceeded
		}
		if _, err := tx.Exec(ctx, `
			UPDATE billing_limit_counters SET reserved_amount_micros=reserved_amount_micros+$5,
			reserved_tokens=reserved_tokens+$6, updated_at=NOW()
			WHERE tenant_id=$1 AND user_id=$2 AND period_kind=$3 AND period_start=$4::date
		`, tenantID, userID, item.kind, item.start, amount, tokens); err != nil {
			return fmt.Errorf("reserve customer billing limits: %w", err)
		}
	}
	return nil
}

type RequestLeaseCleanupResult struct {
	Deleted  int64
	Batches  int
	Backlog  bool
	Acquired bool
}

type RequestLeaseCleanupStats struct {
	DeletedTotal int64
	LastRunUnix  int64
	Backlog      bool
}

func (s *Store) RequestLeaseCleanupStats() RequestLeaseCleanupStats {
	if s == nil {
		return RequestLeaseCleanupStats{}
	}
	return RequestLeaseCleanupStats{
		DeletedTotal: s.requestLeaseDeletedTotal.Load(),
		LastRunUnix:  s.requestLeaseCleanupRun.Load(),
		Backlog:      s.requestLeaseBacklog.Load(),
	}
}

func (s *Store) PruneRequestLeases(ctx context.Context, at time.Time) (RequestLeaseCleanupResult, error) {
	return s.pruneRequestLeases(ctx, at)
}

func (s *Store) pruneRequestLeases(ctx context.Context, at time.Time) (RequestLeaseCleanupResult, error) {
	result := RequestLeaseCleanupResult{}
	if s == nil || s.db == nil {
		return result, errors.New("billing request lease cleanup store is not initialized")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	for {
		if err := ctx.Err(); err != nil {
			result.Backlog = true
			s.recordRequestLeaseCleanup(at, result)
			return result, err
		}
		deleted, acquired, err := s.pruneRequestLeaseBatch(ctx, at)
		if err != nil {
			result.Backlog = true
			s.recordRequestLeaseCleanup(at, result)
			return result, err
		}
		if !acquired {
			result.Backlog = true
			s.recordRequestLeaseCleanup(at, result)
			return result, nil
		}
		result.Acquired = true
		result.Batches++
		result.Deleted += deleted
		if deleted < requestLeaseCleanupBatchSize {
			result.Backlog = false
			s.recordRequestLeaseCleanup(at, result)
			return result, nil
		}
		result.Backlog = true
	}
}

func (s *Store) recordRequestLeaseCleanup(at time.Time, result RequestLeaseCleanupResult) {
	if result.Deleted > 0 {
		s.requestLeaseDeletedTotal.Add(result.Deleted)
	}
	s.requestLeaseCleanupRun.Store(at.Unix())
	s.requestLeaseBacklog.Store(result.Backlog)
}

func (s *Store) pruneRequestLeaseBatch(ctx context.Context, at time.Time) (int64, bool, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, false, fmt.Errorf("begin request lease cleanup: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
		return 0, false, fmt.Errorf("set request lease cleanup lock timeout: %w", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '400ms'`); err != nil {
		return 0, false, fmt.Errorf("set request lease cleanup statement timeout: %w", err)
	}
	var acquired bool
	if err := tx.QueryRow(ctx, `
		SELECT pg_try_advisory_xact_lock(hashtextextended('jjdguard:billing-request-leases-cleanup', 0))
	`).Scan(&acquired); err != nil {
		return 0, false, fmt.Errorf("lock request lease cleanup: %w", err)
	}
	if !acquired {
		return 0, false, nil
	}
	tag, err := tx.Exec(ctx, `
		WITH stale AS (
			SELECT ctid
			FROM billing_request_leases
			WHERE (released_at IS NULL AND expires_at <= $1)
			   OR (released_at IS NOT NULL AND acquired_at < $2)
			ORDER BY acquired_at
			FOR UPDATE SKIP LOCKED
			LIMIT $3
		)
		DELETE FROM billing_request_leases AS leases
		USING stale
		WHERE leases.ctid = stale.ctid
	`, at, at.Add(-time.Minute), requestLeaseCleanupBatchSize)
	if err != nil {
		return 0, true, fmt.Errorf("prune request leases: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, true, fmt.Errorf("commit request lease cleanup: %w", err)
	}
	return tag.RowsAffected(), true, nil
}

func releaseCustomerRequestLease(ctx context.Context, tx pgx.Tx, tenantID, requestID string) error {
	if _, err := tx.Exec(ctx, `
		UPDATE billing_request_leases
		SET released_at=COALESCE(released_at, NOW())
		WHERE tenant_id=$1 AND request_id=$2
	`, tenantID, requestID); err != nil {
		return fmt.Errorf("release customer request lease: %w", err)
	}
	return nil
}

func settleLimitUsage(ctx context.Context, tx pgx.Tx, tenantID, userID string, reservation *Reservation, amount Micros, tokens int64) error {
	daily, monthly := billingPeriodDates(reservation.CreatedAt)
	for _, item := range []struct{ kind, start string }{{"daily", daily}, {"monthly", monthly}} {
		if _, err := tx.Exec(ctx, `
			UPDATE billing_limit_counters
			SET reserved_amount_micros=GREATEST(0,reserved_amount_micros-$5),
				reserved_tokens=GREATEST(0,reserved_tokens-$6),
				settled_amount_micros=settled_amount_micros+$7,
				settled_tokens=settled_tokens+$8, updated_at=NOW()
			WHERE tenant_id=$1 AND user_id=$2 AND period_kind=$3 AND period_start=$4::date
		`, tenantID, userID, item.kind, item.start, reservation.ReservedMicros, reservation.ReservedTokens, amount, tokens); err != nil {
			return fmt.Errorf("settle customer billing limits: %w", err)
		}
	}
	return nil
}

func releaseLimitUsage(ctx context.Context, tx pgx.Tx, tenantID, userID string, reservation *Reservation) error {
	daily, monthly := billingPeriodDates(reservation.CreatedAt)
	for _, item := range []struct{ kind, start string }{{"daily", daily}, {"monthly", monthly}} {
		if _, err := tx.Exec(ctx, `
			UPDATE billing_limit_counters
			SET reserved_amount_micros=GREATEST(0,reserved_amount_micros-$5),
				reserved_tokens=GREATEST(0,reserved_tokens-$6), updated_at=NOW()
			WHERE tenant_id=$1 AND user_id=$2 AND period_kind=$3 AND period_start=$4::date
		`, tenantID, userID, item.kind, item.start, reservation.ReservedMicros, reservation.ReservedTokens); err != nil {
			return fmt.Errorf("release customer billing limits: %w", err)
		}
	}
	return nil
}
