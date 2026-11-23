package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrWalletNotFound      = errors.New("billing wallet not found")
	ErrReservationNotFound = errors.New("billing reservation not found")
	ErrIdempotencyConflict = errors.New("billing idempotency conflict")
	currencyPattern        = regexp.MustCompile(`^[A-Z]{3,8}$`)
)

const (
	ReservationReserved = "reserved"
	ReservationSettled  = "settled"
	ReservationReleased = "released"
)

type Wallet struct {
	ID             string
	TenantID       string
	UserID         string
	Currency       string
	BalanceMicros  Micros
	ReservedMicros Micros
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (w Wallet) AvailableMicros() Micros {
	return WalletState{BalanceMicros: w.BalanceMicros, ReservedMicros: w.ReservedMicros}.AvailableMicros()
}

type Reservation struct {
	ID                    string
	TenantID              string
	WalletID              string
	RequestID             string
	ReservedMicros        Micros
	ReservedTokens        int64
	PriceID               string
	ModelName             string
	CustomerGroup         string
	CustomerGroupRatioPPM int64
	UserID                string
	DepartmentID          string
	DepartmentName        string
	TariffPlanID          string
	TariffPlanVersion     int
	TariffRuleID          string
	TariffBand            string
	TariffMultiplierPPM   int64
	BillingTimezone       string
	AdmittedAt            time.Time
	SettledMicros         *Micros
	Status                string
	CreatedAt             time.Time
	FinalizedAt           *time.Time
}

type BillingAttribution struct {
	UserID         string
	UserName       string
	DepartmentID   string
	DepartmentName string
}

// billingDB is the minimal database surface the billing store relies on.
// *pgxpool.Pool satisfies it; the interface exists so tests can inject
// narrow, targeted faults (for example failing only the reconciliation
// pending-count query) without mocking the whole pool.
type billingDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Store struct {
	fundingClock             func() time.Time
	db                       billingDB
	defaultCurrency          string
	redemptionPrefix         string
	requestLeaseDeletedTotal atomic.Int64
	requestLeaseCleanupRun   atomic.Int64
	requestLeaseBacklog      atomic.Bool
	// auditChain 非空时，关键计费审计（切换币种、作废其他币种价格）在业务事务内写入审计链。
	auditChain AuditChainTx
}

func NewStore(db *pgxpool.Pool) *Store {
	currency := strings.ToUpper(strings.TrimSpace(os.Getenv("BILLING_DEFAULT_CURRENCY")))
	if !currencyPattern.MatchString(currency) {
		currency = "CNY"
	}
	prefix := strings.ToUpper(strings.TrimSpace(os.Getenv("BILLING_REDEMPTION_PREFIX")))
	prefix = regexp.MustCompile(`[^A-Z0-9]`).ReplaceAllString(prefix, "")
	if len(prefix) < 2 || len(prefix) > 8 {
		prefix = "JJD"
	}
	return &Store{db: db, defaultCurrency: currency, redemptionPrefix: prefix}
}

func (s *Store) DefaultCurrency() string {
	if s == nil || s.defaultCurrency == "" {
		return "CNY"
	}
	return s.defaultCurrency
}

// EnsureWallet 只建「租户当前币种」的钱包。租户已明确设置币种（billing_employee_settings）后，
// 其它币种一律拒绝，避免像现场那样在 USD 钱包旁边冒出空的 CNY 钱包；
// 尚未设置币种的老租户保持原行为。与币种切换、保存设置共用 allowance-settings 咨询锁，
// 切换期间不会并发建出旧币种钱包。
func (s *Store) EnsureWallet(ctx context.Context, tenantID, userID, currency string) (*Wallet, error) {
	if tenantID == "" || userID == "" || !currencyPattern.MatchString(currency) {
		return nil, fmt.Errorf("%w: invalid wallet owner or currency", ErrInvalidWalletState)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("ensure billing wallet: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, "allowance-settings:"+tenantID); err != nil {
		return nil, fmt.Errorf("ensure billing wallet: %w", err)
	}
	var explicit string
	switch err = tx.QueryRow(ctx, `SELECT currency FROM billing_employee_settings WHERE tenant_id=$1`, tenantID).Scan(&explicit); {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return nil, fmt.Errorf("ensure billing wallet: %w", err)
	case explicit != currency:
		return nil, ErrAllowanceCurrency
	}
	wallet, err := ensureWalletTx(ctx, tx, tenantID, userID, currency)
	if err != nil {
		return nil, fmt.Errorf("ensure billing wallet: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("ensure billing wallet: %w", err)
	}
	return wallet, nil
}

func (s *Store) FindWalletForUser(ctx context.Context, tenantID, userID, currency string) (*Wallet, error) {
	if userID != "" {
		if _, err := s.EnsureMonthlyWalletGrant(ctx, tenantID, userID, currency, time.Now().UTC()); err != nil {
			return nil, err
		}
	}
	wallet, err := scanWallet(s.db.QueryRow(ctx, `SELECT id,tenant_id,user_id,currency,balance_micros,reserved_micros,version,created_at,updated_at FROM billing_wallets WHERE tenant_id=$1 AND user_id=$2 AND currency=$3 AND (prepaid_configured OR balance_micros<>0)`, tenantID, userID, currency))
	if errors.Is(err, pgx.ErrNoRows) {
		var otherCurrency bool
		lookupErr := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_wallets w WHERE w.tenant_id=$1 AND w.user_id=$2 AND w.currency<>$3 AND `+fundedWalletPredicate+`)`, tenantID, userID, currency).Scan(&otherCurrency)
		if lookupErr != nil {
			return nil, lookupErr
		}
		if otherCurrency {
			return nil, ErrAllowanceCurrency
		}
		return nil, nil
	}
	return wallet, err
}

func (s *Store) GetWallet(ctx context.Context, tenantID, walletID string) (*Wallet, error) {
	wallet, err := scanWallet(s.db.QueryRow(ctx, `
        SELECT id, tenant_id, user_id, currency, balance_micros, reserved_micros,
               version, created_at, updated_at
        FROM billing_wallets
        WHERE tenant_id = $1 AND id = $2
    `, tenantID, walletID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrWalletNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get billing wallet: %w", err)
	}
	return wallet, nil
}

func (s *Store) Credit(ctx context.Context, tenantID, walletID, idempotencyKey string, amount Micros, actorID string, reason ...string) (*Wallet, error) {
	if tenantID == "" || walletID == "" || idempotencyKey == "" || amount <= 0 {
		return nil, fmt.Errorf("%w: invalid credit", ErrInvalidWalletState)
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	wallet, err := creditWalletTx(ctx, tx, tenantID, walletID, idempotencyKey, amount, actorID, reason...)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return wallet, nil
}

// CreditUserWallet provisions in the authoritative tenant denomination while
// serializing with settings and price saves. It never funds a foreign wallet.
func (s *Store) CreditUserWallet(ctx context.Context, tenantID, userID, idempotencyKey string, amount Micros, actorID string, reason ...string) (*Wallet, error) {
	if tenantID == "" || userID == "" || idempotencyKey == "" || amount <= 0 {
		return nil, ErrInvalidWalletState
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "allowance-settings:"+tenantID); err != nil {
		return nil, err
	}
	var owned bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id=$1 AND id=$2)`, tenantID, userID).Scan(&owned); err != nil {
		return nil, err
	}
	if !owned {
		return nil, ErrInvalidWalletState
	}
	currency, err := s.billingCurrencyForTenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	var mismatch bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_wallets w WHERE w.tenant_id=$1 AND w.user_id=$2 AND w.currency<>$3 AND `+fundedWalletPredicate+`)`, tenantID, userID, currency).Scan(&mismatch); err != nil {
		return nil, err
	}
	if mismatch {
		return nil, ErrAllowanceCurrency
	}
	wallet, err := ensureWalletTx(ctx, tx, tenantID, userID, currency)
	if err != nil {
		return nil, err
	}
	wallet, err = creditWalletTx(ctx, tx, tenantID, wallet.ID, idempotencyKey, amount, actorID, reason...)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return wallet, nil
}

func creditWalletTx(ctx context.Context, tx pgx.Tx, tenantID, walletID, idempotencyKey string, amount Micros, actorID string, reason ...string) (*Wallet, error) {
	wallet, err := getWalletForUpdate(ctx, tx, tenantID, walletID)
	if err != nil {
		return nil, err
	}
	var eventType string
	var existingDelta Micros
	var existingMetadata []byte
	err = tx.QueryRow(ctx, `
        SELECT event_type, balance_delta_micros, metadata_json
        FROM billing_ledger_entries
        WHERE wallet_id = $1 AND idempotency_key = $2
    `, walletID, idempotencyKey).Scan(&eventType, &existingDelta, &existingMetadata)
	switch {
	case err == nil:
		if eventType != "credit" || existingDelta != amount ||
			ledgerReason(existingMetadata) != reasonMetadata(reason)["reason"] {
			return nil, ErrIdempotencyConflict
		}
		return wallet, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("read billing credit idempotency: %w", err)
	}

	newBalance, err := addMicros(wallet.BalanceMicros, amount)
	if err != nil {
		return nil, err
	}
	next := WalletState{BalanceMicros: newBalance, ReservedMicros: wallet.ReservedMicros}
	wallet, err = updateWallet(ctx, tx, wallet, next)
	if err != nil {
		return nil, err
	}
	if err := insertLedger(ctx, tx, ledgerInsert{
		TenantID: tenantID, WalletID: walletID, EventType: "credit",
		BalanceDelta: amount, BalanceAfter: wallet.BalanceMicros,
		ReservedAfter: wallet.ReservedMicros, IdempotencyKey: idempotencyKey,
		ActorType: "admin", ActorID: actorID,
		Metadata: reasonMetadata(reason),
	}); err != nil {
		return nil, err
	}
	return wallet, nil
}

// Adjust records a signed, operator-initiated balance correction. A negative
// correction cannot reduce a wallet below its currently frozen reservation
// amount, protecting in-flight requests from an administrative race.
func (s *Store) Adjust(ctx context.Context, tenantID, walletID, idempotencyKey string, delta Micros, actorID string, reason ...string) (*Wallet, error) {
	if tenantID == "" || walletID == "" || idempotencyKey == "" || delta == 0 {
		return nil, fmt.Errorf("%w: invalid adjustment", ErrInvalidWalletState)
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin billing adjustment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	wallet, err := getWalletForUpdate(ctx, tx, tenantID, walletID)
	if err != nil {
		return nil, err
	}
	var eventType string
	var existingDelta Micros
	var existingMetadata []byte
	err = tx.QueryRow(ctx, `
        SELECT event_type, balance_delta_micros, metadata_json
        FROM billing_ledger_entries
        WHERE wallet_id = $1 AND idempotency_key = $2
    `, walletID, idempotencyKey).Scan(&eventType, &existingDelta, &existingMetadata)
	switch {
	case err == nil:
		if eventType != "adjustment" || existingDelta != delta ||
			ledgerReason(existingMetadata) != reasonMetadata(reason)["reason"] {
			return nil, ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit idempotent billing adjustment: %w", err)
		}
		return wallet, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("read billing adjustment idempotency: %w", err)
	}

	fundingAt := s.fundingNow()
	wallet, err = expireMonthlyGrantsTx(ctx, tx, wallet, fundingAt)
	if err != nil {
		return nil, err
	}
	newBalance, err := addMicros(wallet.BalanceMicros, delta)
	if err != nil {
		return nil, err
	}
	next := WalletState{BalanceMicros: newBalance, ReservedMicros: wallet.ReservedMicros}
	// A positive correction only improves the wallet and must be accepted even
	// when an earlier settlement left it overdrawn (D5); a negative correction
	// still cannot eat into money frozen for in-flight requests.
	if err := next.validate(); err != nil || (delta < 0 && next.BalanceMicros < next.ReservedMicros) {
		return nil, ErrInsufficientBalance
	}
	adjustedGift := Micros(0)
	if delta < 0 {
		adjustedGift, err = adjustMonthlyGrantTx(ctx, tx, wallet, -delta, fundingAt)
		if err != nil {
			return nil, err
		}
	}
	metadata := reasonMetadata(reason)
	if metadata == nil {
		metadata = map[string]any{}
	}
	if delta < 0 {
		metadata["monthly_grant_adjusted_micros"] = adjustedGift
		metadata["permanent_adjusted_micros"] = -delta - adjustedGift
	}
	wallet, err = updateWallet(ctx, tx, wallet, next)
	if err != nil {
		return nil, err
	}
	if err := insertLedger(ctx, tx, ledgerInsert{
		TenantID: tenantID, WalletID: walletID, EventType: "adjustment",
		BalanceDelta: delta, BalanceAfter: wallet.BalanceMicros, ReservedAfter: wallet.ReservedMicros,
		IdempotencyKey: idempotencyKey, ActorType: "admin", ActorID: actorID,
		Metadata: metadata,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit billing adjustment: %w", err)
	}
	return wallet, nil
}
func (s *Store) Reserve(ctx context.Context, tenantID, walletID, requestID string, amount Micros) (*Reservation, *Wallet, error) {
	return s.reserve(ctx, tenantID, walletID, requestID, amount, 0, nil, "", ratioScale, BillingAttribution{}, DefaultTariffQuote(time.Now().UTC(), billingTimeZone()))
}

// ReservePriced stores the immutable price version selected at admission.
func (s *Store) ReservePriced(ctx context.Context, tenantID, walletID, requestID string, amount Micros, price *ModelPrice) (*Reservation, *Wallet, error) {
	return s.ReservePricedWithUsage(ctx, tenantID, walletID, requestID, amount, 0, price)
}

func (s *Store) ReservePricedWithUsage(ctx context.Context, tenantID, walletID, requestID string, amount Micros, reservedTokens int64, price *ModelPrice) (*Reservation, *Wallet, error) {
	return s.ReservePricedWithUsageForGroup(ctx, tenantID, walletID, requestID, amount, reservedTokens, price, DefaultCustomerGroup, ratioScale)
}

// ReservePricedWithUsageForGroup stores both immutable inputs to the quote:
// the model price version and the customer's group multiplier at admission.
func (s *Store) ReservePricedWithUsageForGroup(ctx context.Context, tenantID, walletID, requestID string, amount Micros, reservedTokens int64, price *ModelPrice, customerGroup string, customerGroupRatioPPM int64) (*Reservation, *Wallet, error) {
	return s.ReservePricedWithUsageForGroupAndTariff(ctx, tenantID, walletID, requestID, amount, reservedTokens, price, customerGroup, customerGroupRatioPPM, BillingAttribution{}, DefaultTariffQuote(time.Now().UTC(), billingTimeZone()))
}

// ReservePricedWithUsageForGroupAndTariff freezes identity attribution and
// the selected time-band quote at admission. Settlement must reuse these
// fields so department moves and tariff edits cannot rewrite history.
func (s *Store) ReservePricedWithUsageForGroupAndTariff(ctx context.Context, tenantID, walletID, requestID string, amount Micros, reservedTokens int64, price *ModelPrice, customerGroup string, customerGroupRatioPPM int64, attribution BillingAttribution, tariff TariffQuote) (*Reservation, *Wallet, error) {
	if price == nil || price.ID == "" || price.TenantID != tenantID || price.ModelName == "" || price.CustomerGroup == "" {
		return nil, nil, ErrInvalidPrice
	}
	customerGroup = normalizeCustomerGroupCode(customerGroup)
	if !customerGroupCodePattern.MatchString(customerGroup) || customerGroupRatioPPM <= 0 || customerGroupRatioPPM > MaxCustomerGroupRatioPPM {
		return nil, nil, ErrInvalidPrice
	}
	if tariff.MultiplierPPM <= 0 || tariff.MultiplierPPM > MaxCustomerGroupRatioPPM || !validTariffBand(tariff.Band) || strings.TrimSpace(tariff.Timezone) == "" {
		return nil, nil, ErrInvalidTariff
	}
	if tariff.AdmittedAt.IsZero() {
		tariff.AdmittedAt = time.Now().UTC()
	}
	return s.reserve(ctx, tenantID, walletID, requestID, amount, reservedTokens, price, customerGroup, customerGroupRatioPPM, attribution, tariff)
}

func (s *Store) reserve(ctx context.Context, tenantID, walletID, requestID string, amount Micros, reservedTokens int64, price *ModelPrice, customerGroup string, customerGroupRatioPPM int64, attribution BillingAttribution, tariff TariffQuote) (*Reservation, *Wallet, error) {
	if tenantID == "" || walletID == "" || requestID == "" || amount < 0 || reservedTokens < 0 || (amount == 0 && reservedTokens == 0) {
		return nil, nil, fmt.Errorf("%w: invalid reservation", ErrInvalidWalletState)
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("begin billing reservation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 与系统币种切换的排他锁互斥；旧报价不能在切换提交后按旧面额预占。
	if price != nil {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, "allowance-settings:"+tenantID); err != nil {
			return nil, nil, err
		}
		currency, err := s.billingCurrencyForTenant(ctx, tx, tenantID)
		if err != nil {
			return nil, nil, err
		}
		if price.Currency != currency {
			return nil, nil, ErrPriceCurrencyMismatch
		}
	}

	owner, err := scanWallet(tx.QueryRow(ctx, `SELECT id,tenant_id,user_id,currency,balance_micros,reserved_micros,version,created_at,updated_at FROM billing_wallets WHERE tenant_id=$1 AND id=$2`, tenantID, walletID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrWalletNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	cfg, amountRule, eligible, err := s.walletFundingContextTx(ctx, tx, tenantID, owner.UserID, owner.Currency)
	if err != nil {
		return nil, nil, err
	}
	wallet, err := getWalletForUpdate(ctx, tx, tenantID, walletID)
	if err != nil {
		return nil, nil, err
	}
	if wallet.UserID != owner.UserID || wallet.Currency != owner.Currency {
		return nil, nil, ErrIdempotencyConflict
	}
	fundingAt := s.fundingNow()
	wallet, err = s.syncMonthlyWalletTx(ctx, tx, wallet, cfg, amountRule, eligible, fundingAt)
	if err != nil {
		return nil, nil, err
	}
	existing, err := getReservation(ctx, tx, tenantID, requestID, false)
	switch {
	case err == nil:
		if existing.WalletID != walletID || existing.ReservedMicros != amount || existing.ReservedTokens != reservedTokens ||
			(existing.PriceID != "" && (price == nil || existing.PriceID != price.ID)) ||
			(existing.PriceID == "" && price != nil) ||
			(price != nil && (existing.CustomerGroup != customerGroup || existing.CustomerGroupRatioPPM != customerGroupRatioPPM ||
				existing.UserID != attribution.UserID || existing.DepartmentID != attribution.DepartmentID ||
				existing.TariffPlanID != tariff.PlanID || existing.TariffPlanVersion != tariff.PlanVersion ||
				existing.TariffRuleID != tariff.RuleID || existing.TariffBand != tariff.Band ||
				existing.TariffMultiplierPPM != tariff.MultiplierPPM || existing.BillingTimezone != tariff.Timezone)) {
			return nil, nil, ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, nil, fmt.Errorf("commit idempotent billing reservation: %w", err)
		}
		return existing, wallet, nil
	case !errors.Is(err, ErrReservationNotFound):
		return nil, nil, err
	}

	// Zero estimates on a paid model still require funds under the wallet lock.
	// The separate quote guard cannot protect against a competing settlement.
	if price != nil && !price.IsFullyFree() && wallet.AvailableMicros() <= 0 {
		return nil, nil, ErrInsufficientBalance
	}
	if amount > 0 {
		next, err := (WalletState{BalanceMicros: wallet.BalanceMicros, ReservedMicros: wallet.ReservedMicros}).Reserve(amount)
		if err != nil {
			return nil, nil, err
		}
		wallet, err = updateWallet(ctx, tx, wallet, next)
		if err != nil {
			return nil, nil, err
		}
	}
	if err := reserveLimitUsage(ctx, tx, tenantID, wallet.UserID, requestID, fundingAt, amount, reservedTokens); err != nil {
		return nil, nil, err
	}
	reservation := &Reservation{
		ID: "reservation_" + uuid.NewString(), TenantID: tenantID, WalletID: walletID,
		RequestID: requestID, ReservedMicros: amount, ReservedTokens: reservedTokens,
		CustomerGroupRatioPPM: ratioScale, Status: ReservationReserved,
		UserID: attribution.UserID, DepartmentID: attribution.DepartmentID, DepartmentName: attribution.DepartmentName,
		TariffPlanID: tariff.PlanID, TariffPlanVersion: tariff.PlanVersion, TariffRuleID: tariff.RuleID,
		TariffBand: tariff.Band, TariffMultiplierPPM: tariff.MultiplierPPM,
		BillingTimezone: tariff.Timezone, AdmittedAt: tariff.AdmittedAt.UTC(),
	}
	if price != nil {
		reservation.PriceID = price.ID
		reservation.ModelName = price.ModelName
		reservation.CustomerGroup = customerGroup
		reservation.CustomerGroupRatioPPM = customerGroupRatioPPM
	}
	err = tx.QueryRow(ctx, `
        INSERT INTO billing_reservations
            (id, tenant_id, wallet_id, request_id, price_id, model_name, customer_group, customer_group_ratio_ppm,
			 user_id, department_id, department_name, tariff_plan_id, tariff_plan_version, tariff_rule_id,
			 tariff_band, tariff_multiplier_ppm, billing_timezone, admitted_at,
			 reserved_micros, reserved_tokens, status, created_at)
        VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), $8,
			NULLIF($9,''),NULLIF($10,''),$11,NULLIF($12,''),NULLIF($13,0),NULLIF($14,''),$15,$16,$17,$18,
			$19,$20,$21,$22)
        RETURNING created_at
    `, reservation.ID, tenantID, walletID, requestID, reservation.PriceID, reservation.ModelName,
		reservation.CustomerGroup, reservation.CustomerGroupRatioPPM,
		reservation.UserID, reservation.DepartmentID, reservation.DepartmentName, reservation.TariffPlanID,
		reservation.TariffPlanVersion, reservation.TariffRuleID, reservation.TariffBand,
		reservation.TariffMultiplierPPM, reservation.BillingTimezone, reservation.AdmittedAt,
		amount, reservedTokens, reservation.Status, fundingAt).Scan(&reservation.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, nil, ErrIdempotencyConflict
		}
		return nil, nil, fmt.Errorf("insert billing reservation: %w", err)
	}
	giftReserved, err := reserveMonthlyGrantTx(ctx, tx, wallet, reservation, fundingAt)
	if err != nil {
		return nil, nil, err
	}
	if err := insertLedger(ctx, tx, ledgerInsert{
		TenantID: tenantID, WalletID: walletID, ReservationID: reservation.ID,
		RequestID: requestID, EventType: "reserve", ReservedDelta: amount,
		BalanceAfter: wallet.BalanceMicros, ReservedAfter: wallet.ReservedMicros,
		IdempotencyKey: "reserve:" + requestID, ActorType: "gateway",
		Metadata: map[string]any{"monthly_grant_reserved_micros": giftReserved, "permanent_reserved_micros": amount - giftReserved, "funding_at": fundingAt},
	}); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit billing reservation: %w", err)
	}
	return reservation, wallet, nil
}

func (s *Store) Settle(ctx context.Context, tenantID, requestID string, actual Micros) (*Reservation, *Wallet, error) {
	if tenantID == "" || requestID == "" || actual < 0 {
		return nil, nil, fmt.Errorf("%w: invalid settlement", ErrInvalidWalletState)
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("begin billing settlement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	wallet, reservation, err := lockWalletReservation(ctx, tx, tenantID, requestID)
	if err != nil {
		return nil, nil, err
	}
	if err := releaseCustomerRequestLease(ctx, tx, tenantID, requestID); err != nil {
		return nil, nil, err
	}
	if reservation.Status == ReservationSettled {
		if reservation.SettledMicros == nil || *reservation.SettledMicros != actual {
			return nil, nil, ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, nil, fmt.Errorf("commit idempotent billing settlement: %w", err)
		}
		return reservation, wallet, nil
	}
	if reservation.Status != ReservationReserved {
		return nil, nil, ErrIdempotencyConflict
	}

	wallet, err = settleWalletFundingTx(ctx, tx, wallet, reservation, actual, false, s.fundingNow())
	if err != nil {
		return nil, nil, err
	}
	if err := settleLimitUsage(ctx, tx, tenantID, wallet.UserID, reservation, actual, reservation.ReservedTokens); err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	reservation.Status = ReservationSettled
	reservation.SettledMicros = &actual
	reservation.FinalizedAt = &now
	if _, err := tx.Exec(ctx, `
        UPDATE billing_reservations
        SET settled_micros = $1, status = $2, finalized_at = $3
        WHERE tenant_id = $4 AND id = $5 AND status = 'reserved'
    `, actual, reservation.Status, now, tenantID, reservation.ID); err != nil {
		return nil, nil, fmt.Errorf("update billing settlement: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit billing settlement: %w", err)
	}
	return reservation, wallet, nil
}

func (s *Store) Release(ctx context.Context, tenantID, requestID string) (*Reservation, *Wallet, error) {
	if tenantID == "" || requestID == "" {
		return nil, nil, fmt.Errorf("%w: invalid release", ErrInvalidWalletState)
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("begin billing release: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	wallet, reservation, err := lockWalletReservation(ctx, tx, tenantID, requestID)
	if err != nil {
		return nil, nil, err
	}
	if err := releaseCustomerRequestLease(ctx, tx, tenantID, requestID); err != nil {
		return nil, nil, err
	}
	if reservation.Status == ReservationReleased {
		if err := tx.Commit(ctx); err != nil {
			return nil, nil, fmt.Errorf("commit idempotent billing release: %w", err)
		}
		return reservation, wallet, nil
	}
	if reservation.Status != ReservationReserved {
		return nil, nil, ErrIdempotencyConflict
	}

	wallet, err = releaseWalletFundingTx(ctx, tx, wallet, reservation, s.fundingNow())
	if err != nil {
		return nil, nil, err
	}
	if err := releaseLimitUsage(ctx, tx, tenantID, wallet.UserID, reservation); err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	reservation.Status = ReservationReleased
	reservation.FinalizedAt = &now
	if _, err := tx.Exec(ctx, `
        UPDATE billing_reservations
        SET status = $1, finalized_at = $2
        WHERE tenant_id = $3 AND id = $4 AND status = 'reserved'
    `, reservation.Status, now, tenantID, reservation.ID); err != nil {
		return nil, nil, fmt.Errorf("update billing release: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit billing release: %w", err)
	}
	return reservation, wallet, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanWallet(row rowScanner) (*Wallet, error) {
	wallet := &Wallet{}
	err := row.Scan(
		&wallet.ID, &wallet.TenantID, &wallet.UserID, &wallet.Currency,
		&wallet.BalanceMicros, &wallet.ReservedMicros, &wallet.Version,
		&wallet.CreatedAt, &wallet.UpdatedAt,
	)
	return wallet, err
}

func getWalletForUpdate(ctx context.Context, tx pgx.Tx, tenantID, walletID string) (*Wallet, error) {
	wallet, err := scanWallet(tx.QueryRow(ctx, `
        SELECT id, tenant_id, user_id, currency, balance_micros, reserved_micros,
               version, created_at, updated_at
        FROM billing_wallets
        WHERE tenant_id = $1 AND id = $2
        FOR UPDATE
    `, tenantID, walletID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrWalletNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock billing wallet: %w", err)
	}
	return wallet, nil
}

func updateWallet(ctx context.Context, tx pgx.Tx, wallet *Wallet, state WalletState) (*Wallet, error) {
	updated, err := scanWallet(tx.QueryRow(ctx, `
        UPDATE billing_wallets
        SET prepaid_configured = prepaid_configured OR balance_micros <> $1, balance_micros = $1, reserved_micros = $2, version = version + 1, updated_at = NOW()
        WHERE tenant_id = $3 AND id = $4
        RETURNING id, tenant_id, user_id, currency, balance_micros, reserved_micros,
                  version, created_at, updated_at
    `, state.BalanceMicros, state.ReservedMicros, wallet.TenantID, wallet.ID))
	if err != nil {
		return nil, fmt.Errorf("update billing wallet: %w", err)
	}
	return updated, nil
}

func getReservation(ctx context.Context, tx pgx.Tx, tenantID, requestID string, forUpdate bool) (*Reservation, error) {
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE"
	}
	reservation := &Reservation{}
	var settled *int64
	err := tx.QueryRow(ctx, `
        SELECT id, tenant_id, wallet_id, request_id, COALESCE(price_id, ''),
               COALESCE(model_name, ''), COALESCE(customer_group, ''), customer_group_ratio_ppm, reserved_micros, reserved_tokens,
			   COALESCE(user_id,''), COALESCE(department_id,''), department_name,
			   COALESCE(tariff_plan_id,''), COALESCE(tariff_plan_version,0), COALESCE(tariff_rule_id,''),
			   tariff_band, tariff_multiplier_ppm, billing_timezone, admitted_at,
               settled_micros, status, created_at, finalized_at
        FROM billing_reservations
        WHERE tenant_id = $1 AND request_id = $2`+suffix,
		tenantID, requestID,
	).Scan(
		&reservation.ID, &reservation.TenantID, &reservation.WalletID,
		&reservation.RequestID, &reservation.PriceID, &reservation.ModelName, &reservation.CustomerGroup,
		&reservation.CustomerGroupRatioPPM, &reservation.ReservedMicros, &reservation.ReservedTokens,
		&reservation.UserID, &reservation.DepartmentID, &reservation.DepartmentName,
		&reservation.TariffPlanID, &reservation.TariffPlanVersion, &reservation.TariffRuleID,
		&reservation.TariffBand, &reservation.TariffMultiplierPPM, &reservation.BillingTimezone, &reservation.AdmittedAt, &settled,
		&reservation.Status, &reservation.CreatedAt, &reservation.FinalizedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrReservationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get billing reservation: %w", err)
	}
	if settled != nil {
		value := Micros(*settled)
		reservation.SettledMicros = &value
	}
	return reservation, nil
}

type ledgerInsert struct {
	TenantID       string
	WalletID       string
	ReservationID  string
	RequestID      string
	EventType      string
	BalanceDelta   Micros
	ReservedDelta  Micros
	BalanceAfter   Micros
	ReservedAfter  Micros
	IdempotencyKey string
	ActorType      string
	ActorID        string
	// Metadata is stored in metadata_json; nil keeps the column default {}.
	Metadata map[string]any
}

// GetReservation returns a tenant-scoped reservation without a row lock.
func (s *Store) GetReservation(ctx context.Context, tenantID, requestID string) (*Reservation, error) {
	reservation := &Reservation{}
	var settled *int64
	err := s.db.QueryRow(ctx, `
        SELECT id, tenant_id, wallet_id, request_id, COALESCE(price_id, ''),
               COALESCE(model_name, ''), COALESCE(customer_group, ''), customer_group_ratio_ppm, reserved_micros, reserved_tokens,
			   COALESCE(user_id,''), COALESCE(department_id,''), department_name,
			   COALESCE(tariff_plan_id,''), COALESCE(tariff_plan_version,0), COALESCE(tariff_rule_id,''),
			   tariff_band, tariff_multiplier_ppm, billing_timezone, admitted_at,
               settled_micros, status, created_at, finalized_at
        FROM billing_reservations WHERE tenant_id = $1 AND request_id = $2
    `, tenantID, requestID).Scan(
		&reservation.ID, &reservation.TenantID, &reservation.WalletID, &reservation.RequestID,
		&reservation.PriceID, &reservation.ModelName, &reservation.CustomerGroup, &reservation.CustomerGroupRatioPPM, &reservation.ReservedMicros,
		&reservation.ReservedTokens, &reservation.UserID, &reservation.DepartmentID, &reservation.DepartmentName,
		&reservation.TariffPlanID, &reservation.TariffPlanVersion, &reservation.TariffRuleID,
		&reservation.TariffBand, &reservation.TariffMultiplierPPM, &reservation.BillingTimezone, &reservation.AdmittedAt,
		&settled, &reservation.Status, &reservation.CreatedAt, &reservation.FinalizedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrReservationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get billing reservation: %w", err)
	}
	if settled != nil {
		value := Micros(*settled)
		reservation.SettledMicros = &value
	}
	return reservation, nil
}

// ResolveBillingAttribution reads the server-authoritative department at
// admission. Browser or gateway supplied department identifiers are never
// accepted for financial attribution.
func (s *Store) ResolveBillingAttribution(ctx context.Context, tenantID, userID string) (BillingAttribution, error) {
	var value BillingAttribution
	err := s.db.QueryRow(ctx, `
		SELECT u.id, COALESCE(u.username,''), COALESCE(u.department_id,''), COALESCE(t.name,'')
		FROM users u
		LEFT JOIN teams t ON t.id=u.department_id AND t.tenant_id=u.tenant_id
		WHERE u.tenant_id=$1 AND u.id=$2
	`, tenantID, userID).Scan(&value.UserID, &value.UserName, &value.DepartmentID, &value.DepartmentName)
	if errors.Is(err, pgx.ErrNoRows) {
		return BillingAttribution{}, ErrInvalidWalletState
	}
	if err != nil {
		return BillingAttribution{}, fmt.Errorf("resolve billing attribution: %w", err)
	}
	return value, nil
}

// reasonMetadata stores the operator-supplied reason inside the ledger entry
// metadata in the same transaction as the balance change, keeping the audit
// trail atomic with the mutation.
func reasonMetadata(reason []string) map[string]any {
	if len(reason) == 0 || strings.TrimSpace(reason[0]) == "" {
		return nil
	}
	return map[string]any{"reason": strings.TrimSpace(reason[0])}
}

// ledgerReason reads the operator reason back out of a persisted ledger
// entry's metadata so idempotent replays can compare the full input.
func ledgerReason(metadata []byte) any {
	var decoded struct {
		Reason any `json:"reason"`
	}
	if len(metadata) == 0 || json.Unmarshal(metadata, &decoded) != nil {
		return nil
	}
	return decoded.Reason
}

func insertLedger(ctx context.Context, tx pgx.Tx, entry ledgerInsert) error {
	if (entry.EventType == "reserve" || entry.EventType == "settle" || entry.EventType == "release") && entry.ReservedDelta == 0 && entry.BalanceDelta == 0 {
		return nil
	}
	metadata := []byte("{}")
	if len(entry.Metadata) > 0 {
		encoded, err := json.Marshal(entry.Metadata)
		if err != nil {
			return fmt.Errorf("encode billing ledger metadata: %w", err)
		}
		metadata = encoded
	}
	_, err := tx.Exec(ctx, `
        INSERT INTO billing_ledger_entries (
            id, tenant_id, wallet_id, reservation_id, request_id, event_type,
            balance_delta_micros, reserved_delta_micros,
            balance_after_micros, reserved_after_micros,
            idempotency_key, actor_type, actor_id, metadata_json, created_at
        ) VALUES (
            $1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), $6,
            $7, $8, $9, $10, $11, $12, NULLIF($13, ''), $14::jsonb, clock_timestamp()
        )
    `, "ledger_"+uuid.NewString(), entry.TenantID, entry.WalletID,
		entry.ReservationID, entry.RequestID, entry.EventType,
		entry.BalanceDelta, entry.ReservedDelta, entry.BalanceAfter,
		entry.ReservedAfter, entry.IdempotencyKey, entry.ActorType, entry.ActorID, string(metadata))
	if err != nil {
		if isUniqueViolation(err) {
			return ErrIdempotencyConflict
		}
		return fmt.Errorf("insert billing ledger entry: %w", err)
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
