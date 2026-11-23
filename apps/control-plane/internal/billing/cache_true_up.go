package billing

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ExceptionRecoveredWithoutCache marks a reconciliation-recovered charge whose
// price snapshot has a distinct cache rate: request_logs only keep prompt and
// output totals, so the cache share was billed at the full input rate (7.5).
const ExceptionRecoveredWithoutCache = "recovered_without_cache"

var ErrCacheTrueUpNotApplicable = errors.New("billing charge is not a recovered charge awaiting cache true-up")

// CacheTrueUpResult describes a cache breakdown correction booked on the
// wallet ledger. The original charge record stays immutable.
type CacheTrueUpResult struct {
	RequestID       string
	OriginalMicros  Micros
	CorrectedMicros Micros
	DeltaMicros     Micros // corrected - original; negative means refunded
	Wallet          *Wallet
}

// TrueUpRecoveredCharge re-prices a recovered charge with the operator-verified
// cache breakdown, using the charge's immutable price snapshot, and books the
// difference: a refund when the recovery over-billed, an adjustment when it
// under-billed. A repeated call with the same breakdown is idempotent.
func (s *Store) TrueUpRecoveredCharge(ctx context.Context, tenantID, requestID string, cachedInputTokens, cacheWriteInputTokens int64, actorID string) (*CacheTrueUpResult, error) {
	if tenantID == "" || requestID == "" || actorID == "" || cachedInputTokens < 0 || cacheWriteInputTokens < 0 {
		return nil, fmt.Errorf("%w: invalid cache true-up", ErrInvalidWalletState)
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin billing cache true-up: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	charge, err := getChargeRecord(ctx, tx, tenantID, requestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCacheTrueUpNotApplicable
	}
	if err != nil {
		return nil, fmt.Errorf("read billing charge for cache true-up: %w", err)
	}
	var recovered bool
	if err := tx.QueryRow(ctx, `
		SELECT raw_usage_json->>'usage_source' = 'recovered_request_log'
		FROM billing_charge_records WHERE tenant_id = $1 AND request_id = $2
	`, tenantID, requestID).Scan(&recovered); err != nil {
		return nil, fmt.Errorf("read billing charge usage source: %w", err)
	}
	if !recovered || charge.Status != "settled" {
		return nil, ErrCacheTrueUpNotApplicable
	}
	corrected, err := CalculateDirectCharge(Usage{
		PromptTokens: charge.PromptTokens, CachedInputTokens: cachedInputTokens,
		CacheWriteInputTokens: cacheWriteInputTokens, OutputTokens: charge.OutputTokens,
		ReasoningTokens: charge.ReasoningTokens,
	}, DirectPrice{
		InputPerMillionMicros:       charge.InputPerMillionMicros,
		CachedInputPerMillionMicros: charge.CachedInputPerMillionMicros, HasCachedInputPrice: true,
		CacheWritePerMillionMicros: charge.CacheWritePerMillionMicros, HasCacheWritePrice: true,
		OutputPerMillionMicros: charge.OutputPerMillionMicros,
	})
	if err != nil {
		return nil, err
	}
	delta := corrected.TotalMicros - charge.AmountMicros
	result := &CacheTrueUpResult{RequestID: requestID, OriginalMicros: charge.AmountMicros, CorrectedMicros: corrected.TotalMicros, DeltaMicros: delta}

	wallet, err := getWalletForUpdate(ctx, tx, tenantID, charge.WalletID)
	if err != nil {
		return nil, err
	}
	var existingCached, existingWrite, existingDelta int64
	err = tx.QueryRow(ctx, `
		SELECT (detail_json->>'cached_input_tokens')::bigint, (detail_json->>'cache_write_input_tokens')::bigint, delta_micros
		FROM billing_exception_resolutions
		WHERE tenant_id = $1 AND request_id = $2 AND kind = $3
	`, tenantID, requestID, ExceptionRecoveredWithoutCache).Scan(&existingCached, &existingWrite, &existingDelta)
	switch {
	case err == nil:
		if existingCached != cachedInputTokens || existingWrite != cacheWriteInputTokens || existingDelta != int64(delta) {
			return nil, ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit idempotent billing cache true-up: %w", err)
		}
		result.Wallet = wallet
		return result, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("read billing cache true-up: %w", err)
	}

	if delta != 0 {
		// The ledger is the correction record: a refund returns over-billed
		// money; an adjustment books the remaining cost. Like settlement (D5),
		// an incurred cost is booked even if it overdraws the wallet.
		balance, err := addMicros(wallet.BalanceMicros, -delta)
		if err != nil {
			return nil, err
		}
		before := WalletState{BalanceMicros: wallet.BalanceMicros, ReservedMicros: wallet.ReservedMicros}
		next := WalletState{BalanceMicros: balance, ReservedMicros: wallet.ReservedMicros}
		wallet, err = updateWallet(ctx, tx, wallet, next)
		if err != nil {
			return nil, err
		}
		eventType := "refund"
		if delta > 0 {
			eventType = "adjustment"
		}
		metadata := map[string]any{
			"reason": "cache_true_up", "charge_id": charge.ID,
			"original_micros": int64(charge.AmountMicros), "corrected_micros": int64(corrected.TotalMicros),
			"cached_input_tokens": cachedInputTokens, "cache_write_input_tokens": cacheWriteInputTokens,
		}
		for key, value := range OverdraftLedgerMetadata(before, next) {
			metadata[key] = value
		}
		if err := insertLedger(ctx, tx, ledgerInsert{
			TenantID: tenantID, WalletID: wallet.ID, RequestID: requestID, EventType: eventType,
			BalanceDelta: -delta, BalanceAfter: wallet.BalanceMicros, ReservedAfter: wallet.ReservedMicros,
			IdempotencyKey: "cache-true-up:" + requestID, ActorType: "admin", ActorID: actorID,
			Metadata: metadata,
		}); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO billing_exception_resolutions
			(tenant_id, request_id, kind, resolution, delta_micros, detail_json, actor_id)
		VALUES ($1, $2, $3, 'cache_true_up', $4,
			jsonb_build_object('cached_input_tokens', $5::bigint, 'cache_write_input_tokens', $6::bigint,
				'original_micros', $7::bigint, 'corrected_micros', $8::bigint), $9)
	`, tenantID, requestID, ExceptionRecoveredWithoutCache, int64(delta), cachedInputTokens, cacheWriteInputTokens,
		int64(charge.AmountMicros), int64(corrected.TotalMicros), actorID); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrIdempotencyConflict
		}
		return nil, fmt.Errorf("record billing cache true-up: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit billing cache true-up: %w", err)
	}
	result.Wallet = wallet
	return result, nil
}
