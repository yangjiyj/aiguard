package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ChargeRecord struct {
	PricingExtras               PriceExtensions
	UsageExtras                 UsageExtensions
	ID                          string
	TenantID                    string
	WalletID                    string
	ReservationID               string
	PriceID                     string
	RequestID                   string
	ModelName                   string
	CustomerGroup               string
	CustomerGroupRatioPPM       int64
	UserID                      string
	DepartmentID                string
	DepartmentName              string
	ProjectID                   string
	ClientID                    string
	ProviderID                  string
	ProviderName                string
	ProviderType                string
	ModelID                     string
	TariffPlanID                string
	TariffPlanVersion           int
	TariffRuleID                string
	TariffBand                  string
	TariffMultiplierPPM         int64
	BillingTimezone             string
	AdmittedAt                  time.Time
	PromptTokens                int64
	CachedInputTokens           int64
	CacheWriteInputTokens       int64
	OutputTokens                int64
	ReasoningTokens             int64
	InputPerMillionMicros       Micros
	CachedInputPerMillionMicros Micros
	CacheWritePerMillionMicros  Micros
	OutputPerMillionMicros      Micros
	AmountMicros                Micros
	UpstreamCostMicros          *Micros
	PricingMode                 string
	Currency                    string
	Status                      string
	RawUsageJSON                json.RawMessage
	CreatedAt                   time.Time
}

func (s *Store) SettleCharge(
	ctx context.Context,
	tenantID, requestID string,
	price *ModelPrice,
	usage Usage,
	rawUsageJSON []byte,
	upstreamCost *Micros,
) (*ChargeRecord, *Wallet, error) {
	if tenantID == "" || requestID == "" || price == nil || price.TenantID != tenantID ||
		price.ID == "" || price.ModelName == "" {
		return nil, nil, ErrInvalidPrice
	}
	if upstreamCost != nil && *upstreamCost < 0 {
		return nil, nil, ErrInvalidPrice
	}
	if len(rawUsageJSON) == 0 {
		rawUsageJSON = []byte(`{}`)
	}
	if !json.Valid(rawUsageJSON) {
		return nil, nil, fmt.Errorf("%w: raw usage is not valid JSON", ErrInvalidUsage)
	}
	actualTokens, err := UsageTotalTokens(usage)
	if err != nil {
		return nil, nil, err
	}
	reservationQuote, err := s.GetReservation(ctx, tenantID, requestID)
	if err != nil {
		return nil, nil, err
	}
	groupRatioPPM := reservationQuote.CustomerGroupRatioPPM
	if groupRatioPPM == 0 {
		groupRatioPPM = ratioScale
	}
	basePrice, err := price.AsDirectPrice()
	if err != nil {
		return nil, nil, err
	}
	tariffMultiplierPPM := reservationQuote.TariffMultiplierPPM
	if tariffMultiplierPPM == 0 {
		tariffMultiplierPPM = TariffRatioFlat
	}
	directPrice, err := ApplyPriceRatios(basePrice, groupRatioPPM, tariffMultiplierPPM)
	if err != nil {
		return nil, nil, err
	}
	breakdown, err := CalculateDirectCharge(usage, directPrice)
	if err != nil {
		return nil, nil, err
	}
	cachedRate := directPrice.InputPerMillionMicros
	if directPrice.HasCachedInputPrice {
		cachedRate = directPrice.CachedInputPerMillionMicros
	}
	cacheWriteRate := directPrice.InputPerMillionMicros
	if directPrice.HasCacheWritePrice {
		cacheWriteRate = directPrice.CacheWritePerMillionMicros
	}
	expected := &ChargeRecord{
		PricingExtras: directPrice.Extensions, UsageExtras: usage.UsageExtensions,
		TenantID: tenantID, PriceID: price.ID, RequestID: requestID, ModelName: price.ModelName,
		CustomerGroupRatioPPM: groupRatioPPM,
		UserID:                reservationQuote.UserID, DepartmentID: reservationQuote.DepartmentID,
		DepartmentName: reservationQuote.DepartmentName,
		TariffPlanID:   reservationQuote.TariffPlanID, TariffPlanVersion: reservationQuote.TariffPlanVersion,
		TariffRuleID: reservationQuote.TariffRuleID, TariffBand: reservationQuote.TariffBand,
		TariffMultiplierPPM: tariffMultiplierPPM, BillingTimezone: reservationQuote.BillingTimezone,
		AdmittedAt:   reservationQuote.AdmittedAt,
		PromptTokens: usage.PromptTokens, CachedInputTokens: usage.CachedInputTokens,
		CacheWriteInputTokens: usage.CacheWriteInputTokens, OutputTokens: usage.OutputTokens,
		ReasoningTokens:             usage.ReasoningTokens,
		InputPerMillionMicros:       directPrice.InputPerMillionMicros,
		CachedInputPerMillionMicros: cachedRate,
		CacheWritePerMillionMicros:  cacheWriteRate,
		OutputPerMillionMicros:      directPrice.OutputPerMillionMicros,
		AmountMicros:                breakdown.TotalMicros, UpstreamCostMicros: upstreamCost,
		PricingMode: price.PricingMode, Currency: price.Currency, Status: "settled",
		RawUsageJSON: append(json.RawMessage(nil), rawUsageJSON...),
	}

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("begin billing charge settlement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	wallet, reservation, err := lockWalletReservation(ctx, tx, tenantID, requestID)
	if err != nil {
		return nil, nil, err
	}
	if reservation.CustomerGroup != reservationQuote.CustomerGroup || reservation.CustomerGroupRatioPPM != groupRatioPPM {
		return nil, nil, ErrIdempotencyConflict
	}
	expected.CustomerGroup = DefaultCustomerGroup
	if reservation.CustomerGroup != "" {
		expected.CustomerGroup = reservation.CustomerGroup
	}
	if err := releaseCustomerRequestLease(ctx, tx, tenantID, requestID); err != nil {
		return nil, nil, err
	}
	if wallet.Currency != price.Currency {
		return nil, nil, fmt.Errorf("%w: wallet and price currency differ", ErrInvalidPrice)
	}
	expected.WalletID = wallet.ID
	expected.ReservationID = reservation.ID
	dimensions, err := loadBillingRequestDimensions(ctx, tx, tenantID, requestID, reservation)
	if err != nil {
		return nil, nil, err
	}
	expected.ProjectID, expected.ClientID = dimensions.ProjectID, dimensions.ClientID
	expected.ProviderID, expected.ProviderName, expected.ProviderType = dimensions.ProviderID, dimensions.ProviderName, dimensions.ProviderType
	expected.ModelID = dimensions.ModelID

	existing, err := getChargeRecord(ctx, tx, tenantID, requestID)
	switch {
	case err == nil:
		// Automatic procurement cost belongs to the first settlement snapshot.
		// A gateway replay supplies nil; preserve that snapshot rather than
		// recomputing under current rates or comparing it against absent input.
		// Explicit caller-provided costs still participate in conflict checks.
		if upstreamCost == nil {
			expected.UpstreamCostMicros = existing.UpstreamCostMicros
		}
		if reservation.Status != ReservationSettled || !chargeMatches(existing, expected) {
			return nil, nil, ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, nil, fmt.Errorf("commit idempotent billing charge: %w", err)
		}
		return existing, wallet, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, nil, fmt.Errorf("read billing charge idempotency: %w", err)
	}
	if reservation.Status != ReservationReserved {
		return nil, nil, ErrIdempotencyConflict
	}
	// Legacy reservations have no quote. New gateway calls must always use one.
	if reservation.PriceID != "" && reservation.PriceID != price.ID {
		return nil, nil, ErrIdempotencyConflict
	}

	wallet, err = settleWalletFundingTx(ctx, tx, wallet, reservation, breakdown.TotalMicros, estimatedUsageEvidence(expected.RawUsageJSON), s.fundingNow())
	if err != nil {
		return nil, nil, err
	}
	if err := settleLimitUsage(ctx, tx, tenantID, wallet.UserID, reservation, breakdown.TotalMicros, actualTokens); err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	reservation.Status = ReservationSettled
	reservation.SettledMicros = &breakdown.TotalMicros
	reservation.FinalizedAt = &now
	result, err := tx.Exec(ctx, `
        UPDATE billing_reservations
        SET settled_micros = $1, status = 'settled', finalized_at = $2
        WHERE tenant_id = $3 AND id = $4 AND status = 'reserved'
    `, breakdown.TotalMicros, now, tenantID, reservation.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("update billing charge reservation: %w", err)
	}
	if result.RowsAffected() != 1 {
		return nil, nil, ErrIdempotencyConflict
	}

	if upstreamCost == nil {
		upstreamCost, err = ComputeUpstreamCost(ctx, tx, tenantID, dimensions.ProviderID, dimensions.ModelID, expected.ModelName, expected.Currency, usage)
		if err != nil {
			return nil, nil, err
		}
		expected.UpstreamCostMicros = upstreamCost
	}
	expected.ID = "charge_" + uuid.NewString()
	upstreamValue := any(nil)
	if upstreamCost != nil {
		upstreamValue = int64(*upstreamCost)
	}
	err = tx.QueryRow(ctx, `
        INSERT INTO billing_charge_records (
            id, tenant_id, wallet_id, reservation_id, price_id, request_id, model_name,
            customer_group, customer_group_ratio_ppm, prompt_tokens, cached_input_tokens, cache_write_input_tokens, output_tokens, reasoning_tokens,
            input_per_million_micros, cached_input_per_million_micros,
            cache_write_per_million_micros, output_per_million_micros,
            amount_micros, upstream_cost_micros, pricing_mode, currency, status, raw_usage_json,
			user_id, department_id, department_name, project_id, client_id,
			provider_id, provider_name, provider_type, model_id,
			tariff_plan_id, tariff_plan_version, tariff_rule_id, tariff_band,
			tariff_multiplier_ppm, billing_timezone, admitted_at, pricing_extras, usage_extras
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24::jsonb,
			NULLIF($25,''),NULLIF($26,''),$27,NULLIF($28,''),NULLIF($29,''),
			NULLIF($30,''),$31,$32,NULLIF($33,''),NULLIF($34,''),NULLIF($35,0),NULLIF($36,''),$37,$38,$39,$40,$41::jsonb,$42::jsonb
        ) RETURNING created_at
    `, expected.ID, expected.TenantID, expected.WalletID, expected.ReservationID,
		expected.PriceID, expected.RequestID, expected.ModelName,
		expected.CustomerGroup, expected.CustomerGroupRatioPPM, expected.PromptTokens, expected.CachedInputTokens, expected.CacheWriteInputTokens,
		expected.OutputTokens, expected.ReasoningTokens,
		expected.InputPerMillionMicros, expected.CachedInputPerMillionMicros,
		expected.CacheWritePerMillionMicros, expected.OutputPerMillionMicros,
		expected.AmountMicros, upstreamValue, expected.PricingMode, expected.Currency,
		expected.Status, string(expected.RawUsageJSON), expected.UserID, expected.DepartmentID,
		expected.DepartmentName, expected.ProjectID, expected.ClientID, expected.ProviderID,
		expected.ProviderName, expected.ProviderType, expected.ModelID, expected.TariffPlanID,
		expected.TariffPlanVersion, expected.TariffRuleID, expected.TariffBand,
		expected.TariffMultiplierPPM, expected.BillingTimezone, expected.AdmittedAt, jsonObject(expected.PricingExtras), jsonObject(expected.UsageExtras),
	).Scan(&expected.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, nil, ErrIdempotencyConflict
		}
		return nil, nil, fmt.Errorf("insert billing charge record: %w", err)
	}
	if err := insertBillingUsageFact(ctx, tx, expected, dimensions); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit billing charge settlement: %w", err)
	}
	return expected, wallet, nil
}

func getChargeRecord(ctx context.Context, tx pgx.Tx, tenantID, requestID string) (*ChargeRecord, error) {
	charge := &ChargeRecord{}
	var pricingExtras, usageExtras []byte
	var upstream *int64
	err := tx.QueryRow(ctx, `
        SELECT id, tenant_id, wallet_id, COALESCE(reservation_id, ''), COALESCE(price_id, ''),
               request_id, model_name, customer_group, customer_group_ratio_ppm, prompt_tokens, cached_input_tokens,
               cache_write_input_tokens, output_tokens, reasoning_tokens,
               input_per_million_micros, cached_input_per_million_micros,
               cache_write_per_million_micros, output_per_million_micros,
               amount_micros, upstream_cost_micros, pricing_mode, currency, status,
               raw_usage_json, COALESCE(user_id,''), COALESCE(department_id,''), department_name,
			   COALESCE(project_id,''), COALESCE(client_id,''), COALESCE(provider_id,''), provider_name, provider_type,
			   COALESCE(model_id,''), COALESCE(tariff_plan_id,''), COALESCE(tariff_plan_version,0),
			   COALESCE(tariff_rule_id,''), tariff_band, tariff_multiplier_ppm, billing_timezone,
			   COALESCE(admitted_at,created_at), created_at, pricing_extras, usage_extras
        FROM billing_charge_records
        WHERE tenant_id = $1 AND request_id = $2
    `, tenantID, requestID).Scan(
		&charge.ID, &charge.TenantID, &charge.WalletID, &charge.ReservationID, &charge.PriceID,
		&charge.RequestID, &charge.ModelName, &charge.CustomerGroup, &charge.CustomerGroupRatioPPM, &charge.PromptTokens, &charge.CachedInputTokens,
		&charge.CacheWriteInputTokens, &charge.OutputTokens, &charge.ReasoningTokens,
		&charge.InputPerMillionMicros, &charge.CachedInputPerMillionMicros,
		&charge.CacheWritePerMillionMicros, &charge.OutputPerMillionMicros,
		&charge.AmountMicros, &upstream, &charge.PricingMode, &charge.Currency,
		&charge.Status, &charge.RawUsageJSON, &charge.UserID, &charge.DepartmentID,
		&charge.DepartmentName, &charge.ProjectID, &charge.ClientID, &charge.ProviderID,
		&charge.ProviderName, &charge.ProviderType, &charge.ModelID, &charge.TariffPlanID,
		&charge.TariffPlanVersion, &charge.TariffRuleID, &charge.TariffBand,
		&charge.TariffMultiplierPPM, &charge.BillingTimezone, &charge.AdmittedAt, &charge.CreatedAt, &pricingExtras, &usageExtras,
	)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(pricingExtras, &charge.PricingExtras); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(usageExtras, &charge.UsageExtras); err != nil {
		return nil, err
	}
	if upstream != nil {
		value := Micros(*upstream)
		charge.UpstreamCostMicros = &value
	}
	return charge, nil
}

func chargeMatches(actual, expected *ChargeRecord) bool {
	if jsonObject(actual.PricingExtras) != jsonObject(expected.PricingExtras) || jsonObject(actual.UsageExtras) != jsonObject(expected.UsageExtras) {
		return false
	}
	if actual.WalletID != expected.WalletID || actual.ReservationID != expected.ReservationID ||
		actual.PriceID != expected.PriceID || actual.ModelName != expected.ModelName ||
		actual.CustomerGroup != expected.CustomerGroup || actual.CustomerGroupRatioPPM != expected.CustomerGroupRatioPPM ||
		actual.UserID != expected.UserID || actual.DepartmentID != expected.DepartmentID ||
		actual.ProjectID != expected.ProjectID || actual.ClientID != expected.ClientID ||
		actual.ProviderID != expected.ProviderID || actual.ModelID != expected.ModelID ||
		actual.TariffPlanID != expected.TariffPlanID || actual.TariffPlanVersion != expected.TariffPlanVersion ||
		actual.TariffRuleID != expected.TariffRuleID || actual.TariffBand != expected.TariffBand ||
		actual.TariffMultiplierPPM != expected.TariffMultiplierPPM || actual.BillingTimezone != expected.BillingTimezone ||
		actual.PromptTokens != expected.PromptTokens || actual.CachedInputTokens != expected.CachedInputTokens ||
		actual.CacheWriteInputTokens != expected.CacheWriteInputTokens || actual.OutputTokens != expected.OutputTokens ||
		actual.ReasoningTokens != expected.ReasoningTokens ||
		actual.InputPerMillionMicros != expected.InputPerMillionMicros ||
		actual.CachedInputPerMillionMicros != expected.CachedInputPerMillionMicros ||
		actual.CacheWritePerMillionMicros != expected.CacheWritePerMillionMicros ||
		actual.OutputPerMillionMicros != expected.OutputPerMillionMicros ||
		actual.AmountMicros != expected.AmountMicros || actual.PricingMode != expected.PricingMode ||
		actual.Currency != expected.Currency || actual.Status != expected.Status {
		return false
	}
	if actual.UpstreamCostMicros == nil || expected.UpstreamCostMicros == nil {
		return actual.UpstreamCostMicros == nil && expected.UpstreamCostMicros == nil
	}
	return *actual.UpstreamCostMicros == *expected.UpstreamCostMicros
}

type billingRequestDimensions struct {
	UserName     string
	ProjectID    string
	ProjectName  string
	ClientID     string
	ProviderID   string
	ProviderName string
	ProviderType string
	ModelID      string
	ModelName    string
	OccurredAt   time.Time
}

func loadBillingRequestDimensions(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, requestID string,
	reservation *Reservation,
) (billingRequestDimensions, error) {
	dimensions := billingRequestDimensions{
		ModelName:  reservation.ModelName,
		OccurredAt: reservation.AdmittedAt,
	}
	if dimensions.OccurredAt.IsZero() {
		dimensions.OccurredAt = time.Now().UTC()
	}
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(u.username, ''),
		       COALESCE(rl.project_id, ''), COALESCE(p.name, ''),
		       COALESCE(rl.client_id, ''),
		       COALESCE(rl.provider_id, ''), COALESCE(pv.name, ''), COALESCE(pv.provider_type, ''),
		       COALESCE(rl.model_id, ''),
		       COALESCE(NULLIF(m.model_label, ''), NULLIF(m.model_name, ''), NULLIF($4, ''), ''),
		       rl.created_at
		FROM request_logs rl
		LEFT JOIN users u
		  ON u.id = COALESCE(rl.user_id, NULLIF($3, ''))
		 AND u.tenant_id = rl.tenant_id
		LEFT JOIN projects p
		  ON p.id = rl.project_id
		 AND p.tenant_id = rl.tenant_id
		LEFT JOIN providers pv
		  ON pv.id = rl.provider_id
		 AND pv.tenant_id = rl.tenant_id
		LEFT JOIN models m
		  ON m.id = rl.model_id
		 AND m.provider_id = pv.id
		WHERE rl.tenant_id = $1 AND rl.request_id = $2
	`, tenantID, requestID, reservation.UserID, reservation.ModelName).Scan(
		&dimensions.UserName,
		&dimensions.ProjectID, &dimensions.ProjectName,
		&dimensions.ClientID,
		&dimensions.ProviderID, &dimensions.ProviderName, &dimensions.ProviderType,
		&dimensions.ModelID, &dimensions.ModelName, &dimensions.OccurredAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		// The financial settlement is authoritative even when the audit write was
		// unavailable. Keep a safely attributed fact instead of rolling back money.
		return dimensions, nil
	}
	if err != nil {
		return billingRequestDimensions{}, fmt.Errorf("load billing request dimensions: %w", err)
	}
	return dimensions, nil
}

func insertBillingUsageFact(
	ctx context.Context,
	tx pgx.Tx,
	charge *ChargeRecord,
	dimensions billingRequestDimensions,
) error {
	quality := "unknown"
	if charge.DepartmentID != "" {
		quality = "exact"
	}
	upstreamValue := any(nil)
	if charge.UpstreamCostMicros != nil {
		upstreamValue = int64(*charge.UpstreamCostMicros)
	}
	occurredAt := dimensions.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = charge.AdmittedAt
	}
	if occurredAt.IsZero() {
		occurredAt = charge.CreatedAt
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO billing_usage_facts (
			id, tenant_id, request_id, billing_mode,
			user_id, user_name, department_id, department_name,
			project_id, project_name, client_id,
			provider_id, provider_name, provider_type,
			model_id, model_name,
			prompt_tokens, cached_input_tokens, cache_write_input_tokens,
			output_tokens, reasoning_tokens,
			billable_amount_micros, upstream_cost_micros, currency, price_id,
			tariff_plan_id, tariff_plan_version, tariff_rule_id, tariff_band,
			tariff_multiplier_ppm, billing_timezone, attribution_quality,
			status, occurred_at, usage_extras,admitted_at,estimated
		) VALUES (
			$1,$2,$3,'prepaid',
			NULLIF($4,''),$5,NULLIF($6,''),$7,
			NULLIF($8,''),$9,NULLIF($10,''),
			NULLIF($11,''),$12,$13,
			NULLIF($14,''),$15,
			$16,$17,$18,$19,$20,$21,$22,$23,NULLIF($24,''),
			NULLIF($25,''),NULLIF($26,0),NULLIF($27,''),$28,$29,$30,$31,
			$32,$33,$34::jsonb,$35,$36
		)
	`, "usage_fact_"+uuid.NewString(), charge.TenantID, charge.RequestID,
		charge.UserID, dimensions.UserName, charge.DepartmentID, charge.DepartmentName,
		dimensions.ProjectID, dimensions.ProjectName, dimensions.ClientID,
		dimensions.ProviderID, dimensions.ProviderName, dimensions.ProviderType,
		dimensions.ModelID, dimensions.ModelName,
		charge.PromptTokens, charge.CachedInputTokens, charge.CacheWriteInputTokens,
		charge.OutputTokens, charge.ReasoningTokens,
		charge.AmountMicros, upstreamValue, charge.Currency, charge.PriceID,
		charge.TariffPlanID, charge.TariffPlanVersion, charge.TariffRuleID,
		charge.TariffBand, charge.TariffMultiplierPPM, charge.BillingTimezone,
		quality, charge.Status, occurredAt, jsonObject(charge.UsageExtras), charge.AdmittedAt, estimatedUsageEvidence(charge.RawUsageJSON),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrIdempotencyConflict
		}
		return fmt.Errorf("insert prepaid billing usage fact: %w", err)
	}
	return nil
}

// Financial and usage-evidence flags share the same append-only ledger row.
func withEstimatedLedgerMetadata(metadata map[string]any, estimated bool) map[string]any {
	if !estimated {
		return metadata
	}
	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["estimated"] = true
	return metadata
}

func estimatedUsageEvidence(raw []byte) bool {
	var evidence struct {
		UsageSource string `json:"usage_source"`
	}
	if json.Unmarshal(raw, &evidence) != nil {
		return false
	}
	switch evidence.UsageSource {
	case "estimated_reservation", "estimated_reservation_invalid_usage", "estimated_incomplete", "estimated_incomplete_invalid_usage":
		return true
	}
	return false
}
