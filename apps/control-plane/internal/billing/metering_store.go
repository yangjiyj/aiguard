package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type MeteringInput struct {
	Unpriced           bool
	Estimated          bool
	QuotePriceID       string
	QuoteGroupRatioPPM *int64
	QuoteTariff        *TariffQuote
	TenantID           string
	UserID             string
	RequestID          string
	ModelName          string
	RequestStatus      string
	Usage              Usage
	AdmittedAt         time.Time
	// RawUsage is the durable evidence blob (usage_source, upstream usage)
	// produced by the gateway; it participates in the idempotency fingerprint
	// and is persisted verbatim for audit. nil keeps the column NULL.
	RawUsage []byte
	// UsageSource 标记事实来自哪条链路：空或 "gateway" 为网关 API；"forward_proxy" 为正向代理解密的
	// 大模型流量（P1）。正向代理只允许结算后记账，不经过预占。
	UsageSource string
	// SourceIP 仅正向代理使用：没有 user_id 时由控制面按“源 IP 登录态映射”解析唯一员工，
	// 解析到时归属质量为 inferred，解析不到 user 为空、归属为 unknown。
	SourceIP string
	// UsageUnknown 仅正向代理使用：请求已发生但解析不出 token 用量（如网页版 ChatGPT/Claude），
	// 记一条 token 全 0、金额 0 的 usage_unknown 事实进入计费待处理，不得静默丢弃。
	UsageUnknown bool
	// admittedAtSupplied is DERIVED from AdmittedAt at the store boundary (a
	// non-zero timestamp means the caller supplied one) and persisted as
	// migration 942's admitted_at_supplied column. The value alone cannot
	// express that intent — a defaulted timestamp is a real time — so a replay
	// omitting the field must stay distinguishable from one supplying a
	// different time.
	//
	// It is deliberately NOT exported: the HTTP measurement handler passes only
	// AdmittedAt, so an extra flag would be silently unset for a real request
	// that did carry a timestamp, persisting "not supplied" for a supplied time.
	// Deriving it here keeps the single source of truth beside the defaulting
	// logic it describes.
	admittedAtSupplied bool
}

type UsageFact struct {
	ID                   string
	TenantID             string
	RequestID            string
	BillingMode          string
	BillableAmountMicros *Micros
	Currency             string
	Status               string
	OccurredAt           time.Time
	// AdmittedAt is the persisted admission timestamp: replays return the
	// value fixed at first write instead of a recomputed one.
	AdmittedAt time.Time
	// EvidenceVerified is true when the full input (including raw request
	// status, admitted_at and the raw usage evidence) was compared against a
	// fact that carries the migration-942 evidence columns. It is false for
	// pre-942 legacy facts, which are accepted conservatively from their
	// derived status alone and are therefore explicitly marked unverified.
	EvidenceVerified bool
}

const (
	UsageSourceGateway      = "gateway"
	UsageSourceForwardProxy = "forward_proxy"
	// FactStatusUsageUnknown 是正向代理“请求发生了但用量解析不出来”的事实状态（迁移 954）。
	FactStatusUsageUnknown = "usage_unknown"
	// forwardProxySourceIPLoginWindow 与预算断流守卫解析源 IP 的窗口一致。
	forwardProxySourceIPLoginWindow = 12 * time.Hour
)

// RecordMeteringUsage writes an immutable usage fact and settles the quoted
// configured wallet in the same transaction. An unpriced admission is never
// charged, even when a price is subsequently added before finalization.
func (s *Store) RecordMeteringUsage(ctx context.Context, input MeteringInput) (*UsageFact, error) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.UserID = strings.TrimSpace(input.UserID)
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.ModelName = strings.TrimSpace(input.ModelName)
	input.RequestStatus = strings.ToLower(strings.TrimSpace(input.RequestStatus))
	input.UsageSource = strings.ToLower(strings.TrimSpace(input.UsageSource))
	input.SourceIP = strings.TrimSpace(input.SourceIP)
	if input.UsageSource == "" {
		input.UsageSource = UsageSourceGateway
	}
	if input.TenantID == "" || input.RequestID == "" || input.ModelName == "" {
		return nil, ErrInvalidUsage
	}
	if input.UsageSource == UsageSourceForwardProxy || input.UsageSource == "reverse_proxy" {
		return &UsageFact{TenantID: input.TenantID, RequestID: input.RequestID, Status: "observed"}, nil
	}

	switch input.UsageSource {
	case UsageSourceGateway:
		// source_ip 与 usage_unknown 只属于正向代理链路；网关始终带 user_id 与真实用量。
		if input.SourceIP != "" || input.UsageUnknown {
			return nil, fmt.Errorf("%w: source_ip/usage_unknown are forward-proxy only", ErrInvalidUsage)
		}
	case UsageSourceForwardProxy:
		// 正向代理按结算后记账，不接受准入报价。
		if input.QuotePriceID != "" || input.QuoteGroupRatioPPM != nil || input.QuoteTariff != nil {
			return nil, fmt.Errorf("%w: forward proxy facts carry no admission quote", ErrInvalidUsage)
		}
	default:
		return nil, fmt.Errorf("%w: unknown usage source %q", ErrInvalidUsage, input.UsageSource)
	}
	if input.UsageUnknown && !usageIsZero(input.Usage) {
		return nil, fmt.Errorf("%w: usage_unknown fact must not carry tokens", ErrInvalidUsage)
	}
	if _, err := UsageTotalTokens(input.Usage); err != nil {
		return nil, err
	}
	if len(input.RawUsage) > 0 && !json.Valid(input.RawUsage) {
		return nil, fmt.Errorf("%w: raw usage is not valid JSON", ErrInvalidUsage)
	}
	// Read immutable admission inputs without holding a pool connection across
	// store lookups. Re-lock and verify before the atomic fact/debit transaction.
	input.admittedAtSupplied = !input.AdmittedAt.IsZero()
	frozen, bindErr := s.GetReservation(ctx, input.TenantID, input.RequestID)
	var frozenWallet *Wallet
	if bindErr != nil && !errors.Is(bindErr, ErrReservationNotFound) {
		return nil, bindErr
	}
	if bindErr == nil {
		var e error
		frozenWallet, e = s.GetWallet(ctx, input.TenantID, frozen.WalletID)
		if e != nil {
			return nil, e
		}
		if e = bindMeteringReservation(&input, frozenWallet, frozen); e != nil {
			return nil, e
		}
	}
	if input.QuotePriceID != "" {
		if input.QuoteGroupRatioPPM != nil && (*input.QuoteGroupRatioPPM <= 0 || *input.QuoteGroupRatioPPM > MaxCustomerGroupRatioPPM) {
			return nil, ErrInvalidPrice
		}
		if input.QuoteTariff != nil && (input.QuoteTariff.MultiplierPPM <= 0 || input.QuoteTariff.MultiplierPPM > MaxCustomerGroupRatioPPM) {
			return nil, ErrInvalidPrice
		}
		var evidence map[string]any
		if len(input.RawUsage) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(input.RawUsage))
			decoder.UseNumber()
			if decoder.Decode(&evidence) != nil {
				return nil, ErrInvalidUsage
			}
		}
		if evidence == nil {
			evidence = map[string]any{}
		}
		evidence["billing_quote"] = map[string]any{"price_id": input.QuotePriceID, "group_ratio_ppm": input.QuoteGroupRatioPPM, "tariff": input.QuoteTariff}
		input.RawUsage, _ = json.Marshal(evidence)
	} else if input.QuoteGroupRatioPPM != nil || input.QuoteTariff != nil {
		return nil, ErrInvalidPrice
	}
	if input.UsageSource == UsageSourceForwardProxy {
		// 正向代理的归属线索（源 IP）与“用量未知”标记写进证据，参与幂等比对并留档审计。
		evidence, err := decodeMeteringEvidence(input.RawUsage)
		if err != nil {
			return nil, err
		}
		evidence["forward_proxy"] = map[string]any{"source_ip": input.SourceIP, "usage_unknown": input.UsageUnknown}
		input.RawUsage, _ = json.Marshal(evidence)
	}
	// A non-zero admitted_at IS the caller supplying one; anything else is the
	// store defaulting below. Deriving it here is what lets a plain HTTP
	// measurement (which carries only AdmittedAt) persist an honest true.
	if input.AdmittedAt.IsZero() {
		input.AdmittedAt = time.Now().UTC()
	}
	// PostgreSQL stores microseconds: normalize up front so a replay of the
	// same input compares equal against the persisted admitted_at.
	input.AdmittedAt = input.AdmittedAt.UTC().Truncate(time.Microsecond)

	// Durable fact first: a replay is answered from the persisted row without
	// recomputing attribution, tariff or price under current configuration.
	existing, err := readIdempotentMeteringFact(ctx, s.db, input)
	switch {
	case err == nil:
		return existing, nil
	case errors.Is(err, pgx.ErrNoRows):
		// No fact yet: fall through to compute and insert.
	case errors.Is(err, ErrIdempotencyConflict):
		return nil, err
	default:
		return nil, err
	}

	attribution := BillingAttribution{UserID: input.UserID}
	if input.UserID == "" && input.UsageSource == UsageSourceForwardProxy && input.SourceIP != "" {
		// 正向代理没有 user_id：按源 IP 登录态解析唯一员工（多人共用 IP 时不归属，宁可不归属也不误记）。
		resolvedUser, err := s.ResolveUserBySourceIP(ctx, input.TenantID, input.SourceIP, forwardProxySourceIPLoginWindow)
		if err != nil {
			return nil, err
		}
		input.UserID = resolvedUser
		attribution.UserID = resolvedUser
	}
	if input.UserID != "" {
		resolved, err := s.ResolveBillingAttribution(ctx, input.TenantID, input.UserID)
		if err == nil {
			attribution = resolved
		} else if !errors.Is(err, ErrInvalidWalletState) {
			return nil, err
		}
	}
	if frozen != nil {
		attribution.UserID = frozenWallet.UserID
		attribution.DepartmentID = frozen.DepartmentID
		attribution.DepartmentName = frozen.DepartmentName
	}
	groupRatio := int64(ratioScale)
	if input.UserID != "" && input.QuoteGroupRatioPPM == nil {
		if group, err := s.ResolveCustomerGroupDetails(ctx, input.TenantID, input.UserID); err == nil {
			groupRatio = group.RatioPPM
		} else if !errors.Is(err, ErrInvalidCustomerGroup) {
			return nil, err
		}
	}
	if input.QuoteGroupRatioPPM != nil {
		groupRatio = *input.QuoteGroupRatioPPM
	}
	var tariff TariffQuote
	if input.QuoteTariff != nil {
		tariff = *input.QuoteTariff
		err = nil
	} else {
		tariff, err = s.ResolveTariffQuoteForModel(ctx, input.TenantID, input.ModelName, input.AdmittedAt)
	}
	if err != nil {
		return nil, err
	}

	status := "failed"
	currency, currencyErr := s.BillingCurrencyForTenant(ctx, input.TenantID)
	if currencyErr != nil && !errors.Is(currencyErr, ErrMixedCurrency) {
		return nil, currencyErr
	}
	if currencyErr != nil {
		currency = s.DefaultCurrency()
	}
	var price *ModelPrice
	var amount *Micros
	succeeded := input.RequestStatus == "success" || input.RequestStatus == "incomplete"
	if succeeded && input.UsageUnknown {
		// 用量未知：金额记 0 并单列状态，既不算“已定价 0 元”，也不计入员工额度已用。
		zero := Micros(0)
		amount = &zero
		status = FactStatusUsageUnknown
	} else if succeeded && input.Unpriced {
		status = "unpriced"
	} else if succeeded {
		if input.QuotePriceID != "" {
			price, err = s.GetModelPriceByID(ctx, input.TenantID, input.QuotePriceID)
			if errors.Is(err, ErrPriceNotFound) {
				return nil, ErrInvalidPrice
			}
			if err == nil && price.ModelName != input.ModelName {
				return nil, ErrInvalidPrice
			}
		} else {
			price, err = s.ResolveModelPrice(ctx, input.TenantID, input.ModelName, DefaultCustomerGroup, input.AdmittedAt)
		}
		switch {
		case errors.Is(err, ErrPriceNotFound):
			status = "unpriced"
			err = nil
		case err != nil:
			return nil, err
		default:
			base, priceErr := price.AsDirectPrice()
			if priceErr != nil {
				return nil, priceErr
			}
			direct, priceErr := ApplyPriceRatios(base, groupRatio, tariff.MultiplierPPM)
			if priceErr != nil {
				return nil, priceErr
			}
			charge, priceErr := CalculateDirectCharge(input.Usage, direct)
			if priceErr != nil {
				return nil, priceErr
			}
			value := charge.TotalMicros
			amount = &value
			currency = price.Currency
			status = "settled"
		}
	}

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin metering fact: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	lockedWallet, locked, lockErr := lockWalletReservation(ctx, tx, input.TenantID, input.RequestID)
	if lockErr != nil && !errors.Is(lockErr, ErrReservationNotFound) {
		return nil, lockErr
	}
	if lockErr == nil {
		if frozen == nil {
			return nil, ErrIdempotencyConflict
		}
		checked := input
		if e := bindMeteringReservation(&checked, lockedWallet, locked); e != nil {
			return nil, e
		}
		if locked.UserID != frozen.UserID || locked.DepartmentID != frozen.DepartmentID || locked.DepartmentName != frozen.DepartmentName {
			return nil, ErrIdempotencyConflict
		}
	} else if frozen != nil {
		return nil, ErrIdempotencyConflict
	}
	dimensions, err := loadBillingRequestDimensions(ctx, tx, input.TenantID, input.RequestID, &Reservation{
		TenantID: input.TenantID, RequestID: input.RequestID, ModelName: input.ModelName,
		UserID: input.UserID, DepartmentID: attribution.DepartmentID,
		DepartmentName: attribution.DepartmentName, AdmittedAt: input.AdmittedAt,
	})
	if err != nil {
		return nil, err
	}
	if dimensions.UserName == "" && input.UsageSource == UsageSourceForwardProxy {
		// 正向代理：审计行尚未写入（异步）时用服务端解析出的员工名，账单不显示“未知用户”。
		// 网关路径保持原样。
		dimensions.UserName = attribution.UserName
	}
	quality := "unknown"
	if input.UsageSource == UsageSourceForwardProxy {
		if attribution.UserID != "" {
			quality = "inferred"
		}
	} else if attribution.DepartmentID != "" {
		quality = "exact"
	}
	priceID := ""
	if price != nil {
		priceID = price.ID
	}
	amountValue := any(nil)
	if amount != nil {
		amountValue = int64(*amount)
	}
	var upstreamCost *Micros
	if status == "settled" {
		upstreamCost, err = ComputeUpstreamCost(ctx, tx, input.TenantID, dimensions.ProviderID, dimensions.ModelID, input.ModelName, currency, input.Usage)
		if err != nil {
			return nil, err
		}
	}
	factID := "usage_fact_" + uuid.NewString()
	result, err := tx.Exec(ctx, `
		INSERT INTO billing_usage_facts (
		  id,tenant_id,request_id,billing_mode,user_id,user_name,
		  department_id,department_name,project_id,project_name,client_id,
		  provider_id,provider_name,provider_type,model_id,model_name,
		  prompt_tokens,cached_input_tokens,cache_write_input_tokens,output_tokens,reasoning_tokens,
		  billable_amount_micros,currency,price_id,
		  tariff_plan_id,tariff_plan_version,tariff_rule_id,tariff_band,
		  tariff_multiplier_ppm,billing_timezone,attribution_quality,status,occurred_at,
		  request_status,admitted_at,raw_usage_json,admitted_at_supplied,usage_extras,upstream_cost_micros,usage_source,estimated
		) VALUES (
		  $1,$2,$3,'metering',NULLIF($4,''),$5,NULLIF($6,''),$7,NULLIF($8,''),$9,NULLIF($10,''),
		  NULLIF($11,''),$12,$13,NULLIF($14,''),$15,
		  $16,$17,$18,$19,$20,$21,$22,NULLIF($23,''),
		  NULLIF($24,''),NULLIF($25,0),NULLIF($26,''),$27,$28,$29,$30,$31,$32,
		  $33,$34,NULLIF($35::text,'')::jsonb,$36,$37::jsonb,$38,$39,$40
		) ON CONFLICT (tenant_id,request_id) DO NOTHING
	`, factID, input.TenantID, input.RequestID, attribution.UserID, dimensions.UserName,
		attribution.DepartmentID, attribution.DepartmentName,
		dimensions.ProjectID, dimensions.ProjectName, dimensions.ClientID,
		dimensions.ProviderID, dimensions.ProviderName, dimensions.ProviderType,
		dimensions.ModelID, dimensions.ModelName,
		input.Usage.PromptTokens, input.Usage.CachedInputTokens, input.Usage.CacheWriteInputTokens,
		input.Usage.OutputTokens, input.Usage.ReasoningTokens,
		amountValue, currency, priceID, tariff.PlanID, tariff.PlanVersion, tariff.RuleID,
		tariff.Band, tariff.MultiplierPPM, tariff.Timezone, quality, status, dimensions.OccurredAt,
		input.RequestStatus, input.AdmittedAt, rawUsageText(input.RawUsage), input.admittedAtSupplied, jsonObject(input.Usage.UsageExtensions), upstreamCost, input.UsageSource, input.Estimated && status == "settled",
	)
	if err != nil {
		return nil, fmt.Errorf("insert metering usage fact: %w", err)
	}
	if result.RowsAffected() == 0 {
		// Idempotent replay: the durable fact wins. Return the persisted
		// result when the replayed evidence matches, and flag a conflict when
		// a different input tries to reuse the same (tenant, request) key so
		// attribution and price snapshots stay stable at their first write.
		return readIdempotentMeteringFact(ctx, tx, input)
	}
	if status == "settled" && amount != nil {
		if err := s.settleMeteringWallet(ctx, tx, input, currency, *amount); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM billing_employee_reservations WHERE tenant_id=$1 AND request_id=$2`, input.TenantID, input.RequestID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit metering usage fact: %w", err)
	}
	return &UsageFact{
		ID: factID, TenantID: input.TenantID, RequestID: input.RequestID,
		BillingMode: meteringBillingMode, BillableAmountMicros: amount,
		Currency: currency, Status: status, OccurredAt: dimensions.OccurredAt,
		AdmittedAt:       input.AdmittedAt,
		EvidenceVerified: true,
	}, nil
}

// meteringStatusFamily maps a request status to the outcome family it can
// produce: success/incomplete settle (or stay unpriced when no price exists),
// everything else is a failure. Full-input idempotency compares families, so
// a replay claiming a different outcome conflicts while the settled/unpriced
// distinction — which depends on price configuration, not the input — stays
// snapshot-stable.
func meteringStatusFamily(requestStatus string) string {
	switch requestStatus {
	case "success", "incomplete":
		return "settled-or-unpriced"
	}
	return "failed"
}

func persistedStatusFamily(status string) string {
	switch status {
	case "settled", "unpriced", FactStatusUsageUnknown:
		return "settled-or-unpriced"
	}
	return "failed"
}

// meteringBillingMode is the billing_mode value every metering fact carries.
// The idempotent replay check compares it so a prepaid settlement fact (which
// shares the same tenant_id/request_id key) can never be returned as if it were
// a metering measurement.
const meteringBillingMode = "metering"

func rawUsageText(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

// readIdempotentMeteringFact returns the persisted usage fact for a replayed
// metering input. Same input (user, model and token evidence) returns the
// durable result — including its original attribution and price snapshot —
// instead of values recomputed under current configuration. Different input
// under the same request key is rejected as a conflict.
// meteringQuerier abstracts the row query so the durable-first pre-check
// (pool) and the in-transaction conflict fallback (tx) share one code path.
type meteringQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func readIdempotentMeteringFact(ctx context.Context, q meteringQuerier, input MeteringInput) (*UsageFact, error) {
	var (
		factID, billingMode, userID, modelName, status, currency, usageSource string
		prompt, cached, cacheWrite, output, reasoning                         int64
		amount                                                                *int64
		occurredAt                                                            time.Time
		admittedAt                                                            *time.Time
		requestStatus                                                         *string
		admittedAtSupplied                                                    *bool
	)
	// The raw usage equality is decided by PostgreSQL, not by comparing Go
	// bytes: jsonb normalizes numeric literals ('1e2' and '100' are the same
	// jsonb value, as are '1.0' and '1') and reorders object keys. A Go-side
	// literal comparison would report a false conflict for a genuine replay
	// whose exponent or trailing-zero form differs, and with token counts
	// beyond 2^53 it could also mask a real difference. raw_usage_json IS NOT
	// DISTINCT FROM $3::jsonb covers the NULL-vs-absent case in the same
	// statement.
	var rawUsageEqual, usageExtrasEqual bool
	err := q.QueryRow(ctx, `
		SELECT id, billing_mode, COALESCE(user_id,''), model_name,
		       prompt_tokens, cached_input_tokens, cache_write_input_tokens,
		       output_tokens, reasoning_tokens,
		       billable_amount_micros, currency, status, occurred_at,
		       request_status, admitted_at, admitted_at_supplied,
		       (raw_usage_json IS NOT DISTINCT FROM $3::jsonb) AS raw_usage_equal,
		       (usage_extras = $4::jsonb) AS usage_extras_equal,
		       usage_source
		FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2
	`, input.TenantID, input.RequestID, rawUsageText(input.RawUsage), jsonObject(input.Usage.UsageExtensions)).Scan(
		&factID, &billingMode, &userID, &modelName,
		&prompt, &cached, &cacheWrite, &output, &reasoning,
		&amount, &currency, &status, &occurredAt,
		&requestStatus, &admittedAt, &admittedAtSupplied, &rawUsageEqual, &usageExtrasEqual,
		&usageSource,
	)
	if err != nil {
		return nil, fmt.Errorf("read idempotent metering fact: %w", err)
	}
	// A fact written by the prepaid settlement path shares the
	// (tenant_id, request_id) key but is not a metering fact at all. Handing it
	// back as a metering replay would report a settled charge the caller never
	// made, so the mode is part of the compared input.
	if billingMode != meteringBillingMode {
		return nil, fmt.Errorf("%w: request %s is a %s fact, not a metering fact",
			ErrIdempotencyConflict, input.RequestID, billingMode)
	}
	evidence := meteringEvidenceMatches(status, requestStatus, admittedAt, admittedAtSupplied, rawUsageEqual, input)
	if usageSource != input.UsageSource {
		return nil, fmt.Errorf("%w: usage source differs for request %s", ErrIdempotencyConflict, input.RequestID)
	}
	// 正向代理的 user 是控制面按源 IP 推断的（源 IP 已在证据里比对），重放不带 user_id 时不比 user。
	inferredUser := input.UsageSource == UsageSourceForwardProxy && input.UserID == ""
	if (!inferredUser && userID != input.UserID) || modelName != input.ModelName ||
		prompt != input.Usage.PromptTokens || cached != input.Usage.CachedInputTokens ||
		cacheWrite != input.Usage.CacheWriteInputTokens || output != input.Usage.OutputTokens ||
		reasoning != input.Usage.ReasoningTokens || !usageExtrasEqual || !evidence.Matches {
		return nil, fmt.Errorf("%w: metering evidence differs for request %s", ErrIdempotencyConflict, input.RequestID)
	}
	var billable *Micros
	if amount != nil {
		value := Micros(*amount)
		billable = &value
	}
	factAdmittedAt := time.Time{}
	if admittedAt != nil {
		factAdmittedAt = *admittedAt
	}
	return &UsageFact{
		ID: factID, TenantID: input.TenantID, RequestID: input.RequestID,
		BillingMode: billingMode, BillableAmountMicros: billable,
		Currency: currency, Status: status, OccurredAt: occurredAt,
		AdmittedAt: factAdmittedAt, EvidenceVerified: evidence.Verified,
	}, nil
}

// meteringEvidence is the outcome of comparing a replayed input against the
// durable evidence of a persisted fact.
//
// Verified is deliberately NOT "a 942 row exists". It means every field the
// caller controls was compared AND agreed. A field the caller did not supply is
// not a gap: its ABSENCE is the input, and a matching absence is a comparison
// that succeeded. The store's defaulted timestamp is an internal first-write
// value, not an upstream claim, so it needs no attestation of its own and must
// not by itself downgrade a full-input match.
//
// The only unverified case is a NULL presence bit — a row written before the
// column existed, which carries no admission-intent information at all and is
// never backfilled.
type meteringEvidence struct {
	// Matches is false when a supplied field contradicts the persisted fact, or
	// when caller intent itself changed (a field supplied on one side and
	// omitted on the other).
	Matches bool
	// Verified is true when status, admission-time presence and raw usage were
	// all compared and agreed on a row that records presence.
	Verified bool
}

// meteringEvidenceMatches compares the durable evidence of a persisted fact
// with the replayed input. A fact written after migration 942 stores the raw
// request status, admitted_at, the caller's admitted_at presence bit and the
// raw usage evidence. Pre-942 facts keep NULL in all of them; for those the
// comparison falls back to the conservative outcome-family check derived from
// the always-present status column, and the result is reported unverified
// rather than silently claiming a full match.
//
// rawUsageEqual is PostgreSQL's jsonb verdict (raw_usage_json IS NOT DISTINCT
// FROM $n::jsonb), not a Go byte comparison: jsonb normalizes numeric literals,
// so '1e2' and '100' are the same value and a literal comparison would fail a
// genuine replay. Because that verdict is computed in SQL against a typed
// jsonb, an absent (NULL) raw usage is explicitly compared as absence rather
// than being skipped because a Go slice happened to be empty.
func meteringEvidenceMatches(
	persistedDerivedStatus string,
	persistedStatus *string,
	persistedAdmittedAt *time.Time,
	persistedSupplied *bool,
	rawUsageEqual bool,
	input MeteringInput,
) meteringEvidence {
	if persistedStatus == nil {
		// Legacy row: compare against the derived status column, which
		// predates migration 942 and is always present. Only that one
		// comparison happened, so the result is never "verified".
		family := meteringStatusFamily(input.RequestStatus) == persistedStatusFamily(persistedDerivedStatus)
		return meteringEvidence{Matches: family, Verified: false}
	}
	if *persistedStatus != strings.TrimSpace(input.RequestStatus) {
		return meteringEvidence{Matches: false, Verified: false}
	}
	// The admission timestamp is compared on the CALLER'S INTENT, not on the
	// stored value, because a defaulted timestamp is a real time and cannot
	// distinguish "the caller sent this" from "the store filled it in".
	//
	//	both supplied  -> compare at PostgreSQL microsecond precision
	//	both omitted   -> absence matches absence; reuse the first default
	//	one only       -> the replay changed the input: conflict
	//
	// A NULL presence bit means the row predates the column (or was written by
	// something that did not record intent). It is never coerced to false and
	// never backfilled, and the time is left unchecked rather than compared from
	// a value whose provenance is unknown.
	//
	// presenceVerified records that the caller's intent was compared and agreed.
	// Both-supplied compares the values; both-omitted compares the matching
	// absence. Either is a completed comparison of a caller-supplied field, so
	// neither downgrades verification: the store default is an internal value
	// that needs no upstream attestation, and omitting the time is itself the
	// input that was compared.
	presenceVerified := false
	if persistedSupplied == nil {
		// No presence information: leave the field unchecked, which keeps the
		// replay compatible and honest (Verified stays false) instead of
		// manufacturing a conflict out of absent bookkeeping or backfilling a
		// presence bit the row never had.
	} else if *persistedSupplied && input.admittedAtSupplied {
		if persistedAdmittedAt == nil ||
			!persistedAdmittedAt.UTC().Truncate(time.Microsecond).Equal(input.AdmittedAt) {
			return meteringEvidence{Matches: false, Verified: false}
		}
		presenceVerified = true
	} else if *persistedSupplied != input.admittedAtSupplied {
		// First write supplied a time and the replay omitted it (or the
		// reverse). The persisted default is not evidence of caller intent, so
		// this is a real difference between the two inputs.
		return meteringEvidence{Matches: false, Verified: false}
	} else {
		// Both omitted: the ABSENCE matched, and the stored default is returned
		// so attribution keeps the first write's timestamp.
		presenceVerified = true
	}
	if !rawUsageEqual {
		return meteringEvidence{Matches: false, Verified: false}
	}
	// The raw usage blob is compared by PostgreSQL on every call, including the
	// both-absent case (NULL IS NOT DISTINCT FROM NULL), so absence is an
	// explicitly compared value rather than an unchecked field. Every
	// caller-supplied field has therefore been compared, and the only
	// unverified case is a NULL presence bit — a row that predates the column.
	return meteringEvidence{
		Matches:  true,
		Verified: presenceVerified,
	}
}

func usageIsZero(usage Usage) bool {
	return usage.PromptTokens == 0 && usage.CachedInputTokens == 0 && usage.CacheWriteInputTokens == 0 &&
		usage.OutputTokens == 0 && usage.ReasoningTokens == 0 && jsonObject(usage.UsageExtensions) == "{}"
}

// decodeMeteringEvidence 把调用方给的证据解成对象，以便追加控制面侧字段；空证据视为空对象。
func decodeMeteringEvidence(raw []byte) (map[string]any, error) {
	evidence := map[string]any{}
	if len(raw) == 0 {
		return evidence, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&evidence) != nil || evidence == nil {
		return nil, ErrInvalidUsage
	}
	return evidence, nil
}

// settleMeteringWallet runs in the same transaction as the unique usage fact.
// A monetary hold is created at quote time only for an existing wallet.
func (s *Store) settleMeteringWallet(ctx context.Context, tx pgx.Tx, input MeteringInput, currency string, amount Micros) error {
	wallet, reservation, err := lockWalletReservation(ctx, tx, input.TenantID, input.RequestID)
	if errors.Is(err, ErrReservationNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if reservation.Status != ReservationReserved {
		return ErrIdempotencyConflict
	}
	if wallet.Currency != currency {
		return ErrAllowanceCurrency
	}
	wallet, err = settleWalletFundingTx(ctx, tx, wallet, reservation, amount, input.Estimated, s.fundingNow())
	if err != nil {
		return err
	}
	tokens, err := UsageTotalTokens(input.Usage)
	if err != nil {
		return err
	}
	if err = settleLimitUsage(ctx, tx, input.TenantID, wallet.UserID, reservation, amount, tokens); err != nil {
		return err
	}
	if err = releaseCustomerRequestLease(ctx, tx, input.TenantID, input.RequestID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE billing_reservations SET status='settled',settled_micros=$3,finalized_at=NOW() WHERE tenant_id=$1 AND request_id=$2`, input.TenantID, input.RequestID, amount); err != nil {
		return err
	}
	return nil
}
