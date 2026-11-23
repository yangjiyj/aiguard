package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

// Billing gateway APIs are only exposed through the existing internal shared
// secret boundary. The gateway never writes a price or balance itself.
type BillingReserveRequest struct {
	TenantID      string        `json:"tenant_id"`
	UserID        string        `json:"user_id"`
	RequestID     string        `json:"request_id"`
	ModelName     string        `json:"model_name"`
	CustomerGroup string        `json:"customer_group"`
	Usage         billing.Usage `json:"usage"`
	// OutputTokensUnbounded: the client sent no max_tokens and
	// Usage.OutputTokens is only the gateway ceiling (7.6).
	OutputTokensUnbounded bool `json:"output_tokens_unbounded"`
}

// applyOutputEstimate narrows an unbounded output reservation to the model's
// observed P95 (never above the gateway ceiling). It returns the estimate to
// report back, or nil when the request bounded its own output.
func (req *BillingReserveRequest) applyOutputEstimate(ctx context.Context, store *billing.Store) (*int64, error) {
	if !req.OutputTokensUnbounded {
		return nil, nil
	}
	estimate, _, err := store.EstimateOutputTokens(ctx, req.TenantID, req.ModelName)
	if err != nil {
		return nil, err
	}
	if req.Usage.OutputTokens <= 0 || estimate < req.Usage.OutputTokens {
		req.Usage.OutputTokens = estimate
	}
	value := req.Usage.OutputTokens
	return &value, nil
}

type gatewayBillingQuote struct {
	CustomerGroup *billing.CustomerGroup
	Price         *billing.ModelPrice
	Tariff        billing.TariffQuote
	AmountMicros  billing.Micros
	Tokens        int64
	AdmittedAt    time.Time
	// CustomerPrice 是叠加客户组与时段倍率后的实际单价，流式截断按它折算输出上限。
	CustomerPrice billing.DirectPrice
}

// maxStreamOutputTokenCap 以上的预算折算结果不构成合理约束，不下发。
const maxStreamOutputTokenCap int64 = 1_000_000

type streamOutputCapBudgetSource interface {
	EmployeeAllowanceBudgetFor(context.Context, string, string, string, string, time.Time) (billing.Micros, bool, error)
	UserBudgetPolicies(context.Context, string, string) ([]billing.BudgetPolicyScope, error)
}

// streamOutputTokenCap 仅为已配置金额额度的用户下发输出上限。
// 默认钱包准入仍生效，但钱包余额本身不等同于显式预算断流配置。
func streamOutputTokenCap(ctx context.Context, store streamOutputCapBudgetSource, req BillingReserveRequest, quote *gatewayBillingQuote, budget billing.Micros, hasBudget bool) *int64 {
	if store == nil || quote == nil || quote.Price == nil || !hasBudget {
		return nil
	}
	limit, ok, err := billing.OutputTokenCapForBudget(req.Usage, quote.CustomerPrice, budget)
	if err != nil || !ok || limit > maxStreamOutputTokenCap {
		return nil
	}
	// 旧的全局 BudgetCutoffEnabled 已移除；采用断流状态接口相同的额度来源。
	_, limited, err := store.EmployeeAllowanceBudgetFor(ctx, req.TenantID, req.UserID, req.RequestID, quote.Price.Currency, quote.AdmittedAt)
	if err != nil {
		return nil
	}
	if !limited {
		policies, err := store.UserBudgetPolicies(ctx, req.TenantID, req.UserID)
		if err != nil || len(policies) == 0 {
			return nil
		}
	}
	return &limit
}

// Fully free catalog prices still validate denomination and synchronize funding.
// A zero estimate for a nonzero price never bypasses the money admission guard.
func syncGatewayWalletFunding(ctx context.Context, store *billing.Store, req BillingReserveRequest, quote *gatewayBillingQuote) error {
	if req.UserID != "" && quote.Price.IsFullyFree() {
		_, err := store.EnsureMonthlyWalletGrant(ctx, req.TenantID, req.UserID, quote.Price.Currency, quote.AdmittedAt)
		return err
	}
	return store.ReserveEmployeeAllowance(ctx, req.TenantID, req.UserID, req.RequestID, quote.Price.Currency, int64(quote.AmountMicros), quote.AdmittedAt)
}

func resolveGatewayBillingQuote(
	ctx context.Context,
	store *billing.Store,
	tenantID, userID, modelName string,
	usage billing.Usage,
	admittedAt time.Time,
) (*gatewayBillingQuote, error) {
	if admittedAt.IsZero() {
		admittedAt = time.Now().UTC()
	}
	group := &billing.CustomerGroup{Code: billing.DefaultCustomerGroup, RatioPPM: 1_000_000}
	if userID != "" {
		resolved, err := store.ResolveCustomerGroupDetails(ctx, tenantID, userID)
		if err != nil {
			return nil, err
		}
		group = resolved
	}
	price, err := store.ResolveModelPrice(ctx, tenantID, modelName, group.Code, admittedAt)
	if err != nil {
		return nil, err
	}
	currency, err := store.BillingCurrencyForTenant(ctx, tenantID)
	// 没有币种设置、历史上又混用多种币种的租户推断不出系统币种：与 711 一致不拦截报价，
	// 价格取最近生效的一条；钱包币种由资金校验把关。只有明确知道系统币种时才做币种一致性检查。
	if err != nil && !errors.Is(err, billing.ErrMixedCurrency) {
		return nil, err
	}
	if err == nil && price.Currency != currency {
		return nil, billing.ErrPriceCurrencyMismatch
	}
	basePrice, err := price.AsDirectPrice()
	if err != nil {
		return nil, err
	}
	tariff, err := store.ResolveTariffQuoteForModel(ctx, tenantID, modelName, admittedAt)
	if err != nil {
		return nil, err
	}
	customerPrice, err := billing.ApplyPriceRatios(basePrice, group.RatioPPM, tariff.MultiplierPPM)
	if err != nil {
		return nil, err
	}
	charge, err := billing.CalculateDirectCharge(usage, customerPrice)
	if err != nil {
		return nil, err
	}
	tokens, err := billing.UsageTotalTokens(usage)
	if err != nil {
		return nil, err
	}
	return &gatewayBillingQuote{
		CustomerGroup: group, Price: price, Tariff: tariff,
		AmountMicros: charge.TotalMicros, Tokens: tokens, AdmittedAt: admittedAt,
		CustomerPrice: customerPrice,
	}, nil
}

type BillingFinalizeRequest struct {
	TenantID  string          `json:"tenant_id"`
	RequestID string          `json:"request_id"`
	Usage     billing.Usage   `json:"usage"`
	RawUsage  json.RawMessage `json:"raw_usage"`
}

type BillingReleaseRequest struct {
	TenantID  string `json:"tenant_id"`
	RequestID string `json:"request_id"`
}

type BillingMeasurementRequest struct {
	Unpriced              bool                 `json:"unpriced"`
	Estimated             bool                 `json:"estimated"`
	PriceID               string               `json:"price_id"`
	CustomerGroupRatioPPM *int64               `json:"customer_group_ratio_ppm"`
	TariffQuote           *billing.TariffQuote `json:"tariff_quote"`
	TenantID              string               `json:"tenant_id"`
	UserID                string               `json:"user_id"`
	RequestID             string               `json:"request_id"`
	ModelName             string               `json:"model_name"`
	RequestStatus         string               `json:"request_status"`
	Usage                 billing.Usage        `json:"usage"`
	RawUsage              json.RawMessage      `json:"raw_usage"`
	AdmittedAt            time.Time            `json:"admitted_at"`
	// 以下三个字段只属于正向代理（P1）：usage_source="forward_proxy" 时可不带 user_id，
	// 由控制面按 source_ip 的登录态解析唯一员工；usage_unknown=true 表示请求发生但解析不出用量。
	// 网关请求不带这些字段，行为与改造前一致。
	UsageSource  string `json:"usage_source"`
	SourceIP     string `json:"source_ip"`
	UsageUnknown bool   `json:"usage_unknown"`
}

func billingStore(deps *Dependencies) (*billing.Store, bool) {
	if deps == nil || deps.BillingStore == nil {
		return nil, false
	}
	return deps.BillingStore, true
}

const (
	billingModelPriceMissingCode      = "model_price_missing"
	billingModelPriceMissingMessage   = "该模型未配置价格，请联系管理员"
	billingInsufficientBalanceMessage = "余额不足，请充值"
)

func billingHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, billing.ErrInsufficientBalance):
		// Empty or overdrawn wallets are refused before contacting upstream.
		writeErrorWithStatus(w, http.StatusTooManyRequests, "insufficient_balance", billingInsufficientBalanceMessage)
	case errors.Is(err, billing.ErrImageVariantPriceNotFound):
		writeErrorWithStatus(w, http.StatusForbidden, "image_price_missing", "该图片尺寸与质量未配置价格，请联系管理员")
	case errors.Is(err, billing.ErrPriceCurrencyMismatch):
		writeErrorWithStatus(w, http.StatusConflict, "price_currency_mismatch", "该模型价格币种与系统币种不一致，请管理员重新设置价格")
	case errors.Is(err, billing.ErrAllowanceCurrency):
		writeErrorWithStatus(w, http.StatusConflict, "allowance_currency_mismatch", "钱包与模型价格币种不一致，系统不进行汇率转换")
	case errors.Is(err, billing.ErrPriceNotFound):
		// Administrative price lookups retain a stable error code. Gateway
		// admission handles this case explicitly as unpriced and allowed.
		writeErrorWithStatus(w, http.StatusForbidden, billingModelPriceMissingCode, billingModelPriceMissingMessage)
	case errors.Is(err, billing.ErrCustomerGroupNotFound):
		writeErrorWithStatus(w, http.StatusNotFound, "customer_group_not_found", "billing customer group is not configured or active")
	case errors.Is(err, billing.ErrTariffNotFound):
		writeErrorWithStatus(w, http.StatusNotFound, "tariff_not_found", "billing tariff plan was not found")
	case errors.Is(err, billing.ErrTariffNotDraft):
		writeErrorWithStatus(w, http.StatusConflict, "tariff_not_draft", "方案正在生效，请先停用后再删除")
	case errors.Is(err, billing.ErrCustomerRPMLimitExceeded):
		w.Header().Set("Retry-After", "60")
		writeErrorWithStatus(w, http.StatusTooManyRequests, "rpm_limit_exceeded", "已达到每分钟请求数上限")
	case errors.Is(err, billing.ErrCustomerConcurrencyLimitExceeded):
		w.Header().Set("Retry-After", "1")
		writeErrorWithStatus(w, http.StatusTooManyRequests, "concurrency_limit_exceeded", "已达到同时进行的请求数上限")
	case errors.Is(err, billing.ErrCustomerLimitExceeded):
		writeErrorWithStatus(w, http.StatusTooManyRequests, "usage_limit_exceeded", "已达到个人每日或每月使用上限")
	case errors.Is(err, billing.ErrIdempotencyConflict):
		writeErrorWithStatus(w, http.StatusConflict, "billing_idempotency_conflict", "本次操作与已有记录冲突，请重新加载后重试")
	case errors.Is(err, billing.ErrRedemptionInvalid), errors.Is(err, billing.ErrRedemptionUsed):
		writeErrorWithStatus(w, http.StatusBadRequest, "redemption_unavailable", "兑换码无效、已使用或已过期")
	case errors.Is(err, billing.ErrPriceCurrencyUnsupported):
		writeErrorWithStatus(w, http.StatusBadRequest, "price_currency_unsupported", "价格币种必须与钱包计价币种一致，系统不进行汇率转换")
	case errors.Is(err, billing.ErrMixedCurrency):
		// Mixed-currency analytics selections are refused, not summed: micros
		// totals across currencies are not a meaningful number. 409 keeps the
		// stable code contract while signaling a state the caller can fix by
		// narrowing the selection.
		writeErrorWithStatus(w, http.StatusConflict, "billing_currency_mixed", "analytics selection spans multiple currencies; totals are not summable, scope the selection to one currency")
	case errors.Is(err, billing.ErrInvalidCustomerLimit), errors.Is(err, billing.ErrInvalidUsage),
		errors.Is(err, billing.ErrInvalidPrice), errors.Is(err, billing.ErrInvalidWalletState),
		errors.Is(err, billing.ErrInvalidCustomerGroup), errors.Is(err, billing.ErrInvalidTariff):
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_billing_request", "invalid billing request")
	default:
		writeError(w, "billing_internal_error", "billing operation failed")
	}
}

func ReserveGatewayBilling(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		var req BillingReserveRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		req.TenantID, req.UserID, req.RequestID, req.ModelName = strings.TrimSpace(req.TenantID), strings.TrimSpace(req.UserID), strings.TrimSpace(req.RequestID), strings.TrimSpace(req.ModelName)
		if req.TenantID == "" || req.RequestID == "" || req.ModelName == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_billing_request", "tenant_id, request_id and model_name are required")
			return
		}
		estimatedOutput, err := req.applyOutputEstimate(r.Context(), store)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		admittedAt := time.Now().UTC()
		quote, err := resolveGatewayBillingQuote(r.Context(), store, req.TenantID, req.UserID, req.ModelName, req.Usage, admittedAt)
		if errors.Is(err, billing.ErrPriceNotFound) || errors.Is(err, billing.ErrImageVariantPriceNotFound) {
			writeJSON(w, map[string]any{"reserved": false, "unpriced": true, "admitted_at": admittedAt})
			return
		}
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		if req.UserID == "" {
			writeErrorWithStatus(w, http.StatusForbidden, "billing_account_missing", "API key must belong to a customer account for priced prepaid billing")
			return
		}
		if err := syncGatewayWalletFunding(r.Context(), store, req, quote); err != nil {
			employeeAllowanceHTTPError(w, err)
			return
		}
		allowanceReserved := true
		defer func() {
			if allowanceReserved {
				_ = store.ReleaseEmployeeAllowance(context.WithoutCancel(r.Context()), req.TenantID, req.RequestID)
			}
		}()
		wallet, err := store.EnsureMonthlyWalletGrant(r.Context(), req.TenantID, req.UserID, quote.Price.Currency, quote.AdmittedAt)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		if wallet == nil {
			billingHTTPError(w, billing.ErrInvalidWalletState)
			return
		}
		attribution, err := store.ResolveBillingAttribution(r.Context(), req.TenantID, req.UserID)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		reservation, wallet, err := store.ReservePricedWithUsageForGroupAndTariff(
			r.Context(), req.TenantID, wallet.ID, req.RequestID, quote.AmountMicros, quote.Tokens,
			quote.Price, quote.CustomerGroup.Code, quote.CustomerGroup.RatioPPM, attribution, quote.Tariff,
		)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		allowanceReserved = false
		response := map[string]any{"reserved": true, "reservation_id": reservation.ID, "customer_group": quote.CustomerGroup.Code, "customer_group_ratio_ppm": quote.CustomerGroup.RatioPPM, "tariff_band": quote.Tariff.Band, "tariff_multiplier_ppm": quote.Tariff.MultiplierPPM, "reserved_micros": reservation.ReservedMicros, "reserved_tokens": reservation.ReservedTokens, "available_micros": wallet.AvailableMicros(), "currency": wallet.Currency}
		response["price_id"] = reservation.PriceID
		response["admitted_at"] = reservation.AdmittedAt
		if estimatedOutput != nil {
			response["estimated_output_tokens"] = *estimatedOutput
		}
		// The reservation belongs to this request; other in-flight money is unavailable.
		walletBudget := reservation.ReservedMicros + wallet.AvailableMicros()
		if limit := streamOutputTokenCap(r.Context(), store, req, quote, walletBudget, true); limit != nil {
			response["stream_output_token_cap"] = *limit
		}
		writeJSON(w, response)
	}
}

func QuoteGatewayBilling(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		var req BillingReserveRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		req.TenantID = strings.TrimSpace(req.TenantID)
		req.UserID = strings.TrimSpace(req.UserID)
		req.ModelName = strings.TrimSpace(req.ModelName)
		if req.TenantID == "" || req.ModelName == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_billing_request", "tenant_id and model_name are required")
			return
		}
		estimatedOutput, err := req.applyOutputEstimate(r.Context(), store)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		quote, err := resolveGatewayBillingQuote(r.Context(), store, req.TenantID, req.UserID, req.ModelName, req.Usage, time.Now().UTC())
		if errors.Is(err, billing.ErrPriceNotFound) || errors.Is(err, billing.ErrImageVariantPriceNotFound) {
			writeJSON(w, map[string]any{"unpriced": true, "admitted_at": time.Now().UTC()})
			return
		}
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		if err := syncGatewayWalletFunding(r.Context(), store, req, quote); err != nil {
			employeeAllowanceHTTPError(w, err)
			return
		}
		// Human accounts use the same wallet in metering and prepaid modes.
		// The compatibility allowance call synchronizes monthly credits only.
		allowanceReserved := true
		defer func() {
			if allowanceReserved {
				_ = store.ReleaseEmployeeAllowance(context.WithoutCancel(r.Context()), req.TenantID, req.RequestID)
			}
		}()
		wallet, err := store.FindWalletForUser(r.Context(), req.TenantID, req.UserID, quote.Price.Currency)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		var walletBudget billing.Micros
		if wallet != nil {
			attribution, err := store.ResolveBillingAttribution(r.Context(), req.TenantID, req.UserID)
			if err != nil {
				billingHTTPError(w, err)
				return
			}
			reservation, current, err := store.ReservePricedWithUsageForGroupAndTariff(r.Context(), req.TenantID, wallet.ID, req.RequestID, quote.AmountMicros, quote.Tokens, quote.Price, quote.CustomerGroup.Code, quote.CustomerGroup.RatioPPM, attribution, quote.Tariff)
			if err != nil {
				billingHTTPError(w, err)
				return
			}
			walletBudget = reservation.ReservedMicros + current.AvailableMicros()
		}
		allowanceReserved = false

		response := map[string]any{
			"billable_amount_micros":   quote.AmountMicros,
			"estimated_tokens":         quote.Tokens,
			"currency":                 quote.Price.Currency,
			"admitted_at":              quote.AdmittedAt,
			"price_id":                 quote.Price.ID,
			"customer_group_ratio_ppm": quote.CustomerGroup.RatioPPM,
			"tariff_quote":             quote.Tariff,
		}
		if estimatedOutput != nil {
			response["estimated_output_tokens"] = *estimatedOutput
		}
		if wallet != nil {
			if limit := streamOutputTokenCap(r.Context(), store, req, quote, walletBudget, true); limit != nil {
				response["stream_output_token_cap"] = *limit
			}
		}
		writeJSON(w, response)
	}
}

func FinalizeGatewayBilling(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		var req BillingFinalizeRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		req.TenantID, req.RequestID = strings.TrimSpace(req.TenantID), strings.TrimSpace(req.RequestID)
		if req.TenantID == "" || req.RequestID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_billing_request", "tenant_id and request_id are required")
			return
		}
		reservation, err := store.GetReservation(r.Context(), req.TenantID, req.RequestID)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		if reservation.PriceID == "" {
			writeErrorWithStatus(w, http.StatusConflict, "billing_quote_missing", "reservation has no price quote")
			return
		}
		price, err := store.GetModelPriceByID(r.Context(), req.TenantID, reservation.PriceID)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		charge, wallet, err := store.SettleCharge(r.Context(), req.TenantID, req.RequestID, price, req.Usage, req.RawUsage, nil)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		_ = store.ReleaseEmployeeAllowance(r.Context(), req.TenantID, req.RequestID)
		writeJSON(w, map[string]any{"amount_micros": charge.AmountMicros, "available_micros": wallet.AvailableMicros(), "currency": wallet.Currency})
	}
}

func ReleaseGatewayBilling(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		var req BillingReleaseRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		if err := store.ReleaseEmployeeAllowance(r.Context(), req.TenantID, req.RequestID); err != nil {
			billingHTTPError(w, err)
			return
		}
		reservation, wallet, err := store.Release(r.Context(), strings.TrimSpace(req.TenantID), strings.TrimSpace(req.RequestID))
		if errors.Is(err, billing.ErrReservationNotFound) {
			writeJSON(w, map[string]any{"released": true})
			return
		}
		if err != nil {
			billingHTTPError(w, err)
			return
		}

		writeJSON(w, map[string]any{"reservation_id": reservation.ID, "available_micros": wallet.AvailableMicros(), "currency": wallet.Currency})
	}
}

func RecordGatewayMeasurement(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req BillingMeasurementRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		source := strings.ToLower(strings.TrimSpace(req.UsageSource))
		if source == "forward_proxy" || source == "reverse_proxy" {
			writeJSON(w, map[string]any{"recorded": false, "ignored": true, "usage_source": source})
			return
		}

		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		fact, err := store.RecordMeteringUsage(r.Context(), billing.MeteringInput{
			TenantID: req.TenantID, UserID: req.UserID, RequestID: req.RequestID,
			ModelName: req.ModelName, RequestStatus: req.RequestStatus,
			Usage: req.Usage, AdmittedAt: req.AdmittedAt, RawUsage: req.RawUsage,
			QuotePriceID: req.PriceID, QuoteGroupRatioPPM: req.CustomerGroupRatioPPM, QuoteTariff: req.TariffQuote,
			UsageSource: req.UsageSource, SourceIP: req.SourceIP, UsageUnknown: req.UsageUnknown,
			Unpriced: req.Unpriced, Estimated: req.Estimated,
		})
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		_ = store.ReleaseEmployeeAllowance(r.Context(), req.TenantID, req.RequestID)
		writeJSON(w, map[string]any{
			"recorded": true, "usage_fact_id": fact.ID, "status": fact.Status,
			"billable_amount_micros": fact.BillableAmountMicros, "currency": fact.Currency,
		})
	}
}

// GetPortalCustomerBilling is a portal-backend-only read model. The portal
// obtains user_id from its signed session; the browser never receives the
// integration secret and cannot choose another user directly.
func GetPortalCustomerBilling(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
		if userID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "user_required", "user_id is required")
			return
		}
		now := time.Now().UTC()
		monthly, err := store.MonthlyWalletStatus(r.Context(), tenantID, userID, now)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		summary, err := store.CustomerSummary(r.Context(), tenantID, userID, now.AddDate(0, 0, -30), 50)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		keys := []map[string]any{}
		if deps.KeyRepo != nil {
			items, err := deps.KeyRepo.ListByUser(r.Context(), tenantID, userID)
			if err != nil {
				writeError(w, "billing_internal_error", "failed to list customer keys")
				return
			}
			for _, key := range items {
				keys = append(keys, map[string]any{"id": key.ID, "name": key.Name, "prefix": key.KeyPrefix, "project_id": key.ProjectID, "scopes": key.Scopes, "status": key.Status, "created_at": key.CreatedAt, "last_used_at": key.LastUsedAt, "expires_at": key.ExpiresAt})
			}
		}
		projects := []map[string]any{}
		if deps.ProjectUserRepo != nil && deps.ProjectRepo != nil {
			projectIDs, err := deps.ProjectUserRepo.GetProjectsByUser(r.Context(), userID)
			if err != nil {
				writeError(w, "billing_internal_error", "failed to list customer projects")
				return
			}
			for _, projectID := range projectIDs {
				project, err := deps.ProjectRepo.GetByID(r.Context(), tenantID, projectID)
				if err != nil {
					writeError(w, "billing_internal_error", "failed to load customer project")
					return
				}
				if project == nil || project.Status != "active" {
					continue
				}
				projects = append(projects, map[string]any{"id": project.ID, "name": project.Name})
			}
		}
		data := map[string]any{
			"currency":       summary.Wallet.Currency,
			"wallet":         map[string]any{"currency": summary.Wallet.Currency, "balance_micros": summary.Wallet.BalanceMicros, "reserved_micros": summary.Wallet.ReservedMicros, "available_micros": summary.Wallet.AvailableMicros()},
			"monthly_status": monthly,
			"customer_group": summary.CustomerGroup,
			"usage":          summary.Usage,
			"daily":          summary.Daily,
			"limits":         summary.Limits,
			"models":         summary.Models,
			"charges":        summary.Charges,
			"failures":       summary.Failures,
			"generated_at":   summary.GeneratedAt,
		}
		// Keep the previous DTO for API compatibility; wallet money is authoritative.
		if allowance, err := store.EmployeeAllowanceForUser(r.Context(), tenantID, userID, time.Now().UTC()); err != nil {
			log.Printf("[portal_billing] employee allowance tenant=%s: %v", tenantID, err)
			data["employee_allowance"] = nil
		} else {
			data["employee_allowance"] = allowance
		}
		gatewayURL := strings.TrimSpace(r.Header.Get("X-JJDGuard-Gateway-URL"))
		if gatewayURL == "" && deps.SystemRepo != nil {
			if setting, err := deps.SystemRepo.Get(r.Context(), "gateway_public_base_url"); err == nil && setting != nil {
				gatewayURL = setting.Value
			}
		}
		writeJSON(w, map[string]any{"data": data, "keys": keys, "projects": projects, "api_url": normalizePortalGatewayURL(gatewayURL)})
	}
}

func normalizePortalGatewayURL(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	segments := strings.FieldsFunc(parsed.Path, func(r rune) bool { return r == '/' })
	for len(segments) > 0 && strings.EqualFold(segments[len(segments)-1], "v1") {
		segments = segments[:len(segments)-1]
	}
	segments = append(segments, "v1")
	parsed.Path = "/" + strings.Join(segments, "/")
	return strings.TrimRight(parsed.String(), "/")
}
