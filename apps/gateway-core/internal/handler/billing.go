package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/billingmedia"
	billingstates "github.com/yangjiyj/aiguard/packages/shared-go/billingstates"
)

const billingInternalTokenHeader = "X-JJDGuard-Internal-Token"

// billingModelPriceMissingCode is the control-plane error code for a model
// without a configured price (D6).
const billingModelPriceMissingCode = "model_price_missing"

type BillingAdmissionError struct {
	Code       string
	HTTPStatus int
	Message    string
	RetryAfter string
	cutoff     bool
}

func (e *BillingAdmissionError) Error() string { return e.Message }
func (e *BillingAdmissionError) RetryAfterValue() string {
	if e == nil {
		return ""
	}
	return e.RetryAfter
}

// BillingPreflight is intentionally narrow: only a successful reservation is
// allowed to reach an upstream provider. Finalization is performed by the
// audit writer wrapper so every success/failure exit keeps the wallet correct.
type BillingPreflight interface {
	Reserve(context.Context, *modelrouter.RequestEnvelope, *ChatCompletionRequest) error
	ReserveUsage(context.Context, *modelrouter.RequestEnvelope, BillingUsage) error
}

type BillingUsage struct {
	ImageRequest           bool                             `json:"image_request,omitempty"`
	ImageSize              string                           `json:"image_size,omitempty"`
	ImageQuality           string                           `json:"image_quality,omitempty"`
	ImageOutputTokens      int64                            `json:"image_output_tokens,omitempty"`
	ImageVariants          []billingmedia.ImageVariantUsage `json:"image_variants,omitempty"`
	PromptTokens           int64                            `json:"prompt_tokens"`
	CachedInputTokens      int64                            `json:"cached_input_tokens"`
	CacheWriteTokens       int64                            `json:"cache_write_input_tokens"`
	OutputTokens           int64                            `json:"output_tokens"`
	ReasoningTokens        int64                            `json:"reasoning_tokens"`
	ImageInputTokens       int64                            `json:"image_input_tokens,omitempty"`
	CachedImageInputTokens int64                            `json:"cached_image_input_tokens,omitempty"`
	ImageCount             int64                            `json:"image_count,omitempty"`
	ToolCalls              map[string]int64                 `json:"tool_calls,omitempty"`
	// OutputUnbounded marks OutputTokens as a ceiling rather than a client
	// bound (no max_tokens); the control plane may reserve less (7.6).
	OutputUnbounded bool `json:"-"`
}

// defaultOutputTokenCeiling bounds the reservation for a request without
// max_tokens. The control plane narrows it to the model's observed P95.
const defaultOutputTokenCeiling = 4096

type BillingClient struct {
	AllowanceRequired    func(context.Context, string, string) (bool, error)
	ModelPriceConfigured func(context.Context, string, string) (bool, error)
	// cutoff 为空表示不存在断流能力，所有行为与改造前一致。
	baseURL       string
	internalToken string
	group         string
	mode          string
	httpClient    *http.Client
	reserved      sync.Map // request_id -> struct{}
	// tenantCurrency: tenant_id -> 最近一次从控制面成功拿到的计价币种。
	// 控制面不可用（5xx/超时/未配置）时，限额提示仍按租户币种显示金额符号。
	tenantCurrency sync.Map
}

type billingTrackingState struct {
	Unpriced              bool
	CustomerGroupRatioPPM *int64
	TariffQuote           json.RawMessage
	Usage                 BillingUsage
	AdmittedAt            time.Time
	PriceID               string
	// StreamOutputTokenCap 是“预算断流”开启时控制面下发的流式输出上限；为空表示不截断。
	StreamOutputTokenCap *int64
	// Admitted records that the control plane actually admitted this
	// request: a quote was priced (metering) or a reservation was created
	// (prepaid). It is the real evidence behind the estimated_* usage
	// sources — set from the admission response, never assumed. A
	// legitimately free admission (quoted or reserved amount 0) still
	// counts as admitted: the amount is never the test.
	Admitted bool
}

// 断流提示文案与 governor 包保持一致（handler 包不依赖 governor 常量以外的符号）。
const (
	governorBillingUnavailableMessage      = "计费服务暂不可用，请稍后重试"
	governorModelPriceMissingCutoffMessage = "该模型未配置价格，已暂停使用，请联系管理员"
)

// cutoffUserHasMoneyQuota 判断当前请求主体是否配置了金额额度（员工月额度）。
// 第二个返回值为 false 表示无法判断，调用方按“未知”处理：断流开启时无法判断也视为受限，宁可拒绝。
// A local authoritative absence of a model price keeps the no-charge contract
// even when the control-plane HTTP service is temporarily unavailable.
func (c *BillingClient) allowKnownUnpriced(ctx context.Context, envelope *modelrouter.RequestEnvelope, state billingTrackingState) bool {
	if c.ModelPriceConfigured == nil {
		return false
	}
	priced, err := c.ModelPriceConfigured(ctx, envelope.TenantID, envelope.Model)
	if err != nil || priced {
		return false
	}
	state.Unpriced = true
	envelope.QuotaCostEstimateMissingPrice = true
	c.reserved.Store(envelope.RequestID, state)
	return true
}

func NewBillingClient(baseURL, internalToken, group string) *BillingClient {
	return NewBillingClientWithMode(baseURL, internalToken, group, "prepaid")
}

func NewBillingClientWithMode(baseURL, internalToken, group, mode string) *BillingClient {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "metering" && mode != "prepaid" {
		mode = "prepaid"
	}
	return &BillingClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), internalToken: internalToken,
		group: strings.TrimSpace(group), mode: mode, httpClient: &http.Client{Timeout: 3 * time.Second},
	}
}

func (c *BillingClient) Reserve(ctx context.Context, envelope *modelrouter.RequestEnvelope, request *ChatCompletionRequest) error {
	if c == nil || envelope == nil || request == nil {
		return nil
	}
	prompt := estimateChatPromptTokens(request)
	maxOutput := int64(request.MaxTokens)
	if request.MaxCompletionTokens > 0 {
		maxOutput = int64(request.MaxCompletionTokens)
	}
	unbounded := maxOutput <= 0
	if unbounded {
		maxOutput = defaultOutputTokenCeiling
	}
	return c.ReserveUsage(ctx, envelope, BillingUsage{PromptTokens: prompt, OutputTokens: maxOutput, OutputUnbounded: unbounded})
}

func (c *BillingClient) ReserveUsage(ctx context.Context, envelope *modelrouter.RequestEnvelope, usage BillingUsage) error {
	applyTrustedProxyBillingIngress(ctx, envelope)
	if c == nil || envelope == nil || !directModelBilling(envelope) {
		return nil
	}
	state := billingTrackingState{Usage: usage, AdmittedAt: time.Now().UTC()}
	// 先套用缓存币种：下面的早返回路径（AllowanceRequired 报错、控制面不可用、已知未定价放行）
	// 拿不到控制面响应，成功响应则会用 result.Currency 覆盖。
	c.applyCachedTenantCurrency(envelope)
	limited := c.mode == "prepaid"
	if c.AllowanceRequired != nil {
		var err error
		limited, err = c.AllowanceRequired(ctx, envelope.TenantID, envelope.UserID)
		if err != nil {
			if c.allowKnownUnpriced(ctx, envelope, state) {
				return nil
			}
			return &BillingAdmissionError{Code: "billing_unavailable", HTTPStatus: http.StatusServiceUnavailable, Message: governorBillingUnavailableMessage, cutoff: true}
		}
	}
	if c.baseURL == "" || strings.TrimSpace(c.internalToken) == "" {
		if c.allowKnownUnpriced(ctx, envelope, state) {
			return nil
		}
		if limited {
			return &BillingAdmissionError{Code: "billing_unavailable", HTTPStatus: http.StatusServiceUnavailable, Message: governorBillingUnavailableMessage, cutoff: true}
		}
		c.reserved.Store(envelope.RequestID, state)
		return nil
	}
	payload := map[string]any{"tenant_id": envelope.TenantID, "user_id": envelope.UserID, "request_id": envelope.RequestID, "model_name": envelope.Model, "customer_group": c.group, "usage": usage}
	if usage.OutputUnbounded {
		payload["output_tokens_unbounded"] = true
	}
	path := "/internal/v1/billing/quotes"
	if c.mode == "prepaid" {
		path = "/internal/v1/billing/reservations"
	}
	var result billingControlPlaneResponse
	status, retryAfter, err := c.post(ctx, path, payload, &result)
	code, message := result.errorDetail()
	if err == nil && (code == billingModelPriceMissingCode || code == "image_price_missing") {
		result.Unpriced = true // compatibility with control planes before this upgrade
	} else if err != nil || status < 200 || status >= 300 {
		if err != nil || status >= 500 || status == http.StatusRequestTimeout {
			if c.allowKnownUnpriced(ctx, envelope, state) {
				return nil
			}
			if limited {
				return &BillingAdmissionError{Code: "billing_unavailable", HTTPStatus: http.StatusServiceUnavailable, Message: governorBillingUnavailableMessage, cutoff: true}
			}
			c.reserved.Store(envelope.RequestID, state)
			return nil
		}
		return &BillingAdmissionError{Code: mapBillingStatusCode(status, code), HTTPStatus: status, Message: nonEmpty(message, "billing admission denied"), RetryAfter: retryAfter, cutoff: true}
	}
	if result.AdmittedAt != nil && !result.AdmittedAt.IsZero() {
		state.AdmittedAt = result.AdmittedAt.UTC()
	}
	state.Unpriced = result.Unpriced
	state.Usage = result.applyOutputEstimate(state.Usage)
	state.PriceID = result.PriceID
	state.CustomerGroupRatioPPM = result.CustomerGroupRatioPPM
	state.TariffQuote = append(json.RawMessage(nil), result.TariffQuote...)
	state.Admitted = result.PriceID != "" && result.AdmittedAt != nil && !result.AdmittedAt.IsZero()
	state.StreamOutputTokenCap = result.StreamOutputTokenCap
	c.reserved.Store(envelope.RequestID, state)
	envelope.QuotaCostEstimateMissingPrice = result.Unpriced
	applyBillingCostCurrency(envelope, result.Currency)
	c.rememberTenantCurrency(envelope.TenantID, result.Currency)
	if c.mode == "metering" {
		applyBillingCostEstimate(envelope, result.BillableAmountMicros)
	} else {
		applyBillingCostEstimate(envelope, result.ReservedMicros)
	}
	return nil
}

func (c *BillingClient) Finalize(ctx context.Context, envelope *modelrouter.RequestEnvelope, response []byte, status string) string {
	applyTrustedProxyBillingIngress(ctx, envelope)
	if c == nil || envelope == nil || !directModelBilling(envelope) {
		return ""
	}
	if envelope.BillingUsageSource == "" {
		envelope.BillingUsageSource = c.deriveUsageSource(envelope, response, status)
	}
	state, ok := c.trackingState(envelope.RequestID)
	if !ok {
		return ""
	}
	path := "/internal/v1/billing/releases"
	payload := map[string]any{"tenant_id": envelope.TenantID, "request_id": envelope.RequestID}
	if c.mode == "metering" || state.Unpriced {
		path = "/internal/v1/billing/measurements"
		payload["user_id"] = envelope.UserID
		payload["model_name"] = envelope.Model
		payload["request_status"] = status
		payload["admitted_at"] = state.AdmittedAt
		payload["unpriced"] = state.Unpriced
		if state.PriceID != "" {
			payload["price_id"] = state.PriceID
		}
		if state.CustomerGroupRatioPPM != nil {
			payload["customer_group_ratio_ppm"] = *state.CustomerGroupRatioPPM
		}
		if len(state.TariffQuote) > 0 {
			payload["tariff_quote"] = state.TariffQuote
		}
	}
	// Derive the authoritative usage source first: the shared Decide gate in
	// packages/shared-go/billingstates consumes it, so the real-time settle
	// decision and control-plane reconciliation share one evidence rule. The
	// same function feeds request_logs, so the log and the charge can never
	// disagree about where the usage came from.
	usageSource := envelope.BillingUsageSource
	if usageSource == streamBudgetUsageUnavailable {
		usageSource = "estimated_incomplete"
		envelope.BillingUsageSource = usageSource
	}
	// Keep all three terminal kinds distinct. Collapsing this into a
	// settle/not-settle boolean sends TerminalPending to the default
	// releases path below, which would refund a request whose evidence was
	// merely insufficient — pending means "hold the freeze", not "give the
	// money back".
	terminal := billingstates.Decide(status, billingstates.Evidence{
		UsageRecorded:       true,
		UsageSource:         usageSource,
		HasApprovedEstimate: state.Admitted && state.PriceID != "" && !state.AdmittedAt.IsZero(),
	})
	if status == "provider_error" || status == "error" {
		terminal = billingstates.TerminalRelease
	}
	if c.mode != "metering" && !state.Unpriced && terminal == billingstates.TerminalPending {
		envelope.BillingOutcome = "pending"
		return "pending"
	}
	if c.mode == "metering" || state.Unpriced || terminal == billingstates.TerminalSettle {
		if c.mode != "metering" && !state.Unpriced {
			path = "/internal/v1/billing/settlements"
		}
		if c.mode == "metering" && status != "success" && status != "incomplete" {
			payload["usage"] = BillingUsage{}
		} else {
			payload["usage"] = finalBillingUsage(state, response, status)
		}
		payload["raw_usage"] = billingUsageEvidence(response, usageSource)
		payload["estimated"] = strings.HasPrefix(usageSource, "estimated_")
	}
	// Request cancellation must not cancel accounting. Settlement endpoints are
	// idempotent, so a short bounded retry is safe for transient failures.
	finalizeCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if c.mode == "metering" && status != "success" && status != "incomplete" {
		var released billingControlPlaneResponse
		if releaseStatus, _, releaseErr := c.post(finalizeCtx, "/internal/v1/billing/releases", map[string]any{"tenant_id": envelope.TenantID, "request_id": envelope.RequestID}, &released); releaseErr != nil || releaseStatus < 200 || releaseStatus >= 300 {
			log.Printf("billing immediate release failed request=%s http=%d err=%v", envelope.RequestID, releaseStatus, releaseErr)
		}
	}

	var httpStatus int
	var err error
	var result billingControlPlaneResponse
	for attempt := 1; attempt <= 3; attempt++ {
		result = billingControlPlaneResponse{}
		httpStatus, _, err = c.post(finalizeCtx, path, payload, &result)
		if err == nil && httpStatus >= 200 && httpStatus < 300 {
			c.reserved.Delete(envelope.RequestID)
			if c.mode == "metering" || state.Unpriced {
				applyBillingActualCost(envelope, result.BillableAmountMicros)
				envelope.BillingOutcome = "recorded"
				return "recorded"
			}
			if terminal == billingstates.TerminalSettle {
				applyBillingActualCost(envelope, result.AmountMicros)
				envelope.BillingOutcome = "settled"
				return "settled"
			}
			// Only a definitive non-dispatch gets here; pending already
			// returned above without contacting the control plane at all.
			envelope.BillingOutcome = "released"
			return "released"
		}
		if attempt < 3 {
			select {
			case <-finalizeCtx.Done():
				attempt = 3
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			}
		}
	}
	log.Printf("billing finalize failed request=%s status=%s http=%d err=%v", envelope.RequestID, status, httpStatus, err)
	envelope.BillingOutcome = "failed"
	return "failed"
}

// applyBillingCostCurrency 记录控制面返回的计价币种，供断流提示选择金额符号；空值不覆盖已有记录。
func applyBillingCostCurrency(envelope *modelrouter.RequestEnvelope, currency string) {
	currency = strings.ToUpper(strings.TrimSpace(currency))
	if envelope == nil || currency == "" {
		return
	}
	envelope.QuotaCostCurrency = currency
}

// rememberTenantCurrency 按租户缓存控制面成功返回的币种（与 applyBillingCostCurrency 同一规范化）；
// 空租户或空币种不写，避免无租户请求共用一个币种。
func (c *BillingClient) rememberTenantCurrency(tenantID, currency string) {
	currency = strings.ToUpper(strings.TrimSpace(currency))
	if c == nil || tenantID == "" || currency == "" {
		return
	}
	c.tenantCurrency.Store(tenantID, currency)
}

// applyCachedTenantCurrency 在信封还没有币种时套用该租户最近一次成功拿到的币种；没有缓存就保持为空，不猜币种。
func (c *BillingClient) applyCachedTenantCurrency(envelope *modelrouter.RequestEnvelope) {
	if c == nil || envelope == nil || envelope.TenantID == "" || envelope.QuotaCostCurrency != "" {
		return
	}
	if cached, ok := c.tenantCurrency.Load(envelope.TenantID); ok {
		if currency, _ := cached.(string); currency != "" {
			envelope.QuotaCostCurrency = currency
		}
	}
}

func applyBillingCostEstimate(envelope *modelrouter.RequestEnvelope, amount *int64) {
	if envelope == nil || amount == nil || *amount < 0 || *amount > maxExactTokenCount {
		return
	}
	envelope.QuotaEstimatedCostMicros = *amount
	envelope.QuotaCostEstimateAvailable = true
}

func applyBillingActualCost(envelope *modelrouter.RequestEnvelope, amount *int64) {
	if envelope == nil || amount == nil || *amount < 0 || *amount > maxExactTokenCount {
		return
	}
	envelope.QuotaActualCostMicros = *amount
	envelope.QuotaActualCostAvailable = true
}

// One calculation supplies live settlement and durable compensation evidence.
// This contains only usage counters and specifications, never image payloads.
func finalBillingUsage(state billingTrackingState, response []byte, status string) BillingUsage {
	canonical := canonicalizeResponseUsage(response)
	extras := responseUsageExtensions(response)
	usage := state.Usage
	if state.StreamOutputTokenCap != nil && *state.StreamOutputTokenCap < usage.OutputTokens {
		usage.OutputTokens = *state.StreamOutputTokenCap
	}
	if verifiedUsageState(canonical.State) && !(status == "incomplete" && canonical.PromptTokens == 0 && canonical.OutputTokens == 0) {
		usage = BillingUsage{
			PromptTokens: canonical.PromptTokens, CachedInputTokens: canonical.CachedInputTokens,
			CacheWriteTokens: canonical.CacheWriteTokens, OutputTokens: canonical.OutputTokens,
			ReasoningTokens: canonical.ReasoningTokens, ImageInputTokens: canonical.ImageInputTokens,
			CachedImageInputTokens: canonical.CachedImageInputTokens, ImageOutputTokens: canonical.ImageOutputTokens,
			ImageCount: canonical.ImageCount, ToolCalls: canonical.ToolCalls,
		}
	} else {
		if status == "incomplete" || status == "success" {
			var partial ChatCompletionResponse
			if json.Unmarshal(response, &partial) == nil {
				var delivered int64
				for _, choice := range partial.Choices {
					delivered += estimateTextTokens(choice.Message.Content) + estimateTextTokens(choice.Message.ReasoningContent)
					for _, tool := range choice.Message.ToolCalls {
						delivered += estimateTextTokens(tool.Function.Name) + estimateTextTokens(tool.Function.Arguments)
					}
				}
				if delivered > 0 {
					usage.OutputTokens = delivered
				}
			}
			if state.StreamOutputTokenCap != nil && usage.OutputTokens > *state.StreamOutputTokenCap {
				usage.OutputTokens = *state.StreamOutputTokenCap
			}
		}
		if extras.ImageCountMeasured {
			usage.ImageCount = extras.ImageCount
		}
		if len(extras.ToolCalls) > 0 {
			usage.ToolCalls = extras.ToolCalls
		}
		usage.ImageInputTokens = extras.ImageInputTokens
		usage.CachedImageInputTokens = extras.CachedImageInputTokens
	}
	if state.Usage.ImageRequest && (status == "success" || status == "incomplete") {
		usage.ImageRequest = true
		usage.ImageSize, usage.ImageQuality = state.Usage.ImageSize, state.Usage.ImageQuality
		if extras.ImageSize != "" {
			usage.ImageSize = extras.ImageSize
		}
		if extras.ImageQuality != "" {
			usage.ImageQuality = extras.ImageQuality
		}
		usage.ImageCount = state.Usage.ImageCount
		if extras.ImageCountMeasured {
			usage.ImageCount = extras.ImageCount
		}
		usage.ImageVariants = append([]billingmedia.ImageVariantUsage(nil), extras.ImageVariants...)
		for i := range usage.ImageVariants {
			if usage.ImageVariants[i].Size == "" {
				usage.ImageVariants[i].Size = usage.ImageSize
			}
			if usage.ImageVariants[i].Quality == "" {
				usage.ImageVariants[i].Quality = usage.ImageQuality
			}
		}
		usage.ImageOutputTokens = extras.ImageOutputTokens
		if !extras.ImageOutputMeasured && verifiedUsageState(canonical.State) {
			usage.ImageOutputTokens = canonical.OutputTokens - canonical.ReasoningTokens
		}
	}
	return usage
}

// StreamBudget 返回准入时下发的流式输出上限与本次输入 token 估算；未下发时 ok=false。
func (c *BillingClient) StreamBudget(requestID string) (int64, int64, bool) {
	state, ok := c.trackingState(requestID)
	if !ok || state.StreamOutputTokenCap == nil || *state.StreamOutputTokenCap < 0 {
		return 0, 0, false
	}
	return *state.StreamOutputTokenCap, state.Usage.PromptTokens, true
}

func (c *BillingClient) trackingState(requestID string) (billingTrackingState, bool) {
	if c == nil || strings.TrimSpace(requestID) == "" {
		return billingTrackingState{}, false
	}
	tracked, ok := c.reserved.Load(requestID)
	if !ok {
		return billingTrackingState{}, false
	}
	state, valid := tracked.(billingTrackingState)
	if valid {
		return state, true
	}
	state = billingTrackingState{AdmittedAt: time.Now().UTC()}
	if legacyUsage, legacyOK := tracked.(BillingUsage); legacyOK {
		state.Usage = legacyUsage
	}
	return state, true
}

// auditResponseBody supplies the admission estimate to the request-log parser
// only when a provider omitted usage. Billing settlement still receives the
// original response and independently records usage_source=estimated_reservation.
// deriveUsageSource is the single authority for the billing usage_source
// marker. It is a pure function of three durable inputs — the raw provider
// body, the accounting status, and whether an admission snapshot was actually
// granted — so the marker persisted to request_logs and the marker the settle
// decision was made on are the same value by construction.
//
// The returned values are exactly the enumerated set control-plane
// reconciliation accepts (see packages/shared-go/billingstates): the two
// provider-verified markers, the four estimated markers, and
// synthetic_no_upstream. An empty result means "no admission happened", which
// reconciliation treats as a legacy row rather than as verified usage.
//
// An estimated_* marker is emitted only when state.Admitted is true. Emitting
// one for an unadmitted request would claim an approved estimate that never
// existed, and reconciliation would either settle it on that claim or — if the
// admission snapshot is missing — hold it pending forever.
// unknownUsageSource marks a live request whose usage source could not be
// established (no verified provider usage and no approved admission estimate).
// It is deliberately NOT the empty string: an empty usage_source in
// request_logs marks a pre-942 legacy row and earns a compatibility settle in
// packages/shared-go/billingstates, which must never apply to a request this
// gateway is finalizing right now. The value is not part of the enumerated
// source set, so reconciliation treats it as unrecognized and holds the row.
const unknownUsageSource = "unknown_no_admission_evidence"

func (c *BillingClient) deriveUsageSource(envelope *modelrouter.RequestEnvelope, response []byte, status string) string {
	if c == nil {
		return ""
	}
	_, _, usageState := responseUsageTokenState(response)
	if verifiedUsageState(usageState) && !(status == "incomplete" && canonicalizeResponseUsage(response).PromptTokens == 0 && canonicalizeResponseUsage(response).OutputTokens == 0) {
		if usageState == "upstream_total_adjusted" {
			return usageState
		}
		return "upstream"
	}
	// The provider omitted or mangled usage. An estimate may only be claimed
	// when the admission snapshot was really granted.
	admitted := false
	if envelope != nil {
		if state, ok := c.trackingState(envelope.RequestID); ok {
			admitted = state.Admitted && state.PriceID != "" && !state.AdmittedAt.IsZero()
		}
	}
	if !admitted {
		// No admission means no approved estimate may be claimed. The marker
		// must NOT be returned as "": an empty marker is how a pre-942 legacy
		// row is represented, and Decide would take the legacy success-recovery
		// branch and settle a request that never had an admission snapshot. A
		// live request is never legacy, so it is marked explicitly unknown and
		// falls through to pending.
		return unknownUsageSource
	}
	switch {
	case status == "incomplete" && usageState == "invalid":
		return "estimated_incomplete_invalid_usage"
	case status == "incomplete":
		return "estimated_incomplete"
	case usageState == "invalid":
		return "estimated_reservation_invalid_usage"
	default:
		return "estimated_reservation"
	}
}

func (c *BillingClient) auditResponseBody(envelope *modelrouter.RequestEnvelope, response []byte) []byte {
	if c == nil || envelope == nil || len(response) == 0 {
		return response
	}
	if _, _, usagePresent := verifiedResponseUsageTokens(response); usagePresent {
		return response
	}
	state, ok := c.trackingState(envelope.RequestID)
	if !ok || !state.Admitted || state.PriceID == "" || state.AdmittedAt.IsZero() || !hasNonzeroBillingUsage(map[string]int64{
		"prompt_tokens": state.Usage.PromptTokens,
		"output_tokens": state.Usage.OutputTokens,
	}) {
		return response
	}
	return injectBillingUsage(response, state.Usage)
}

func injectBillingUsage(response []byte, usage BillingUsage) []byte {
	var payload map[string]any
	if err := json.Unmarshal(response, &payload); err != nil || payload == nil {
		return response
	}
	payload["usage"] = map[string]any{
		"prompt_tokens":     maxInt64(usage.PromptTokens, 0),
		"completion_tokens": maxInt64(usage.OutputTokens, 0),
		"total_tokens":      maxInt64(usage.PromptTokens, 0) + maxInt64(usage.OutputTokens, 0),
		"input_tokens":      maxInt64(usage.PromptTokens, 0),
		"output_tokens":     maxInt64(usage.OutputTokens, 0),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return response
	}
	return encoded
}

func hasNonzeroBillingUsage(usage map[string]int64) bool {
	for _, value := range usage {
		if value > 0 {
			return true
		}
	}
	return false
}

func verifiedResponseUsageTokens(response []byte) (int64, int64, bool) {
	prompt, completion, state := responseUsageTokenState(response)
	return prompt, completion, verifiedUsageState(state)
}

func verifiedUsageState(state string) bool {
	return state == "upstream" || state == "upstream_total_adjusted"
}

func responseUsageTokenState(response []byte) (int64, int64, string) {
	usage := canonicalizeResponseUsage(response)
	return usage.PromptTokens, usage.OutputTokens, usage.State
}

func billingUsageEvidence(response []byte, source string) json.RawMessage {
	evidence := map[string]any{"usage_source": source, "usage_extras": responseUsageExtensions(response)}
	var payload struct {
		Usage json.RawMessage `json:"usage"`
	}
	const maxRawUsageBytes = 64 << 10
	if len(response) > 0 && json.Unmarshal(response, &payload) == nil &&
		len(payload.Usage) > 0 && len(payload.Usage) <= maxRawUsageBytes && json.Valid(payload.Usage) {
		evidence["upstream_usage"] = payload.Usage
	} else {
		evidence["upstream_usage_available"] = false
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return json.RawMessage(`{"usage_source":"unknown"}`)
	}
	return json.RawMessage(encoded)
}

type billingControlPlaneResponse struct {
	Unpriced              bool            `json:"unpriced"`
	CustomerGroupRatioPPM *int64          `json:"customer_group_ratio_ppm"`
	TariffQuote           json.RawMessage `json:"tariff_quote"`
	PriceID               string          `json:"price_id"`
	Reserved              bool            `json:"reserved"`
	ReservedMicros        *int64          `json:"reserved_micros"`
	AmountMicros          *int64          `json:"amount_micros"`
	BillableAmountMicros  *int64          `json:"billable_amount_micros"`
	AdmittedAt            *time.Time      `json:"admitted_at"`
	Error                 json.RawMessage `json:"error"`
	Message               string          `json:"message"`
	// Currency 是控制面本次计价的币种；老版本控制面不返回时为空。
	Currency string `json:"currency"`
	// EstimatedOutputTokens is the control plane's output reservation for an
	// unbounded request (7.6); absent from older control planes.
	EstimatedOutputTokens *int64 `json:"estimated_output_tokens"`
	// StreamOutputTokenCap 只在预算断流开启时出现，见 streamBudgetGuard。
	StreamOutputTokenCap *int64 `json:"stream_output_token_cap"`
}

func (r billingControlPlaneResponse) applyOutputEstimate(usage BillingUsage) BillingUsage {
	if usage.OutputUnbounded && r.EstimatedOutputTokens != nil &&
		*r.EstimatedOutputTokens > 0 && *r.EstimatedOutputTokens < usage.OutputTokens {
		usage.OutputTokens = *r.EstimatedOutputTokens
	}
	return usage
}

func (r billingControlPlaneResponse) errorDetail() (string, string) {
	var detail struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if len(r.Error) > 0 && json.Unmarshal(r.Error, &detail) == nil && (detail.Code != "" || detail.Message != "") {
		return detail.Code, nonEmpty(detail.Message, r.Message)
	}
	var legacyCode string
	if len(r.Error) > 0 && json.Unmarshal(r.Error, &legacyCode) == nil {
		return legacyCode, r.Message
	}
	return "", r.Message
}

func (c *BillingClient) post(ctx context.Context, path string, payload any, out any) (int, string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(billingInternalTokenHeader, c.internalToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, normalizeRetryAfter(resp.Header.Get("Retry-After")), err
		}
	}
	return resp.StatusCode, normalizeRetryAfter(resp.Header.Get("Retry-After")), nil
}

// Prompt estimation (7.6). Counting UTF-8 bytes billed every CJK character as
// three tokens, roughly 2-3x what BPE tokenizers emit, so prepaid reservations
// for Chinese prompts were frozen far above the real cost. estimateTextTokens
// keeps a safety margin over common tokenizers without a model vocabulary:
// ASCII runs cost one token per three bytes, every other rune 1.5 tokens.
const (
	promptMessageOverheadTokens  = 8
	promptToolOverheadTokens     = 16
	promptToolCallOverheadTokens = 8
)

func estimateTextTokens(text string) int64 {
	var asciiBytes, otherRunes int64
	for _, r := range text {
		if r < 0x80 {
			asciiBytes++
		} else {
			otherRunes++
		}
	}
	return (asciiBytes+2)/3 + (otherRunes*3+1)/2
}

func estimateChatPromptTokens(request *ChatCompletionRequest) int64 {
	size := int64(1)
	for _, message := range request.Messages {
		text := messageText(message.Content)
		size += estimateTextTokens(message.Role) + estimateTextTokens(text) + promptMessageOverheadTokens
		// assistant 历史里的 tool_calls（函数名 + 参数）也是输入：编程助手经常带着大段 write_file/patch 参数，
		// 漏算会让每个请求的预留系统性偏低、结算时必然超出。原生 Messages 的 tool_use 会把同一份参数
		// 同时放进 Content 和 ToolCalls，参数已在正文里的不再重复计数。
		for _, call := range message.ToolCalls {
			size += estimateTextTokens(call.Function.Name) + promptToolCallOverheadTokens
			if arguments := call.Function.Arguments; arguments != "" && !strings.Contains(text, arguments) {
				size += estimateTextTokens(arguments)
			}
		}
	}
	for _, tool := range request.Tools {
		size += estimateTextTokens(tool.Function.Name) + estimateTextTokens(tool.Function.Description) +
			estimateTextTokens(string(tool.Function.Parameters)) + promptToolOverheadTokens
	}
	return size
}

func normalizeBillingUsage(response []byte) map[string]int64 {
	usage := canonicalizeResponseUsage(response)
	return map[string]int64{
		"prompt_tokens": usage.PromptTokens, "cached_input_tokens": usage.CachedInputTokens,
		"cache_write_input_tokens": usage.CacheWriteTokens, "output_tokens": usage.OutputTokens,
		"reasoning_tokens": usage.ReasoningTokens,
	}
}

func maxInt64(values ...int64) int64 {
	var result int64
	for _, value := range values {
		if value > result {
			result = value
		}
	}
	return result
}
func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
func mapBillingStatusCode(status int, code string) string {
	if code != "" {
		return code
	}
	if status == http.StatusPaymentRequired {
		return "insufficient_balance"
	}
	return fmt.Sprintf("billing_http_%d", status)
}

func billingAdmissionResponse(err error) (int, string, string) {
	var typed *BillingAdmissionError
	if errors.As(err, &typed) {
		status := typed.HTTPStatus
		if status < 400 || status > 599 {
			status = http.StatusServiceUnavailable
		}
		code := nonEmpty(typed.Code, "billing_unavailable")
		// 预算断流开启后，员工月额度用尽、预付费余额不足统一为 budget_exhausted + 429，
		// 这样 OpenAI 与 Anthropic 客户端只需识别同一个错误码。断流关闭时错误码与状态码保持原样。
		if typed.cutoff && (code == "monthly_allowance_exhausted" || code == "insufficient_balance") {
			return http.StatusTooManyRequests, budgetExhaustedCode, nonEmpty(typed.Message, "预算已用完，请联系管理员")
		}
		return status, code, nonEmpty(typed.Message, "计费准入被拒绝")
	}
	return http.StatusServiceUnavailable, "billing_unavailable", "计费准入被拒绝"
}

// billingAdmissionOutcome 返回需要写入 request_logs.billing_outcome 的中文可映射取值；非断流拒绝返回空串。
func billingAdmissionOutcome(err error) string {
	var typed *BillingAdmissionError
	if !errors.As(err, &typed) {
		return ""
	}
	switch typed.Code {
	case "monthly_allowance_exhausted", "insufficient_balance":
		if typed.cutoff {
			return billingOutcomeBudgetExhausted
		}
	case "model_price_missing":
		if typed.cutoff {
			return billingOutcomeBudgetUnpriced
		}
	case "billing_unavailable":
		if typed.cutoff {
			return billingOutcomeBudgetUnavailable
		}
	}
	return ""
}

func setBillingAdmissionRetryAfter(w http.ResponseWriter, err error) {
	var typed *BillingAdmissionError
	if errors.As(err, &typed) && typed.RetryAfter != "" {
		w.Header().Set("Retry-After", typed.RetryAfter)
	}
}

func normalizeRetryAfter(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return ""
	}
	if seconds, err := strconv.ParseUint(value, 10, 31); err == nil && seconds > 0 {
		return value
	}
	if _, err := http.ParseTime(value); err == nil {
		return value
	}
	return ""
}

// BillingAuditWriter delegates all audit persistence, then settles or releases
// only requests that passed the synchronous preflight. No unreserved error
// path can create a billing side effect.
type BillingAuditWriter struct {
	inner  AuditWriter
	client *BillingClient
}

type billingOutcomeWriter interface {
	MarkBillingOutcome(context.Context, *modelrouter.RequestEnvelope, string)
}

// Billing consumes route attribution before ordinary terminal audit writes.
// This small synchronous write keeps fallback costs on the final channel.
type billingRouteWriter interface {
	PersistBillingRoute(context.Context, *modelrouter.RequestEnvelope) error
}

func NewBillingAuditWriter(inner AuditWriter, client *BillingClient) *BillingAuditWriter {
	return &BillingAuditWriter{inner: inner, client: client}
}
func (w *BillingAuditWriter) EnsureRequestLog(ctx context.Context, e *modelrouter.RequestEnvelope) {
	w.inner.EnsureRequestLog(ctx, e)
}
func (w *BillingAuditWriter) FinalizeRequestLog(ctx context.Context, e *modelrouter.RequestEnvelope, body []byte, status string, code int, latency int, result *AuditResult) {
	// 结算（client.Finalize）自带最长 12s 的独立限时，这里只脱离请求取消、保留 value；
	// 写库与结果标记各自再取一个新的有界限时，避免结算耗时吃掉审计写库的时间。
	ctx = context.WithoutCancel(ctx)
	applyTrustedProxyBillingIngress(ctx, e)
	if !directModelBilling(e) {
		finalizeCtx, cancel := detachAuditContext(ctx)
		defer cancel()
		w.inner.FinalizeRequestLog(finalizeCtx, e, body, status, code, latency, result)
		return
	}
	billingStatus := accountingStatus(status)
	auditBody := body
	if w.client != nil {
		auditBody = w.client.auditResponseBody(e, body)
		// Derive the authoritative billing usage_source from the RAW provider
		// body, the request status and the real admission tracking state, and
		// persist it BEFORE any finalize call.
		//
		// It used to be derived only under e.QuotaAdmissionManaged, which is a
		// quota concept: with billing enabled and the quota governor disabled no
		// source was ever written, so request_logs carried no usage_source and
		// control-plane reconciliation could not settle any of those rows. The
		// marker is a property of how the usage was obtained, not of whether a
		// quota lease happened to run.
		//
		// Setting it here — before Finalize, which may return pending without
		// contacting the control plane, and before the inner writer persists the
		// row — guarantees the log and the settlement always agree.
		if e != nil {
			if e.BillingUsageSource == "" {
				e.BillingUsageSource = w.client.deriveUsageSource(e, body, billingStatus)
			}
			if state, tracked := w.client.trackingState(e.RequestID); tracked && (billingStatus == "success" || billingStatus == "incomplete") {
				if result == nil {
					result = &AuditResult{}
				}
				if result.ResponseMetadata == nil {
					result.ResponseMetadata = map[string]interface{}{}
				}
				result.ResponseMetadata["billing_usage"] = finalBillingUsage(state, body, billingStatus)
			}
			// The quota lease keeps its OWN marker, derived from the quota
			// estimate rather than from the billing admission, and only when a
			// quota admission actually ran. This is the pre-existing behaviour
			// and is preserved unchanged: it is a separate accounting owner, not
			// a fallback for billing.
			_, _, upstreamUsageState := responseUsageTokenState(body)
			if e.QuotaAdmissionManaged && !verifiedUsageState(upstreamUsageState) {
				if _, _, auditUsagePresent := verifiedResponseUsageTokens(auditBody); auditUsagePresent {
					e.QuotaUsageSource = "estimated_reservation"
					if billingStatus == "incomplete" {
						e.QuotaUsageSource = "estimated_incomplete"
					}
					if upstreamUsageState == "invalid" {
						e.QuotaUsageSource = "estimated_reservation_invalid_usage"
						if billingStatus == "incomplete" {
							e.QuotaUsageSource = "estimated_incomplete_invalid_usage"
						}
					}
				}
			}
		}
	}
	var routeErr error
	if w.client != nil && e != nil {
		if _, tracked := w.client.trackingState(e.RequestID); tracked {
			if routeWriter, ok := w.inner.(billingRouteWriter); ok {
				routeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
				routeErr = routeWriter.PersistBillingRoute(routeCtx, e)
				cancel()
			}
		}
	}
	billingOutcome := ""
	if routeErr == nil || (billingStatus != "success" && billingStatus != "incomplete") {
		billingOutcome = w.client.Finalize(ctx, e, body, billingStatus)
	} else {
		// Keep the hold and normal terminal evidence for compensation. Never
		// freeze a procurement cost computed from an obsolete initial route.
		log.Printf("billing route persistence failed request=%s: %v", e.RequestID, routeErr)
		e.BillingOutcome = "failed"
		billingOutcome = "failed"
	}
	finalizeCtx, cancelFinalize := detachAuditContext(ctx)
	w.inner.FinalizeRequestLog(finalizeCtx, e, auditBody, status, code, latency, result)
	cancelFinalize()
	if billingOutcome != "" {
		if outcomeWriter, ok := w.inner.(billingOutcomeWriter); ok {
			markCtx, cancelMark := detachAuditContext(ctx)
			outcomeWriter.MarkBillingOutcome(markCtx, e, billingOutcome)
			cancelMark()
		}
	}
}

// accountingStatus delegates to the shared billingstates package so the
// real-time path and control-plane reconciliation share one decision table.
func accountingStatus(status string) string {
	return billingstates.AccountingStatus(status)
}
func (w *BillingAuditWriter) WriteSecurityEvent(ctx context.Context, e *modelrouter.RequestEnvelope, f []SecurityFinding, action, summary string) {
	w.inner.WriteSecurityEvent(ctx, e, f, action, summary)
}
func (w *BillingAuditWriter) WriteContentLog(ctx context.Context, e *modelrouter.RequestEnvelope, role, content string, tokens int) {
	w.inner.WriteContentLog(ctx, e, role, content, tokens)
}
func (w *BillingAuditWriter) WriteContentLogAnchored(ctx context.Context, e *modelrouter.RequestEnvelope, role, content string, tokens, messageIndex int) {
	if anchoredWriter, ok := w.inner.(AnchoredContentLogWriter); ok {
		anchoredWriter.WriteContentLogAnchored(ctx, e, role, content, tokens, messageIndex)
		return
	}
	w.inner.WriteContentLog(ctx, e, role, content, tokens)
}
func (w *BillingAuditWriter) UpsertAgentSession(ctx context.Context, e *modelrouter.RequestEnvelope) {
	w.inner.UpsertAgentSession(ctx, e)
}
func (w *BillingAuditWriter) AnnotateTriage(ctx context.Context, e *modelrouter.RequestEnvelope, f []SecurityFinding) {
	w.inner.AnnotateTriage(ctx, e, f)
}

// RecordSecurityEventOccurrence 透传指纹重放的轻量 occurrence 写入。计费包装层若不实现它，
// chat 输入路径的类型断言失败，每次重放都会退回写一条完整 security_events（BILLING_ENABLED=true 时）。
// 内层不支持时返回错误，调用方照旧保留完整事件，不丢证。
func (w *BillingAuditWriter) RecordSecurityEventOccurrence(ctx context.Context, e *modelrouter.RequestEnvelope, representativeEventID, contextKey string) error {
	recorder, ok := w.inner.(securityOccurrenceRecorder)
	if !ok {
		return fmt.Errorf("security occurrence writer is unsupported")
	}
	return recorder.RecordSecurityEventOccurrence(ctx, e, representativeEventID, contextKey)
}

func directModelBilling(envelope *modelrouter.RequestEnvelope) bool {
	if envelope == nil {
		return false
	}
	return envelope.BillingIngress == "" || envelope.BillingIngress == "model_api"
}

func billingIngressFromContext(ctx context.Context) string {
	if isProxyRequest(ctx) {
		return "reverse_proxy"
	}
	return "model_api"
}

func applyTrustedProxyBillingIngress(ctx context.Context, envelope *modelrouter.RequestEnvelope) {
	if envelope != nil && isProxyRequest(ctx) {
		envelope.BillingIngress = "reverse_proxy"
	}
}
