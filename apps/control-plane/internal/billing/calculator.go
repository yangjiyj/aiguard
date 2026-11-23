package billing

import (
	"errors"
	"fmt"
	"math"
	"math/big"
)

const ratioScale int64 = 1_000_000

var (
	ErrInvalidUsage        = errors.New("invalid billing usage")
	ErrInvalidPrice        = errors.New("invalid billing price")
	ErrAmountOverflow      = errors.New("billing amount overflow")
	ErrInvalidWalletState  = errors.New("invalid wallet state")
	ErrInsufficientBalance = errors.New("insufficient wallet balance")
)

type Micros int64

type Usage struct {
	PromptTokens          int64 `json:"prompt_tokens"`
	CachedInputTokens     int64 `json:"cached_input_tokens"`
	CacheWriteInputTokens int64 `json:"cache_write_input_tokens"`
	OutputTokens          int64 `json:"output_tokens"`
	ReasoningTokens       int64 `json:"reasoning_tokens"`
	UsageExtensions
}

type DirectPrice struct {
	Extensions                  PriceExtensions
	InputPerMillionMicros       Micros
	CachedInputPerMillionMicros Micros
	CacheWritePerMillionMicros  Micros
	OutputPerMillionMicros      Micros
	HasCachedInputPrice         bool
	HasCacheWritePrice          bool
}

// RatioPrice is the compatibility input for New API style pricing. Ratios are
// represented as parts per million, so 1.5 is 1_500_000 and no float enters
// the billing path. Cache ratios are optional; zero means use input-price
// fallback, matching providers that do not expose a distinct cache price.
type RatioPrice struct {
	BaseInputPerMillionMicros Micros
	ModelRatioPPM             int64
	CompletionRatioPPM        int64
	GroupRatioPPM             int64
	CachedInputRatioPPM       int64
	HasCachedInputRatio       bool
	CacheWriteRatioPPM        int64
	HasCacheWriteRatio        bool
}

type ChargeBreakdown struct {
	UncachedInputTokens int64
	InputMicros         Micros
	CachedInputMicros   Micros
	CacheWriteMicros    Micros
	OutputMicros        Micros
	TotalMicros         Micros
	ReasoningMicros     Micros
	ImageTokenMicros    Micros
	ImageMicros         Micros
	RequestMicros       Micros
	ToolMicros          Micros
}

func CalculateDirectCharge(usage Usage, price DirectPrice) (ChargeBreakdown, error) {
	if err := validateUsage(usage); err != nil {
		return ChargeBreakdown{}, err
	}
	if err := validateDirectPrice(price); err != nil {
		return ChargeBreakdown{}, err
	}

	imageMode := ""
	if usage.ImageRequest && price.Extensions.ImagePricing != nil {
		imageMode = price.Extensions.ImagePricing.Mode
	}
	if imageMode == "per_image" {
		// Token usage remains in durable facts; the image endpoint's base charge
		// is selected solely from the configured per-image specification.
		usage.PromptTokens, usage.CachedInputTokens, usage.CacheWriteInputTokens = 0, 0, 0
		usage.OutputTokens, usage.ReasoningTokens = 0, 0
		usage.ImageInputTokens, usage.CachedImageInputTokens, usage.ImageOutputTokens = 0, 0, 0
	}
	cachedRate := price.InputPerMillionMicros
	if price.HasCachedInputPrice {
		cachedRate = price.CachedInputPerMillionMicros
	}
	cacheWriteRate := price.InputPerMillionMicros
	if price.HasCacheWritePrice {
		cacheWriteRate = price.CacheWritePerMillionMicros
	}

	result := ChargeBreakdown{
		UncachedInputTokens: usage.PromptTokens - usage.CachedInputTokens - usage.CacheWriteInputTokens,
	}
	var err error
	if price.Extensions.ImageInputPerMillionMicros != nil {
		uncachedImage := usage.ImageInputTokens - usage.CachedImageInputTokens
		result.UncachedInputTokens -= uncachedImage
		result.ImageTokenMicros, err = componentCharge(uncachedImage, *price.Extensions.ImageInputPerMillionMicros)
		if err != nil {
			return ChargeBreakdown{}, err
		}
	}
	cachedTokens := usage.CachedInputTokens
	if price.Extensions.CachedImageInputPerMillionMicros != nil {
		cachedTokens -= usage.CachedImageInputTokens
		charge, e := componentCharge(usage.CachedImageInputTokens, *price.Extensions.CachedImageInputPerMillionMicros)
		if e != nil {
			return ChargeBreakdown{}, e
		}
		result.ImageTokenMicros, e = addMicros(result.ImageTokenMicros, charge)
		if e != nil {
			return ChargeBreakdown{}, e
		}
	}
	if result.InputMicros, err = componentCharge(result.UncachedInputTokens, price.InputPerMillionMicros); err != nil {
		return ChargeBreakdown{}, err
	}
	if result.CachedInputMicros, err = componentCharge(cachedTokens, cachedRate); err != nil {
		return ChargeBreakdown{}, err
	}
	if result.CacheWriteMicros, err = componentCharge(usage.CacheWriteInputTokens, cacheWriteRate); err != nil {
		return ChargeBreakdown{}, err
	}
	outputTokens := usage.OutputTokens
	if price.Extensions.ReasoningPerMillionMicros != nil {
		outputTokens -= usage.ReasoningTokens
		if result.ReasoningMicros, err = componentCharge(usage.ReasoningTokens, *price.Extensions.ReasoningPerMillionMicros); err != nil {
			return ChargeBreakdown{}, err
		}
	}
	if price.Extensions.ImageOutputPerMillionMicros != nil {
		outputTokens -= usage.ImageOutputTokens
		charge, e := componentCharge(usage.ImageOutputTokens, *price.Extensions.ImageOutputPerMillionMicros)
		if e != nil {
			return ChargeBreakdown{}, e
		}
		result.ImageTokenMicros, e = addMicros(result.ImageTokenMicros, charge)
		if e != nil {
			return ChargeBreakdown{}, e
		}
	}
	if result.OutputMicros, err = componentCharge(outputTokens, price.OutputPerMillionMicros); err != nil {
		return ChargeBreakdown{}, err
	}
	if imageMode == "per_image" {
		result.ImageMicros, err = imageVariantCharge(usage, price.Extensions.ImagePricing)
	} else if imageMode != "token" {
		result.ImageMicros, err = chargePerUnit(usage.ImageCount, price.Extensions.ImagePerImageMicros, 1)
	}
	if err != nil {
		return ChargeBreakdown{}, err
	}
	result.RequestMicros = price.Extensions.RequestPerCallMicros
	if imageMode != "" && price.Extensions.NewAPIFixedQuantity {
		result.RequestMicros = 0
	}
	if imageMode == "" && price.Extensions.NewAPIFixedQuantity && usage.ImageCount > 0 {
		result.RequestMicros, err = chargePerUnit(usage.ImageCount, price.Extensions.RequestPerCallMicros, 1)
		if err != nil {
			return ChargeBreakdown{}, err
		}
	}
	for name, count := range usage.ToolCalls {
		component, toolErr := chargePerUnit(count, price.Extensions.ToolPricesPerThousandMicros[name], 1000)
		if toolErr != nil {
			return ChargeBreakdown{}, toolErr
		}
		result.ToolMicros, toolErr = addMicros(result.ToolMicros, component)
		if toolErr != nil {
			return ChargeBreakdown{}, toolErr
		}
	}
	result.TotalMicros, err = addMicros(
		result.InputMicros,
		result.CachedInputMicros,
		result.CacheWriteMicros,
		result.OutputMicros, result.ReasoningMicros, result.ImageTokenMicros, result.ImageMicros, result.RequestMicros, result.ToolMicros,
	)
	if err != nil {
		return ChargeBreakdown{}, err
	}
	return result, nil
}

func NormalizeNewAPIRatioPrice(price RatioPrice) (DirectPrice, error) {
	if price.BaseInputPerMillionMicros < 0 || price.ModelRatioPPM < 0 ||
		price.CompletionRatioPPM < 0 || price.GroupRatioPPM < 0 ||
		price.CachedInputRatioPPM < 0 || price.CacheWriteRatioPPM < 0 {
		return DirectPrice{}, ErrInvalidPrice
	}
	modelRatio := price.ModelRatioPPM
	completionRatio := price.CompletionRatioPPM
	groupRatio := price.GroupRatioPPM

	input, err := multiplyPPM(price.BaseInputPerMillionMicros, modelRatio, groupRatio)
	if err != nil {
		return DirectPrice{}, err
	}
	output, err := multiplyPPM(price.BaseInputPerMillionMicros, modelRatio, groupRatio, completionRatio)
	if err != nil {
		return DirectPrice{}, err
	}
	result := DirectPrice{
		InputPerMillionMicros:  input,
		OutputPerMillionMicros: output,
	}
	if price.HasCachedInputRatio || price.CachedInputRatioPPM != 0 {
		result.CachedInputPerMillionMicros, err = multiplyPPM(
			price.BaseInputPerMillionMicros, modelRatio, groupRatio, price.CachedInputRatioPPM,
		)
		if err != nil {
			return DirectPrice{}, err
		}
		result.HasCachedInputPrice = true
	}
	if price.HasCacheWriteRatio || price.CacheWriteRatioPPM != 0 {
		result.CacheWritePerMillionMicros, err = multiplyPPM(
			price.BaseInputPerMillionMicros, modelRatio, groupRatio, price.CacheWriteRatioPPM,
		)
		if err != nil {
			return DirectPrice{}, err
		}
		result.HasCacheWritePrice = true
	}
	return result, nil
}

// ApplyCustomerGroupRatio converts one tenant/model base price into the rates
// quoted to a customer. It is applied before component rounding so admission
// and settlement use identical per-token rates.
func ApplyCustomerGroupRatio(price DirectPrice, groupRatioPPM int64) (DirectPrice, error) {
	return ApplyPriceRatios(price, groupRatioPPM)
}

// ApplyPriceRatios applies all quote multipliers in one integer operation per
// component. Keeping customer-group and time-band ratios together avoids the
// double rounding that would occur if each multiplier rewrote an already
// rounded rate.
func ApplyPriceRatios(price DirectPrice, ratios ...int64) (DirectPrice, error) {
	if err := validateDirectPrice(price); err != nil {
		return DirectPrice{}, err
	}
	for _, ratio := range ratios {
		if ratio <= 0 || ratio > MaxCustomerGroupRatioPPM {
			return DirectPrice{}, ErrInvalidPrice
		}
	}
	result := price
	var err error
	if result.InputPerMillionMicros, err = multiplyPPM(price.InputPerMillionMicros, ratios...); err != nil {
		return DirectPrice{}, err
	}
	if result.OutputPerMillionMicros, err = multiplyPPM(price.OutputPerMillionMicros, ratios...); err != nil {
		return DirectPrice{}, err
	}
	if price.HasCachedInputPrice {
		if result.CachedInputPerMillionMicros, err = multiplyPPM(price.CachedInputPerMillionMicros, ratios...); err != nil {
			return DirectPrice{}, err
		}
	}
	if price.HasCacheWritePrice {
		if result.CacheWritePerMillionMicros, err = multiplyPPM(price.CacheWritePerMillionMicros, ratios...); err != nil {
			return DirectPrice{}, err
		}
	}
	result.Extensions, err = applyExtensionRatios(price.Extensions, ratios...)
	if err != nil {
		return DirectPrice{}, err
	}
	return result, nil
}

func validateUsage(usage Usage) error {
	if err := usage.UsageExtensions.Validate(); err != nil {
		return err
	}
	if usage.PromptTokens < 0 || usage.CachedInputTokens < 0 ||
		usage.CacheWriteInputTokens < 0 || usage.OutputTokens < 0 || usage.ReasoningTokens < 0 {
		return ErrInvalidUsage
	}
	if usage.CachedInputTokens > usage.PromptTokens ||
		usage.CacheWriteInputTokens > usage.PromptTokens-usage.CachedInputTokens ||
		usage.ReasoningTokens > usage.OutputTokens || usage.ImageOutputTokens > usage.OutputTokens-usage.ReasoningTokens || usage.CachedImageInputTokens > usage.CachedInputTokens ||
		usage.ImageInputTokens-usage.CachedImageInputTokens > usage.PromptTokens-usage.CachedInputTokens-usage.CacheWriteInputTokens {
		return ErrInvalidUsage
	}
	return nil
}

func validateDirectPrice(price DirectPrice) error {
	if err := price.Extensions.Validate(); err != nil {
		return err
	}
	if price.InputPerMillionMicros < 0 || price.CachedInputPerMillionMicros < 0 ||
		price.CacheWritePerMillionMicros < 0 || price.OutputPerMillionMicros < 0 {
		return ErrInvalidPrice
	}
	return nil
}

func componentCharge(tokens int64, rate Micros) (Micros, error) {
	if tokens == 0 || rate == 0 {
		return 0, nil
	}
	numerator := new(big.Int).Mul(big.NewInt(tokens), big.NewInt(int64(rate)))
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(numerator, big.NewInt(ratioScale), remainder)
	if remainder.Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsInt64() {
		return 0, ErrAmountOverflow
	}
	return Micros(quotient.Int64()), nil
}

func multiplyPPM(amount Micros, ratios ...int64) (Micros, error) {
	numerator := big.NewInt(int64(amount))
	divisor := big.NewInt(1)
	for _, ratio := range ratios {
		if ratio < 0 {
			return 0, ErrInvalidPrice
		}
		numerator.Mul(numerator, big.NewInt(ratio))
		divisor.Mul(divisor, big.NewInt(ratioScale))
	}
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(numerator, divisor, remainder)
	if remainder.Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsInt64() {
		return 0, ErrAmountOverflow
	}
	return Micros(quotient.Int64()), nil
}

func addMicros(values ...Micros) (Micros, error) {
	var total int64
	for _, value := range values {
		if value > 0 && total > math.MaxInt64-int64(value) {
			return 0, ErrAmountOverflow
		}
		if value < 0 && total < math.MinInt64-int64(value) {
			return 0, ErrAmountOverflow
		}
		total += int64(value)
	}
	return Micros(total), nil
}

type WalletState struct {
	BalanceMicros  Micros
	ReservedMicros Micros
}

func (s WalletState) AvailableMicros() Micros {
	if s.ReservedMicros > 0 && s.BalanceMicros < Micros(math.MinInt64+int64(s.ReservedMicros)) {
		return Micros(math.MinInt64)
	}
	return s.BalanceMicros - s.ReservedMicros
}

func (s WalletState) Reserve(amount Micros) (WalletState, error) {
	if err := s.validate(); err != nil {
		return WalletState{}, err
	}
	if amount <= 0 {
		return WalletState{}, fmt.Errorf("%w: reserve amount must be positive", ErrInvalidWalletState)
	}
	// D5: an overdrawn or empty wallet admits nothing, and no overdraft credit
	// line exists, so admission must be fully covered by available funds.
	if s.BalanceMicros <= 0 || amount > s.AvailableMicros() {
		return WalletState{}, ErrInsufficientBalance
	}
	if int64(s.ReservedMicros) > math.MaxInt64-int64(amount) {
		return WalletState{}, ErrAmountOverflow
	}
	s.ReservedMicros += amount
	return s, nil
}

func (s WalletState) Settle(reserved, actual Micros) (WalletState, error) {
	if err := s.validate(); err != nil {
		return WalletState{}, err
	}
	if reserved <= 0 || actual < 0 || reserved > s.ReservedMicros {
		return WalletState{}, fmt.Errorf("%w: invalid settlement", ErrInvalidWalletState)
	}
	if actual > 0 && int64(s.BalanceMicros) < math.MinInt64+int64(actual) {
		return WalletState{}, ErrAmountOverflow
	}
	// D5: the upstream cost has already been incurred, so settlement always
	// books the actual amount even when it drives the balance below the other
	// in-flight reservations or below zero. Admission (Reserve) is the only
	// place that refuses money; callers flag the ledger row via Overdrawn.
	s.BalanceMicros -= actual
	s.ReservedMicros -= reserved
	return s, nil
}

// Overdrawn reports whether the wallet no longer covers its own in-flight
// reservations, i.e. a settlement consumed money it did not have available.
func (s WalletState) Overdrawn() bool {
	return s.AvailableMicros() < 0
}

// OverdraftLedgerMetadata is the ledger metadata for a settlement that left
// the wallet overdrawn; nil when the settlement was fully covered.
func OverdraftLedgerMetadata(before, after WalletState) map[string]any {
	if !after.Overdrawn() {
		return nil
	}
	return map[string]any{
		"overdraft":               true,
		"available_before_micros": int64(before.AvailableMicros()),
		"available_after_micros":  int64(after.AvailableMicros()),
	}
}

func (s WalletState) Release(reserved Micros) (WalletState, error) {
	if err := s.validate(); err != nil {
		return WalletState{}, err
	}
	if reserved <= 0 || reserved > s.ReservedMicros {
		return WalletState{}, fmt.Errorf("%w: invalid release", ErrInvalidWalletState)
	}
	s.ReservedMicros -= reserved
	return s, nil
}

func (s WalletState) validate() error {
	if s.ReservedMicros < 0 {
		return ErrInvalidWalletState
	}
	return nil
}
