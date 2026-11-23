package billing

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/yangjiyj/aiguard/packages/shared-go/billingmedia"
)

// PriceExtensions shares the price's declared currency. Amounts are integer
// millionths of that currency; no exchange rate is applied in billing.
type PriceExtensions struct {
	ImagePricing                     *ImagePricing     `json:"image_pricing,omitempty"`
	ImageOutputPerMillionMicros      *Micros           `json:"image_output_per_million_micros,omitempty"`
	ImageInputPerMillionMicros       *Micros           `json:"image_input_per_million_micros,omitempty"`
	CachedImageInputPerMillionMicros *Micros           `json:"cached_image_input_per_million_micros,omitempty"`
	NewAPIFixedQuantity              bool              `json:"newapi_fixed_quantity,omitempty"`
	ImagePerImageMicros              Micros            `json:"image_per_image_micros,omitempty"`
	RequestPerCallMicros             Micros            `json:"request_per_call_micros,omitempty"`
	ReasoningPerMillionMicros        *Micros           `json:"reasoning_per_million_micros,omitempty"`
	ToolPricesPerThousandMicros      map[string]Micros `json:"tool_prices_per_thousand_micros,omitempty"`
	Source                           string            `json:"source,omitempty"`
}

type UsageExtensions struct {
	ImageRequest           bool                             `json:"image_request,omitempty"`
	ImageSize              string                           `json:"image_size,omitempty"`
	ImageQuality           string                           `json:"image_quality,omitempty"`
	ImageOutputTokens      int64                            `json:"image_output_tokens,omitempty"`
	ImageVariants          []billingmedia.ImageVariantUsage `json:"image_variants,omitempty"`
	ImageInputTokens       int64                            `json:"image_input_tokens,omitempty"`
	CachedImageInputTokens int64                            `json:"cached_image_input_tokens,omitempty"`
	ImageCount             int64                            `json:"image_count,omitempty"`
	ToolCalls              map[string]int64                 `json:"tool_calls,omitempty"`
}

var toolNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,95}$`)

func (p PriceExtensions) Validate() error {
	if err := p.ImagePricing.Validate(); err != nil {
		return err
	}
	if p.ImageOutputPerMillionMicros != nil && *p.ImageOutputPerMillionMicros < 0 {
		return ErrInvalidPrice
	}
	if p.ImageInputPerMillionMicros != nil && *p.ImageInputPerMillionMicros < 0 || p.CachedImageInputPerMillionMicros != nil && *p.CachedImageInputPerMillionMicros < 0 || p.ImagePerImageMicros < 0 || p.RequestPerCallMicros < 0 ||
		p.ReasoningPerMillionMicros != nil && *p.ReasoningPerMillionMicros < 0 || len(p.ToolPricesPerThousandMicros) > 64 || len(p.Source) > 512 {
		return ErrInvalidPrice
	}
	for name, rate := range p.ToolPricesPerThousandMicros {
		if !toolNamePattern.MatchString(name) || rate < 0 {
			return ErrInvalidPrice
		}
	}
	return nil
}

func (u UsageExtensions) Validate() error {
	if u.ImageOutputTokens < 0 || !billingmedia.ValidDimension(u.ImageSize, false) || !billingmedia.ValidDimension(u.ImageQuality, false) || len(u.ImageVariants) > 128 {
		return ErrInvalidUsage
	}
	var count int64
	for _, v := range u.ImageVariants {
		if v.Count < 0 || !billingmedia.ValidDimension(v.Size, false) || !billingmedia.ValidDimension(v.Quality, false) || count > u.ImageCount-v.Count {
			return ErrInvalidUsage
		}
		count += v.Count
	}
	if len(u.ImageVariants) > 0 && count != u.ImageCount {
		return ErrInvalidUsage
	}
	if u.ImageInputTokens < 0 || u.CachedImageInputTokens < 0 || u.CachedImageInputTokens > u.ImageInputTokens || u.ImageCount < 0 || len(u.ToolCalls) > 64 {
		return ErrInvalidUsage
	}
	for name, count := range u.ToolCalls {
		if !toolNamePattern.MatchString(name) || count < 0 {
			return ErrInvalidUsage
		}
	}
	return nil
}

func jsonObject(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func chargePerUnit(count int64, price Micros, divisor int64) (Micros, error) {
	// Reuse the checked integer calculator, retaining its round-up policy.
	// Multiplying the unit count (not the rate) avoids rate overflow.
	if count > 0 && count > (1<<63-1)/(ratioScale/divisor) {
		return 0, ErrAmountOverflow
	}
	return componentCharge(count*(ratioScale/divisor), price)
}

func applyExtensionRatios(p PriceExtensions, ratios ...int64) (PriceExtensions, error) {
	result := p
	var err error
	if p.ImagePricing != nil {
		copy := *p.ImagePricing
		copy.Variants = append([]ImageVariantPrice(nil), p.ImagePricing.Variants...)
		for i := range copy.Variants {
			copy.Variants[i].PricePerImageMicros, err = multiplyPPM(copy.Variants[i].PricePerImageMicros, ratios...)
			if err != nil {
				return result, err
			}
		}
		result.ImagePricing = &copy
	}
	if p.ImageOutputPerMillionMicros != nil {
		amount, e := multiplyPPM(*p.ImageOutputPerMillionMicros, ratios...)
		if e != nil {
			return result, e
		}
		result.ImageOutputPerMillionMicros = &amount
	}
	if p.ImageInputPerMillionMicros != nil {
		amount, e := multiplyPPM(*p.ImageInputPerMillionMicros, ratios...)
		if e != nil {
			return result, e
		}
		result.ImageInputPerMillionMicros = &amount
	}
	if p.CachedImageInputPerMillionMicros != nil {
		amount, e := multiplyPPM(*p.CachedImageInputPerMillionMicros, ratios...)
		if e != nil {
			return result, e
		}
		result.CachedImageInputPerMillionMicros = &amount
	}
	if result.ImagePerImageMicros, err = multiplyPPM(p.ImagePerImageMicros, ratios...); err != nil {
		return result, err
	}
	if result.RequestPerCallMicros, err = multiplyPPM(p.RequestPerCallMicros, ratios...); err != nil {
		return result, err
	}
	if p.ReasoningPerMillionMicros != nil {
		amount, err := multiplyPPM(*p.ReasoningPerMillionMicros, ratios...)
		if err != nil {
			return result, err
		}
		result.ReasoningPerMillionMicros = &amount
	}
	if p.ToolPricesPerThousandMicros != nil {
		result.ToolPricesPerThousandMicros = make(map[string]Micros, len(p.ToolPricesPerThousandMicros))
		for name, price := range p.ToolPricesPerThousandMicros {
			amount, err := multiplyPPM(price, ratios...)
			if err != nil {
				return result, fmt.Errorf("tool price %s: %w", name, err)
			}
			result.ToolPricesPerThousandMicros[name] = amount
		}
	}
	return result, nil
}
