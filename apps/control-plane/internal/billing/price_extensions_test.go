package billing

import (
	"errors"
	"math"
	"testing"
)

func TestExtendedChargeCountsReasoningOnceAndUsesActualTools(t *testing.T) {
	reasoning := Micros(20_000_000)
	price := DirectPrice{InputPerMillionMicros: 2_000_000, OutputPerMillionMicros: 10_000_000, Extensions: PriceExtensions{
		ReasoningPerMillionMicros: &reasoning, ImagePerImageMicros: 50_000, RequestPerCallMicros: 10_000,
		ToolPricesPerThousandMicros: map[string]Micros{"web_search": 10_000_000, "file_search": 2_500_000},
	}}
	charge, err := CalculateDirectCharge(Usage{PromptTokens: 1000, OutputTokens: 1000, ReasoningTokens: 300, UsageExtensions: UsageExtensions{ImageCount: 2, ToolCalls: map[string]int64{"web_search": 3, "file_search": 2, "unpriced_tool": 7}}}, price)
	if err != nil {
		t.Fatal(err)
	}
	// Input .002, ordinary output .007, reasoning .006, images .10,
	// request .01, three searches .03, two file searches .005.
	if charge.TotalMicros != 160_000 || charge.OutputMicros != 7000 || charge.ReasoningMicros != 6000 || charge.ToolMicros != 35000 {
		t.Fatalf("charge=%+v", charge)
	}
	price.Extensions.ReasoningPerMillionMicros = nil
	plain, err := CalculateDirectCharge(Usage{OutputTokens: 1000, ReasoningTokens: 300}, price)
	if err != nil || plain.OutputMicros != 10000 || plain.ReasoningMicros != 0 {
		t.Fatalf("reasoning fallback: %+v %v", plain, err)
	}
}

func TestNewAPIFixedImageQuantityAndPriceRatios(t *testing.T) {
	price := DirectPrice{Extensions: PriceExtensions{RequestPerCallMicros: 40_000, NewAPIFixedQuantity: true, ToolPricesPerThousandMicros: map[string]Micros{"web_search": 10_000_000}}}
	discounted, err := ApplyPriceRatios(price, 800000, 500000)
	if err != nil {
		t.Fatal(err)
	}
	charge, err := CalculateDirectCharge(Usage{UsageExtensions: UsageExtensions{ImageCount: 3, ToolCalls: map[string]int64{"web_search": 2}}}, discounted)
	if err != nil || charge.RequestMicros != 48000 || charge.ToolMicros != 8000 || charge.TotalMicros != 56000 {
		t.Fatalf("discounted fixed quantity: %+v %v", charge, err)
	}
	// Applying a quote multiplier cannot mutate the source version's map.
	if price.Extensions.ToolPricesPerThousandMicros["web_search"] != 10_000_000 {
		t.Fatal("source price mutated")
	}
}

func TestExtendedPriceUsageValidationAndOverflow(t *testing.T) {
	bad := []Usage{{UsageExtensions: UsageExtensions{ImageCount: -1}}, {UsageExtensions: UsageExtensions{ToolCalls: map[string]int64{"web_search": -1}}}, {UsageExtensions: UsageExtensions{ToolCalls: map[string]int64{"invalid tool": 1}}}}
	for _, usage := range bad {
		if _, err := CalculateDirectCharge(usage, DirectPrice{}); !errors.Is(err, ErrInvalidUsage) {
			t.Fatalf("invalid usage accepted: %+v %v", usage, err)
		}
	}
	if _, err := CalculateDirectCharge(Usage{UsageExtensions: UsageExtensions{ImageCount: math.MaxInt64}}, DirectPrice{Extensions: PriceExtensions{ImagePerImageMicros: 1}}); !errors.Is(err, ErrAmountOverflow) {
		t.Fatalf("image overflow: %v", err)
	}
}
