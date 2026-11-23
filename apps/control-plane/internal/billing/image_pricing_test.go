package billing

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/billingmedia"
)

func imageMatrix() *ImagePricing {
	return &ImagePricing{Mode: "per_image", DefaultSize: "1024x1024", DefaultQuality: "standard", Variants: []ImageVariantPrice{
		{Size: "1024x1024", Quality: "standard", PricePerImageMicros: 40_001},
		{Size: "1024x1024", Quality: "hd", PricePerImageMicros: 80_003},
		{Size: "1792x1024", Quality: "hd", PricePerImageMicros: 120_007},
	}}
}

func TestImageSpecificationDefaultActualVariantsAndNoDoubleCharge(t *testing.T) {
	price := DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000,
		Extensions: PriceExtensions{ImagePricing: imageMatrix(), ImagePerImageMicros: 999_999, NewAPIFixedQuantity: true, RequestPerCallMicros: 888_888}}
	usage := Usage{PromptTokens: 1000, OutputTokens: 2000, UsageExtensions: UsageExtensions{ImageRequest: true, ImageCount: 2}}
	charge, err := CalculateDirectCharge(usage, price)
	if err != nil || charge.TotalMicros != 80_002 || charge.InputMicros != 0 || charge.OutputMicros != 0 || charge.RequestMicros != 0 {
		t.Fatalf("default specification double charged: %+v %v", charge, err)
	}
	usage.ImageVariants = []billingmedia.ImageVariantUsage{{Size: "1024x1024", Quality: "hd", Count: 1}, {Size: "1792x1024", Quality: "hd", Count: 1}}
	charge, err = CalculateDirectCharge(usage, price)
	if err != nil || charge.TotalMicros != 200_010 {
		t.Fatalf("actual mixed specifications: %+v %v", charge, err)
	}
	usage.ImageVariants = nil
	usage.ImageSize, usage.ImageQuality = "auto", "auto"
	for _, count := range []int64{0, 2} {
		usage.ImageCount = count
		if _, err := CalculateDirectCharge(usage, price); !errors.Is(err, ErrImageVariantPriceNotFound) {
			t.Fatalf("unconfigured auto specification looked free (count=%d): %v", count, err)
		}
	}
	// A model's ordinary chat fee survives an image configuration.
	usage.ImageRequest, usage.ImageCount = false, 0
	charge, err = CalculateDirectCharge(usage, price)
	if err != nil || charge.RequestMicros != 888_888 || charge.InputMicros != 1000 || charge.OutputMicros != 4000 {
		t.Fatalf("ordinary chat fee changed: %+v %v", charge, err)
	}
}

func TestImageTokenPricingSeparatesImageOutputAndReasoning(t *testing.T) {
	imageInput, imageCache, imageOutput, reasoning := Micros(8_000_000), Micros(2_000_000), Micros(30_000_000), Micros(40_000_000)
	price := DirectPrice{InputPerMillionMicros: 5_000_000, CachedInputPerMillionMicros: 1_250_000, HasCachedInputPrice: true, OutputPerMillionMicros: 10_000_000,
		Extensions: PriceExtensions{ImagePricing: &ImagePricing{Mode: "token"}, ImageInputPerMillionMicros: &imageInput, CachedImageInputPerMillionMicros: &imageCache,
			ImageOutputPerMillionMicros: &imageOutput, ReasoningPerMillionMicros: &reasoning, ImagePerImageMicros: 99_999, RequestPerCallMicros: 88_888, NewAPIFixedQuantity: true}}
	usage := Usage{PromptTokens: 100, CachedInputTokens: 10, OutputTokens: 100, ReasoningTokens: 10,
		UsageExtensions: UsageExtensions{ImageRequest: true, ImageCount: 2, ImageInputTokens: 40, CachedImageInputTokens: 5, ImageOutputTokens: 60}}
	charge, err := CalculateDirectCharge(usage, price)
	// text input 55*5 + text cache ceil(5*1.25) + image input35*8 + image cache5*2 + text output30*10 + image output60*30 + reasoning10*40
	if err != nil || charge.TotalMicros != 3072 || charge.ImageMicros != 0 || charge.RequestMicros != 0 || charge.OutputMicros != 300 || charge.ImageTokenMicros != 2090 {
		t.Fatalf("image Token tiers overlapped: %+v %v", charge, err)
	}
	usage.ImageOutputTokens = 91
	if _, err := CalculateDirectCharge(usage, price); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("overlapping image/reasoning output accepted: %v", err)
	}
}

func TestImageSpecificationWildcardPriorityAndRatioPrecision(t *testing.T) {
	matrix := &ImagePricing{Mode: "per_image", Variants: []ImageVariantPrice{
		{Size: "*", Quality: "*", PricePerImageMicros: 1}, {Size: "*", Quality: "hd", PricePerImageMicros: 2},
		{Size: "1024x1024", Quality: "*", PricePerImageMicros: 3}, {Size: "1024x1024", Quality: "hd", PricePerImageMicros: 4},
	}}
	for _, c := range []struct {
		size, quality string
		want          Micros
	}{{"auto", "auto", 1}, {"auto", "hd", 2}, {"1024x1024", "standard", 3}, {"1024x1024", "hd", 4}} {
		got, err := matrix.priceFor(c.size, c.quality)
		if err != nil || got != c.want {
			t.Fatalf("%s/%s = %d, want %d; %v", c.size, c.quality, got, c.want, err)
		}
	}
	price := DirectPrice{Extensions: PriceExtensions{ImagePricing: imageMatrix()}}
	adjusted, err := ApplyPriceRatios(price, 500_000, 800_000)
	if err != nil || adjusted.Extensions.ImagePricing.Variants[0].PricePerImageMicros != 16_001 || price.Extensions.ImagePricing.Variants[0].PricePerImageMicros != 40_001 {
		t.Fatalf("integer micro precision or original snapshot changed: %+v %v", adjusted, err)
	}
}

func TestImageSpecificationRejectsIncompletePriceAndQuantityEvidence(t *testing.T) {
	for _, raw := range []string{`{"mode":"per_image","variants":[{"size":"1024x1024","quality":"hd"}]}`, `{"mode":"per_image","variants":[{"size":"1024x1024","quality":"hd","price_per_image_micros":null}]}`} {
		var p ImagePricing
		if err := json.Unmarshal([]byte(raw), &p); !errors.Is(err, ErrInvalidPrice) {
			t.Fatalf("omitted price became free: %v", err)
		}
	}
	var p ImagePricing
	if err := json.Unmarshal([]byte(`{"mode":"per_image","variants":[{"size":"*","quality":"*","price_per_image_micros":0}]}`), &p); err != nil || p.Validate() != nil {
		t.Fatalf("explicit free variant rejected: %v", err)
	}
	usage := Usage{UsageExtensions: UsageExtensions{ImageRequest: true, ImageCount: 2, ImageVariants: []billingmedia.ImageVariantUsage{{Size: "1024x1024", Quality: "hd", Count: 3}}}}
	if err := validateUsage(usage); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("inconsistent actual quantity accepted: %v", err)
	}
	for _, p := range []*ImagePricing{
		{Mode: "token", Variants: imageMatrix().Variants}, {Mode: "per_image"},
		{Mode: "per_image", Variants: []ImageVariantPrice{{Size: "1024x1024", Quality: "HD"}, {Size: "1024x1024", Quality: "hd"}}},
	} {
		if err := p.Validate(); !errors.Is(err, ErrInvalidPrice) {
			t.Fatalf("invalid specification matrix accepted: %+v", p)
		}
	}
}
