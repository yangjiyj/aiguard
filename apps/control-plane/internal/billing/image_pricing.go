package billing

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yangjiyj/aiguard/packages/shared-go/billingmedia"
)

var ErrImageVariantPriceNotFound = errors.New("image size and quality price is not configured")

type ImageVariantPrice struct {
	Size                string `json:"size"`
	Quality             string `json:"quality"`
	PricePerImageMicros Micros `json:"price_per_image_micros"`
}

// An omitted amount is unconfigured, not an implicit zero-price variant.
func (v *ImageVariantPrice) UnmarshalJSON(data []byte) error {
	var raw struct {
		Size    string  `json:"size"`
		Quality string  `json:"quality"`
		Price   *Micros `json:"price_per_image_micros"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Price == nil {
		return ErrInvalidPrice
	}
	v.Size, v.Quality, v.PricePerImageMicros = raw.Size, raw.Quality, *raw.Price
	return nil
}

type ImagePricing struct {
	Mode           string              `json:"mode"`
	DefaultSize    string              `json:"default_size,omitempty"`
	DefaultQuality string              `json:"default_quality,omitempty"`
	Variants       []ImageVariantPrice `json:"variants,omitempty"`
}

func (p *ImagePricing) Validate() error {
	if p == nil {
		return nil
	}
	if p.Mode != "token" && p.Mode != "per_image" || !billingmedia.ValidDimension(p.DefaultSize, false) || !billingmedia.ValidDimension(p.DefaultQuality, false) {
		return ErrInvalidPrice
	}
	if p.Mode == "token" {
		if len(p.Variants) > 0 {
			return ErrInvalidPrice
		}
		return nil
	}
	if len(p.Variants) == 0 || len(p.Variants) > 128 {
		return ErrInvalidPrice
	}
	seen := map[string]bool{}
	for _, v := range p.Variants {
		size, quality := billingmedia.Dimension(v.Size), billingmedia.Dimension(v.Quality)
		key := size + "/" + quality
		if size == "" || quality == "" || !billingmedia.ValidDimension(size, true) || !billingmedia.ValidDimension(quality, true) || v.PricePerImageMicros < 0 || seen[key] {
			return ErrInvalidPrice
		}
		seen[key] = true
	}
	return nil
}

func (p *ImagePricing) priceFor(size, quality string) (Micros, error) {
	size, quality = billingmedia.Dimension(size), billingmedia.Dimension(quality)
	if size == "" {
		size = billingmedia.Dimension(p.DefaultSize)
	}
	if quality == "" {
		quality = billingmedia.Dimension(p.DefaultQuality)
	}
	best := -1
	var amount Micros
	for _, v := range p.Variants {
		s, q := billingmedia.Dimension(v.Size), billingmedia.Dimension(v.Quality)
		if s != "*" && s != size || q != "*" && q != quality {
			continue
		}
		// Exact pair, exact size, exact quality, then explicit wildcard fallback.
		score := 0
		if s != "*" {
			score += 2
		}
		if q != "*" {
			score++
		}
		if score > best {
			best, amount = score, v.PricePerImageMicros
		}
	}
	if best < 0 {
		return 0, fmt.Errorf("%w: size=%s quality=%s", ErrImageVariantPriceNotFound, size, quality)
	}
	return amount, nil
}

func imageVariantCharge(usage Usage, p *ImagePricing) (Micros, error) {
	variants := usage.ImageVariants
	if len(variants) == 0 {
		variants = []billingmedia.ImageVariantUsage{{Size: usage.ImageSize, Quality: usage.ImageQuality, Count: usage.ImageCount}}
	}
	var total Micros
	for _, v := range variants {
		// Resolve zero-count admissions too: a missing price must not look free.
		rate, err := p.priceFor(v.Size, v.Quality)
		if err != nil {
			return 0, err
		}
		amount, err := chargePerUnit(v.Count, rate, 1)
		if err != nil {
			return 0, err
		}
		total, err = addMicros(total, amount)
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}
