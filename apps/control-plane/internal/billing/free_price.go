package billing

// IsFullyFree requires an actual validated model-price binding. A zero quote
// or caller-provided zero usage is not evidence that future usage is free.
func (p *ModelPrice) IsFullyFree() bool {
	if p == nil || p.ID == "" || p.TenantID == "" || p.ModelName == "" {
		return false
	}
	direct, err := p.AsDirectPrice()
	return err == nil && direct.IsFullyFree()
}

func (p DirectPrice) IsFullyFree() bool {
	if validateDirectPrice(p) != nil || p.Extensions.Validate() != nil {
		return false
	}
	if p.InputPerMillionMicros != 0 || p.CachedInputPerMillionMicros != 0 || p.CacheWritePerMillionMicros != 0 || p.OutputPerMillionMicros != 0 {
		return false
	}
	e := p.Extensions
	if e.ImagePerImageMicros != 0 || e.RequestPerCallMicros != 0 {
		return false
	}
	for _, rate := range []*Micros{e.ImageOutputPerMillionMicros, e.ImageInputPerMillionMicros, e.CachedImageInputPerMillionMicros, e.ReasoningPerMillionMicros} {
		if rate != nil && *rate != 0 {
			return false
		}
	}
	for _, rate := range e.ToolPricesPerThousandMicros {
		if rate != 0 {
			return false
		}
	}
	if e.ImagePricing != nil {
		for _, variant := range e.ImagePricing.Variants {
			if variant.PricePerImageMicros != 0 {
				return false
			}
		}
	}
	return true
}
