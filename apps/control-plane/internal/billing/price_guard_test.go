package billing

import (
	"testing"
	"time"
)

// 价格写入防护的纯函数测试：不依赖数据库。

func pgMicros(v int64) *Micros { m := Micros(v); return &m }

func pgPrevious(direct DirectPrice, ext PriceExtensions) *ModelPrice {
	return &ModelPrice{
		ID: "price_prev", TenantID: "t", ModelName: "m", CustomerGroup: DefaultCustomerGroup, Version: 3,
		PricingMode: PricingModeDirect, Currency: "USD", DirectPrice: direct, Extensions: ext, Status: PriceStatusActive,
	}
}

func pgNext(direct DirectPrice, ext PriceExtensions) NewModelPrice {
	return NewModelPrice{
		TenantID: "t", ModelName: "m", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "USD", DirectPrice: direct, Extensions: ext, Status: PriceStatusActive,
	}
}

func pgFull() DirectPrice {
	return DirectPrice{
		InputPerMillionMicros: 4_000_000, OutputPerMillionMicros: 20_000_000,
		CachedInputPerMillionMicros: 200_000, HasCachedInputPrice: true,
		CacheWritePerMillionMicros: 5_000_000, HasCacheWritePrice: true,
	}
}

func TestSamePriceTermsIdenticalDirectPrices(t *testing.T) {
	if !samePriceTerms(pgPrevious(pgFull(), PriceExtensions{}), pgNext(pgFull(), PriceExtensions{})) {
		t.Fatal("identical direct prices must be reported as the same terms")
	}
	if samePriceTerms(nil, pgNext(pgFull(), PriceExtensions{})) {
		t.Fatal("no previous version can never be the same")
	}
}

func TestSamePriceTermsDetectsEveryBillingField(t *testing.T) {
	cases := map[string]func(*DirectPrice){
		"input":       func(d *DirectPrice) { d.InputPerMillionMicros++ },
		"output":      func(d *DirectPrice) { d.OutputPerMillionMicros++ },
		"cached read": func(d *DirectPrice) { d.CachedInputPerMillionMicros++ },
		"cache write": func(d *DirectPrice) { d.CacheWritePerMillionMicros++ },
	}
	for name, mutate := range cases {
		changed := pgFull()
		mutate(&changed)
		if samePriceTerms(pgPrevious(pgFull(), PriceExtensions{}), pgNext(changed, PriceExtensions{})) {
			t.Errorf("a different %s price must not be the same terms", name)
		}
	}
	next := pgNext(pgFull(), PriceExtensions{})
	next.Currency = "CNY"
	if samePriceTerms(pgPrevious(pgFull(), PriceExtensions{}), next) {
		t.Error("a different currency must not be the same terms")
	}
}

func TestSamePriceTermsDistinguishesUnsetFromZeroCachePrice(t *testing.T) {
	unset := pgFull()
	unset.HasCachedInputPrice, unset.CachedInputPerMillionMicros = false, 0
	zero := pgFull()
	zero.CachedInputPerMillionMicros = 0 // 显式设置为 0：缓存读免费
	if samePriceTerms(pgPrevious(unset, PriceExtensions{}), pgNext(zero, PriceExtensions{})) {
		t.Fatal("unset cache read price (bills at input rate) is not the same as an explicit 0")
	}
	if samePriceTerms(pgPrevious(zero, PriceExtensions{}), pgNext(unset, PriceExtensions{})) {
		t.Fatal("explicit 0 cache read price is not the same as unset")
	}
	// 两边都未设置：未设置价的数值字段不参与比较。
	unsetWithNoise := unset
	unsetWithNoise.CachedInputPerMillionMicros = 123
	if !samePriceTerms(pgPrevious(unset, PriceExtensions{}), pgNext(unsetWithNoise, PriceExtensions{})) {
		t.Fatal("the value of an unset price must be ignored")
	}
}

func TestSamePriceTermsComparesPriceExtensions(t *testing.T) {
	base := PriceExtensions{RequestPerCallMicros: 10, ToolPricesPerThousandMicros: map[string]Micros{"web_search": 10_000_000}}
	same := PriceExtensions{RequestPerCallMicros: 10, ToolPricesPerThousandMicros: map[string]Micros{"web_search": 10_000_000}}
	if !samePriceTerms(pgPrevious(pgFull(), base), pgNext(pgFull(), same)) {
		t.Fatal("equal extensions must be the same terms")
	}
	for name, changed := range map[string]PriceExtensions{
		"request fee": {RequestPerCallMicros: 11, ToolPricesPerThousandMicros: map[string]Micros{"web_search": 10_000_000}},
		"tool price":  {RequestPerCallMicros: 10, ToolPricesPerThousandMicros: map[string]Micros{"web_search": 25_000_000}},
		"extra tool":  {RequestPerCallMicros: 10, ToolPricesPerThousandMicros: map[string]Micros{"web_search": 10_000_000, "code": 1}},
		"reasoning":   {RequestPerCallMicros: 10, ToolPricesPerThousandMicros: map[string]Micros{"web_search": 10_000_000}, ReasoningPerMillionMicros: pgMicros(0)},
	} {
		if samePriceTerms(pgPrevious(pgFull(), base), pgNext(pgFull(), changed)) {
			t.Errorf("changed %s must not be the same terms", name)
		}
	}
}

func TestSamePriceTermsRefusesVersionsWithAnExpiry(t *testing.T) {
	prev := pgPrevious(pgFull(), PriceExtensions{})
	next := pgNext(pgFull(), PriceExtensions{})
	if !samePriceTerms(prev, next) {
		t.Fatal("precondition: identical terms")
	}
	expiry := pgMustTime(t, "2030-01-01T00:00:00Z")
	prev.ExpiresAt = &expiry
	if samePriceTerms(prev, next) {
		t.Fatal("an expiring version and an open-ended one are not the same terms")
	}
}

func pgRatioPrevious(r RatioPrice) *ModelPrice {
	return &ModelPrice{
		ID: "price_prev", TenantID: "t", ModelName: "m", CustomerGroup: DefaultCustomerGroup, Version: 1,
		PricingMode: PricingModeNewAPIRatio, Currency: "USD", RatioPrice: r, Status: PriceStatusActive,
	}
}

func pgRatioNext(r RatioPrice) NewModelPrice {
	return NewModelPrice{
		TenantID: "t", ModelName: "m", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeNewAPIRatio, Currency: "USD", RatioPrice: r, Status: PriceStatusActive,
	}
}

func pgRatio() RatioPrice {
	return RatioPrice{
		BaseInputPerMillionMicros: 2_000_000, ModelRatioPPM: 1_000_000, CompletionRatioPPM: 5_000_000, GroupRatioPPM: ratioScale,
		HasCachedInputRatio: true, CachedInputRatioPPM: 100_000,
	}
}

func TestSamePriceTermsRatioMode(t *testing.T) {
	if !samePriceTerms(pgRatioPrevious(pgRatio()), pgRatioNext(pgRatio())) {
		t.Fatal("identical ratio prices must be the same terms")
	}
	for name, mutate := range map[string]func(*RatioPrice){
		"base":       func(r *RatioPrice) { r.BaseInputPerMillionMicros++ },
		"model":      func(r *RatioPrice) { r.ModelRatioPPM++ },
		"completion": func(r *RatioPrice) { r.CompletionRatioPPM++ },
		"cached":     func(r *RatioPrice) { r.CachedInputRatioPPM++ },
		"cache write added": func(r *RatioPrice) {
			r.HasCacheWriteRatio, r.CacheWriteRatioPPM = true, 1_250_000
		},
	} {
		changed := pgRatio()
		mutate(&changed)
		if samePriceTerms(pgRatioPrevious(pgRatio()), pgRatioNext(changed)) {
			t.Errorf("a different %s must not be the same terms", name)
		}
	}
	// 计价模式不同，即使折算结果碰巧相同也是不同条款。
	if samePriceTerms(pgPrevious(pgFull(), PriceExtensions{}), pgRatioNext(pgRatio())) {
		t.Fatal("direct and ratio pricing are different terms")
	}
}

func TestZeroesPrice(t *testing.T) {
	zero := DirectPrice{}
	cases := []struct {
		name string
		prev *ModelPrice
		next NewModelPrice
		want bool
	}{
		{"non-zero to zero", pgPrevious(pgFull(), PriceExtensions{}), pgNext(zero, PriceExtensions{}), true},
		{"no previous version", nil, pgNext(zero, PriceExtensions{}), false},
		{"already free to free", pgPrevious(zero, PriceExtensions{}), pgNext(zero, PriceExtensions{}), false},
		{"only output was priced", pgPrevious(DirectPrice{OutputPerMillionMicros: 1}, PriceExtensions{}), pgNext(zero, PriceExtensions{}), true},
		{"only input was priced", pgPrevious(DirectPrice{InputPerMillionMicros: 1}, PriceExtensions{}), pgNext(zero, PriceExtensions{}), true},
		{"input zero output still charged", pgPrevious(pgFull(), PriceExtensions{}), pgNext(DirectPrice{OutputPerMillionMicros: 1}, PriceExtensions{}), false},
		{"output zero input still charged", pgPrevious(pgFull(), PriceExtensions{}), pgNext(DirectPrice{InputPerMillionMicros: 1}, PriceExtensions{}), false},
		{"cache prices left over do not count as a charge", pgPrevious(pgFull(), PriceExtensions{}), pgNext(DirectPrice{CachedInputPerMillionMicros: 5, HasCachedInputPrice: true}, PriceExtensions{}), true},
		{"ratio base zero", pgPrevious(pgFull(), PriceExtensions{}), pgRatioNext(RatioPrice{BaseInputPerMillionMicros: 0, ModelRatioPPM: 1_000_000, CompletionRatioPPM: 5_000_000}), true},
		{"ratio model ratio zero", pgPrevious(pgFull(), PriceExtensions{}), pgRatioNext(RatioPrice{BaseInputPerMillionMicros: 2_000_000, ModelRatioPPM: 0, CompletionRatioPPM: 5_000_000}), true},
		{"ratio still charges", pgPrevious(pgFull(), PriceExtensions{}), pgRatioNext(pgRatio()), false},
		{"ratio previous to zero", pgRatioPrevious(pgRatio()), pgNext(zero, PriceExtensions{}), true},
	}
	for _, tc := range cases {
		if got := zeroesPrice(tc.prev, tc.next); got != tc.want {
			t.Errorf("%s: zeroesPrice = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func pgMustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
