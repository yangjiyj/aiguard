package handler

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

// portalModelPriceGroup is the only customer group actually used when a
// request is billed (ResolveModelPrice). The price market must show exactly
// what will be charged, so other groups are never exposed to employees.
const portalModelPriceGroup = "default"

type portalModelPrice struct {
	ModelName                   string                  `json:"model_name"`
	Currency                    string                  `json:"currency"`
	PricingMode                 string                  `json:"pricing_mode"`
	InputPerMillionMicros       int64                   `json:"input_per_million_micros"`
	CachedInputPerMillionMicros int64                   `json:"cached_input_per_million_micros"`
	CacheWritePerMillionMicros  int64                   `json:"cache_write_per_million_micros"`
	OutputPerMillionMicros      int64                   `json:"output_per_million_micros"`
	HasCachedInputPrice         bool                    `json:"has_cached_input_price"`
	HasCacheWritePrice          bool                    `json:"has_cache_write_price"`
	Extras                      billing.PriceExtensions `json:"pricing_extras"`
	EffectiveAt                 time.Time               `json:"effective_at"`
	ExpiresAt                   *time.Time              `json:"expires_at"`
}

// portalModelPriceView converts a stored price into the employee-facing
// projection. Ratio (New API) prices are normalised to direct per-million
// prices so the portal never has to reimplement billing arithmetic.
func portalModelPriceView(item billing.ModelPrice) (portalModelPrice, bool) {
	direct, err := item.AsDirectPrice()
	if err != nil {
		return portalModelPrice{}, false
	}
	return portalModelPrice{
		ModelName:                   item.ModelName,
		Currency:                    item.Currency,
		PricingMode:                 item.PricingMode,
		InputPerMillionMicros:       int64(direct.InputPerMillionMicros),
		CachedInputPerMillionMicros: int64(direct.CachedInputPerMillionMicros),
		CacheWritePerMillionMicros:  int64(direct.CacheWritePerMillionMicros),
		OutputPerMillionMicros:      int64(direct.OutputPerMillionMicros),
		HasCachedInputPrice:         direct.HasCachedInputPrice,
		HasCacheWritePrice:          direct.HasCacheWritePrice,
		Extras:                      item.Extensions,
		EffectiveAt:                 item.EffectiveAt,
		ExpiresAt:                   item.ExpiresAt,
	}, true
}

// portalModelPriceList keeps only billable default-group prices, optionally
// restricted to the employee's allow-list of model names (an empty list yields
// nothing, never "everything"), sorted by model name.
func portalModelPriceList(prices []billing.ModelPrice, models []string) []portalModelPrice {
	allowed := map[string]bool{}
	for _, model := range models {
		if model = strings.TrimSpace(model); model != "" {
			allowed[model] = true
		}
	}
	out := make([]portalModelPrice, 0, len(prices))
	seen := map[string]bool{}
	for _, item := range prices {
		if item.CustomerGroup != portalModelPriceGroup || seen[item.ModelName] {
			continue
		}
		if !allowed[item.ModelName] {
			continue
		}
		view, ok := portalModelPriceView(item)
		if !ok {
			continue
		}
		seen[item.ModelName] = true
		out = append(out, view)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ModelName < out[j].ModelName })
	return out
}

// GetPortalModelPrices is the read model behind the portal "model price
// market". The BFF passes the signed-in employee's authorised models via
// repeated ?model= parameters; the browser never talks to this route.
func GetPortalModelPrices(deps *Dependencies) http.HandlerFunc {
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
		models := r.URL.Query()["model"]
		if len(models) > 500 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "too many models")
			return
		}
		prices, err := store.ListEffectiveModelPrices(r.Context(), tenantID, 500)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": portalModelPriceList(prices, models), "customer_group": portalModelPriceGroup})
	}
}
