package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

// A ratio price preserves the model side of the New API equation: base input
// price multiplied by model, completion, cache-read, and cache-write ratios.
// The customer-group ratio is configured separately and snapshotted at admission.
type billingRatioPriceRequest struct {
	PricingExtras             billing.PriceExtensions `json:"pricing_extras"`
	TenantID                  string                  `json:"tenant_id"`
	ModelName                 string                  `json:"model_name"`
	Currency                  string                  `json:"currency"`
	Status                    string                  `json:"status"`
	BaseInputPerMillionMicros int64                   `json:"base_input_per_million_micros"`
	ModelRatioPPM             *int64                  `json:"model_ratio_ppm"`
	CompletionRatioPPM        *int64                  `json:"completion_ratio_ppm"`
	CachedInputRatioPPM       *int64                  `json:"cached_input_ratio_ppm"`
	CacheWriteRatioPPM        *int64                  `json:"cache_write_ratio_ppm"`
	EffectiveAt               string                  `json:"effective_at"`
	// ConfirmZeroPrice 必须由操作员明确确认才能把非零价格改成 0；缺省为 false。
	ConfirmZeroPrice bool `json:"confirm_zero_price"`
}

func CreateBillingRatioPrice(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorID, ok := billingAdmin(w, r)
		if !ok {
			return
		}
		var req billingRatioPriceRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		req.TenantID = strings.TrimSpace(req.TenantID)
		req.ModelName = strings.TrimSpace(req.ModelName)
		req.Currency = strings.ToUpper(strings.TrimSpace(req.Currency))
		req.Status = strings.TrimSpace(req.Status)
		if req.TenantID == "" || req.ModelName == "" || req.BaseInputPerMillionMicros < 0 ||
			(req.ModelRatioPPM != nil && *req.ModelRatioPPM < 0) || (req.CompletionRatioPPM != nil && *req.CompletionRatioPPM < 0) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "tenant_id, model_name, and non-negative ratio price values are required")
			return
		}
		if req.CachedInputRatioPPM != nil && *req.CachedInputRatioPPM < 0 ||
			req.CacheWriteRatioPPM != nil && *req.CacheWriteRatioPPM < 0 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "cache ratios cannot be negative")
			return
		}
		effectiveAt := time.Now().UTC()
		if req.EffectiveAt != "" {
			value, err := time.Parse(time.RFC3339, req.EffectiveAt)
			if err != nil {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "effective_at must be RFC3339")
				return
			}
			effectiveAt = value
		}
		modelRatio, completionRatio := int64(1_000_000), int64(1_000_000)
		if req.ModelRatioPPM != nil {
			modelRatio = *req.ModelRatioPPM
		}
		if req.CompletionRatioPPM != nil {
			completionRatio = *req.CompletionRatioPPM
		}
		price := billing.NewModelPrice{
			TenantID: req.TenantID, ModelName: req.ModelName, CustomerGroup: billing.DefaultCustomerGroup,
			PricingMode: billing.PricingModeNewAPIRatio, Currency: req.Currency, Status: req.Status, Extensions: req.PricingExtras,
			EffectiveAt: effectiveAt, CreatedBy: actorID,
			RatioPrice: billing.RatioPrice{
				BaseInputPerMillionMicros: billing.Micros(req.BaseInputPerMillionMicros),
				ModelRatioPPM:             modelRatio, CompletionRatioPPM: completionRatio, GroupRatioPPM: 1_000_000,
			},
		}
		if req.CachedInputRatioPPM != nil {
			price.RatioPrice.HasCachedInputRatio = true
			price.RatioPrice.CachedInputRatioPPM = *req.CachedInputRatioPPM
		}
		if req.CacheWriteRatioPPM != nil {
			price.RatioPrice.HasCacheWriteRatio = true
			price.RatioPrice.CacheWriteRatioPPM = *req.CacheWriteRatioPPM
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		saved, err := store.SaveModelPrice(r.Context(), price, billing.SavePriceOptions{
			ConfirmZeroPrice: req.ConfirmZeroPrice,
			Audit:            priceAuditSpec(r, actorID, "billing.ratio_price.create", req.TenantID, req.ModelName),
		})
		if err != nil {
			writePriceSaveError(w, r, deps, req.TenantID, err)
			return
		}
		created := saved.Price
		appendPriceAuditChain(r, deps, req.TenantID, saved)
		writeJSON(w, map[string]any{"data": map[string]any{
			"id": created.ID, "version": created.Version, "pricing_mode": created.PricingMode,
			"effective_at": created.EffectiveAt, "unchanged": saved.Unchanged,
		}})
	}
}
