package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func ListBillingChannelFixedCosts(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		costs, err := store.ListChannelFixedCosts(r.Context(), tenant)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		channels, err := store.ListCostChannels(r.Context(), tenant)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": costs, "channels": channels})
	}
}
func fixedCostHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, billing.ErrFixedCostOverlap):
		writeErrorWithStatus(w, 409, "fixed_cost_period_overlap", "同一渠道的固定费用生效区间不能重叠，请调整日期")
	case errors.Is(err, billing.ErrFixedCostNotFound):
		writeErrorWithStatus(w, 404, "fixed_cost_not_found", "渠道固定费用不存在")
	case errors.Is(err, billing.ErrAllowanceCurrency):
		writeErrorWithStatus(w, 409, "cost_currency_mismatch", "渠道成本币种必须与租户计价币种和员工额度一致，系统不进行汇率转换")
	case errors.Is(err, billing.ErrInvalidPrice):
		writeErrorWithStatus(w, 400, "invalid_fixed_cost", "请选择有效渠道、金额、周期和生效区间；结束日期不含当天")
	default:
		billingHTTPError(w, err)
	}
}
func PutBillingChannelFixedCost(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := billingAdmin(w, r)
		if !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		var req billing.ChannelFixedCost
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
			writeErrorWithStatus(w, 400, "invalid_request", "invalid JSON")
			return
		}
		req.CreatedBy = actor
		result, err := store.SaveChannelFixedCost(r.Context(), tenant, req)
		if err != nil {
			fixedCostHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.channel_fixed_cost.upsert", map[string]any{"tenant_id": tenant, "provider_id": req.ProviderID, "amount_micros": req.AmountMicros, "currency": req.Currency, "period": req.Period, "effective_from": req.EffectiveFrom, "effective_to": req.EffectiveTo}, "billing_channel_fixed_cost", result.ID)
		writeJSON(w, map[string]any{"data": result})
	}
}
func DeleteBillingChannelFixedCost(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			writeErrorWithStatus(w, 400, "invalid_request", "id is required")
			return
		}
		if err := store.DeleteChannelFixedCost(r.Context(), tenant, id); err != nil {
			fixedCostHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.channel_fixed_cost.delete", map[string]any{"tenant_id": tenant}, "billing_channel_fixed_cost", id)
		w.WriteHeader(http.StatusNoContent)
	}
}
func DeleteBillingUpstreamRate(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		provider, model := r.URL.Query().Get("provider_id"), r.URL.Query().Get("model_name")
		if err := store.DeleteUpstreamRate(r.Context(), tenant, provider, model); err != nil {
			billingHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.upstream.rate.delete", map[string]any{"tenant_id": tenant, "provider_id": provider, "model_name": model}, "tenant", tenant)
		w.WriteHeader(http.StatusNoContent)
	}
}
