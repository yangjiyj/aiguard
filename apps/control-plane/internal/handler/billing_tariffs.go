package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

type createTariffPlanRequest struct {
	Name        string               `json:"name"`
	Timezone    string               `json:"timezone"`
	EffectiveAt time.Time            `json:"effective_at"`
	ExpiresAt   *time.Time           `json:"expires_at"`
	Rules       []billing.TariffRule `json:"rules"`
}

func ListBillingTariffPlans(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		plans, err := store.ListTariffPlans(r.Context(), tenantID, billingListLimit(r))
		if err != nil {
			billingTariffHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": plans})
	}
}

func CreateBillingTariffPlan(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorID, ok := billingAdmin(w, r)
		if !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		var req createTariffPlanRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		if len(req.Rules) == 0 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "at least one tariff rule is required")
			return
		}
		for _, rule := range req.Rules {
			if strings.TrimSpace(rule.ModelName) == "" {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "each tariff rule must specify model_name")
				return
			}
			if rule.SpecialDate != nil {
				writeErrorWithStatus(w, http.StatusBadRequest, "tariff_date_rules_unsupported", "仅支持每周时段，不能新增或修改指定日期规则。")
				return
			}
		}
		plan, err := store.CreateTariffPlan(r.Context(), billing.NewTariffPlan{
			TenantID: tenantID, Name: req.Name, Timezone: req.Timezone,
			EffectiveAt: req.EffectiveAt, ExpiresAt: req.ExpiresAt,
			CreatedBy: actorID, Rules: req.Rules,
		})
		if err != nil {
			billingTariffHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.tariff.create", map[string]interface{}{
			"tenant_id": tenantID, "draft_id": plan.ID, "version": plan.Version, "name": req.Name, "rules": len(req.Rules),
		}, "billing_tariff_plan", plan.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": plan})
	}
}

func UpdateBillingTariffPlan(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorID, ok := billingAdmin(w, r)
		if !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		var req createTariffPlanRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		if len(req.Rules) == 0 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "at least one tariff rule is required")
			return
		}
		for _, rule := range req.Rules {
			if strings.TrimSpace(rule.ModelName) == "" {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "each tariff rule must specify model_name")
				return
			}
			if rule.SpecialDate != nil {
				writeErrorWithStatus(w, http.StatusBadRequest, "tariff_date_rules_unsupported", "仅支持每周时段，不能新增或修改指定日期规则。")
				return
			}
		}
		planID := chi.URLParam(r, "id")
		plan, err := store.UpdateTariffPlan(r.Context(), planID, billing.NewTariffPlan{
			TenantID: tenantID, Name: req.Name, Timezone: req.Timezone,
			EffectiveAt: req.EffectiveAt, ExpiresAt: req.ExpiresAt,
			CreatedBy: actorID, Rules: req.Rules,
		})
		if err != nil {
			billingTariffHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.tariff.edit", map[string]interface{}{
			"tenant_id": tenantID, "draft_id": plan.ID, "version": plan.Version,
		}, "billing_tariff_plan", planID)
		writeJSON(w, map[string]any{"data": plan})
	}
}

func DeleteBillingTariffPlan(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		planID := chi.URLParam(r, "id")
		if err := store.DeleteTariffPlan(r.Context(), tenantID, planID); err != nil {
			if errors.Is(err, billing.ErrTariffNotDraft) {
				writeErrorWithStatus(w, http.StatusConflict, "tariff_active", "请先停用生效中的方案，再删除。停用后新请求按原价计费。")
				return
			}
			billingTariffHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.tariff.delete", map[string]interface{}{
			"tenant_id": tenantID,
		}, "billing_tariff_plan", planID)
		w.WriteHeader(http.StatusNoContent)
	}
}

func RetireBillingTariffPlan(deps *Dependencies) http.HandlerFunc {
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
		id := chi.URLParam(r, "id")
		plan, err := store.RetireTariffPlan(r.Context(), tenant, id)
		if err != nil {
			billingTariffHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.tariff.retire", map[string]any{"tenant_id": tenant, "plan_id": id, "version": plan.Version}, "billing_tariff_plan", id)
		writeJSON(w, map[string]any{"data": plan})
	}
}

func PublishBillingTariffPlan(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		planID := chi.URLParam(r, "id")
		plan, err := store.PublishTariffPlan(r.Context(), tenantID, planID)
		if err != nil {
			billingTariffHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.tariff.publish", map[string]interface{}{
			"tenant_id": tenantID, "draft_id": planID, "plan_id": plan.ID, "version": plan.Version,
		}, "billing_tariff_plan", plan.ID)
		writeJSON(w, map[string]any{"data": plan})
	}
}

func PreviewBillingTariff(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		modelName := strings.TrimSpace(r.URL.Query().Get("model_name"))
		if modelName == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "model_name is required for model-scoped tariff preview")
			return
		}
		at := time.Now().UTC()
		if value := strings.TrimSpace(r.URL.Query().Get("at")); value != "" {
			parsed, err := time.Parse(time.RFC3339, value)
			if err != nil {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_time", "at must be RFC3339")
				return
			}
			at = parsed.UTC()
		}
		quote, err := store.ResolveTariffQuoteForModel(r.Context(), tenantID, modelName, at)
		if err != nil {
			billingTariffHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": quote})
	}
}

func billingTariffHTTPError(w http.ResponseWriter, err error) {
	if errors.Is(err, billing.ErrTariffLegacyDateRulesReadOnly) {
		writeErrorWithStatus(w, http.StatusConflict, "tariff_legacy_date_rules_read_only", "此方案含历史日期规则，仅供查看；请停用后新建每周时段方案。")
		return
	}
	if errors.Is(err, billing.ErrTariffDateRulesUnsupported) {
		writeErrorWithStatus(w, http.StatusBadRequest, "tariff_date_rules_unsupported", "仅支持每周时段，不能新增或修改指定日期规则。")
		return
	}
	billingHTTPError(w, err)
}
