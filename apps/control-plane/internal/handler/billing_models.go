package handler

import (
	"net/http"
	"sort"
	"strings"
)

type billingModelInfo struct {
	ModelName    string `json:"model_name"`
	ModelLabel   string `json:"model_label"`
	ProviderName string `json:"provider_name"`
	ProviderType string `json:"provider_type"`
	Status       string `json:"status"`
}

// ListBillingModels returns the customer-facing model catalog for exactly the
// tenant selected by a platform administrator. Internal routing coordinates
// and provider credentials are intentionally omitted.
func ListBillingModels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		if deps == nil || deps.ModelRepo == nil || deps.ProviderRepo == nil {
			portalNotConfigured(w, "billing model catalog")
			return
		}

		models, err := deps.ModelRepo.List(r.Context(), tenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list billing models")
			return
		}
		providers, err := deps.ProviderRepo.List(r.Context(), tenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list billing models")
			return
		}

		providerNames := make(map[string]string, len(providers))
		providerTypes := make(map[string]string, len(providers))
		for _, provider := range providers {
			if provider == nil || strings.TrimSpace(provider.TenantID) != tenantID {
				continue
			}
			providerNames[provider.ID] = strings.TrimSpace(provider.Name)
			providerTypes[provider.ID] = strings.TrimSpace(provider.ProviderType)
		}
		data := make([]billingModelInfo, 0, len(models))
		for _, model := range models {
			if model == nil {
				continue
			}
			modelName := strings.TrimSpace(model.ModelName)
			providerName, providerOK := providerNames[model.ProviderID]
			if modelName == "" || !providerOK {
				continue
			}
			data = append(data, billingModelInfo{
				ModelName:    modelName,
				ModelLabel:   strings.TrimSpace(model.ModelLabel),
				ProviderName: providerName,
				Status:       strings.TrimSpace(model.Status),
			})
		}
		sort.SliceStable(data, func(i, j int) bool {
			if data[i].ModelName != data[j].ModelName {
				return data[i].ModelName < data[j].ModelName
			}
			return data[i].ProviderName < data[j].ProviderName
		})
		writeJSON(w, map[string]any{"data": data})
	}
}
