package handler

import (
	"net/http"

	"github.com/yangjiyj/aiguard/packages/shared-go/billingmedia"
)

func GetBillingPricingCapabilities(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		if _, ok := billingTenant(w, r); !ok {
			return
		}
		id, recognized := billingmedia.SuggestedImageTemplate(r.URL.Query().Get("model_name"))
		writeJSON(w, map[string]any{"data": map[string]any{"image_models": billingmedia.ImageTemplates(), "tools": billingmedia.ToolCapabilitiesForModel(r.URL.Query().Get("model_name")), "recognized_model": recognized, "suggested_template_id": id}})
	}
}
