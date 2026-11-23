package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/billingmedia"
)

func TestBillingPricingCapabilitiesUsesExistingAdminAndTenantBoundary(t *testing.T) {
	for _, c := range []struct {
		role, query string
		status      int
	}{{"developer", "?tenant_id=t", 403}, {"platform_admin", "", 400}, {"platform_admin", "?tenant_id=t&model_name=gpt-4.1-mini", 200}} {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/billing/pricing-capabilities"+c.query, nil)
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u", TenantID: "t", Role: c.role, Status: "active"}))
		w := httptest.NewRecorder()
		GetBillingPricingCapabilities(&Dependencies{})(w, req)
		if w.Code != c.status {
			t.Fatalf("role=%s query=%s: %d %s", c.role, c.query, w.Code, w.Body.String())
		}
		if c.status == 200 {
			var body struct {
				Data struct {
					Tools       []billingmedia.ToolCapability     `json:"tools"`
					ImageModels []billingmedia.ImageModelTemplate `json:"image_models"`
				} `json:"data"`
			}
			if json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body.Data.Tools) == 0 || len(body.Data.ImageModels) == 0 {
				t.Fatalf("catalog missing: %s", w.Body.String())
			}
		}
	}
}
