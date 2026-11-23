package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func TestPortalModelPriceListFiltersGroupAndAuthorisedModels(t *testing.T) {
	now := time.Now().UTC()
	prices := []billing.ModelPrice{
		{ModelName: "qwen", CustomerGroup: "default", PricingMode: billing.PricingModeDirect, Currency: "CNY", EffectiveAt: now,
			DirectPrice: billing.DirectPrice{InputPerMillionMicros: 2_000_000, OutputPerMillionMicros: 8_000_000}},
		{ModelName: "qwen", CustomerGroup: "vip", PricingMode: billing.PricingModeDirect, Currency: "CNY", EffectiveAt: now,
			DirectPrice: billing.DirectPrice{InputPerMillionMicros: 1, OutputPerMillionMicros: 1}},
		{ModelName: "deepseek", CustomerGroup: "default", PricingMode: billing.PricingModeNewAPIRatio, Currency: "CNY", EffectiveAt: now,
			RatioPrice: billing.RatioPrice{BaseInputPerMillionMicros: 2_000_000, ModelRatioPPM: 500_000, CompletionRatioPPM: 4_000_000, GroupRatioPPM: 1_000_000}},
		{ModelName: "secret-model", CustomerGroup: "default", PricingMode: billing.PricingModeDirect, Currency: "CNY", EffectiveAt: now,
			DirectPrice: billing.DirectPrice{InputPerMillionMicros: 9, OutputPerMillionMicros: 9}},
	}
	got := portalModelPriceList(prices, []string{"qwen", " deepseek ", ""})
	if len(got) != 2 {
		t.Fatalf("expected 2 authorised default-group prices, got %d: %+v", len(got), got)
	}
	if got[0].ModelName != "deepseek" || got[1].ModelName != "qwen" {
		t.Fatalf("expected sorted by model name, got %s,%s", got[0].ModelName, got[1].ModelName)
	}
	if got[0].InputPerMillionMicros != 1_000_000 || got[0].OutputPerMillionMicros != 4_000_000 {
		t.Fatalf("ratio price must be normalised to direct price, got %+v", got[0])
	}
	if got[1].InputPerMillionMicros != 2_000_000 {
		t.Fatalf("default group price must win over other groups, got %+v", got[1])
	}
}

func TestPortalModelPriceListFailsClosedWithoutModels(t *testing.T) {
	prices := []billing.ModelPrice{{ModelName: "qwen", CustomerGroup: "default", PricingMode: billing.PricingModeDirect,
		DirectPrice: billing.DirectPrice{InputPerMillionMicros: 1, OutputPerMillionMicros: 1}}}
	if got := portalModelPriceList(prices, nil); len(got) != 0 {
		t.Fatalf("no authorised models must expose no prices, got %+v", got)
	}
}

func TestGetPortalModelPricesRequiresTenant(t *testing.T) {
	rec := httptest.NewRecorder()
	GetPortalModelPrices(&Dependencies{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/model-prices", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without tenant header, got %d", rec.Code)
	}
}
