package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Billing records retain the declared USD/CNY unit; conversion is left to finance.
func TestCreateModelPriceSupportsUSDAndCNYWithoutExchangeConversion(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	_, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "fx-model", CustomerGroup: "default",
		PricingMode: PricingModeDirect, Currency: "USD",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 4_000_000},
		EffectiveAt: now.Add(-time.Hour), Status: PriceStatusActive, CreatedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("USD price: %v", err)
	}
	if price, err := store.ResolveModelPrice(ctx, tenantID, "fx-model", "default", now); err != nil || price.Currency != "USD" || price.DirectPrice.InputPerMillionMicros != 1_000_000 {
		t.Fatalf("source currency and money must be preserved: %+v %v", price, err)
	}
	if _, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenantID, ModelName: "unsupported-fx-model", Currency: "EUR", PricingMode: PricingModeDirect}); !errors.Is(err, ErrPriceCurrencyUnsupported) {
		t.Fatalf("unsupported currency: %v", err)
	}
	otherStore, _, otherTenant, _ := setupBillingStoreTest(t)
	if _, err := otherStore.CreateModelPrice(ctx, NewModelPrice{
		TenantID: otherTenant, ModelName: "fx-model", CustomerGroup: "default",
		PricingMode: PricingModeDirect, Currency: otherStore.DefaultCurrency(),
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 4_000_000},
		EffectiveAt: now.Add(-time.Hour), Status: PriceStatusActive, CreatedBy: "admin-a",
	}); err != nil {
		t.Fatalf("billing-currency price: %v", err)
	}
}
