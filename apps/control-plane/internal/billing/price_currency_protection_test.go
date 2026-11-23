package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCurrentDefaultPriceProtectsDenominationWithoutFinancialSettings(t *testing.T) {
	store, _, tenant, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	price := NewModelPrice{TenantID: tenant, ModelName: "first-usd", Currency: "USD", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1}, EffectiveAt: time.Now().Add(-time.Minute)}
	if _, err := store.CreateModelPrice(ctx, price); err != nil {
		t.Fatalf("first USD price: %v", err)
	}
	price.Currency = "CNY"
	for _, model := range []string{"first-usd", "new-cny"} {
		price.ModelName = model
		if _, err := store.CreateModelPrice(ctx, price); !errors.Is(err, ErrAllowanceCurrency) {
			t.Fatalf("model=%s changed effective denomination: %v", model, err)
		}
	}
	price.ModelName, price.Currency = "new-usd", ""
	if saved, err := store.CreateModelPrice(ctx, price); err != nil || saved.Currency != "USD" {
		t.Fatalf("inferred price=%+v err=%v", saved, err)
	}
	if currency, err := store.BillingCurrencyForTenant(ctx, tenant); err != nil || currency != "USD" {
		t.Fatalf("currency=%s err=%v", currency, err)
	}
}

func TestLegacyMixedPricesAllowOnlyExistingModelRepair(t *testing.T) {
	store, db, tenant, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	price := NewModelPrice{TenantID: tenant, ModelName: "old-usd", Currency: "USD", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1}, EffectiveAt: time.Now().Add(-time.Minute)}
	first, err := store.CreateModelPrice(ctx, price)
	if err != nil {
		t.Fatal(err)
	}
	// Direct insert reproduces a legacy state that the save API now prevents.
	if _, err := db.Exec(ctx, `INSERT INTO billing_model_prices(id,tenant_id,model_name,customer_group,version,pricing_mode,currency,input_per_million_micros,output_per_million_micros,status,effective_at) SELECT $1,tenant_id,'old-cny',customer_group,1,pricing_mode,'CNY',input_per_million_micros,output_per_million_micros,status,effective_at FROM billing_model_prices WHERE id=$2`, tenant+"-legacy-cny", first.ID); err != nil {
		t.Fatal(err)
	}
	price.ModelName = "new-model"
	if _, err := store.CreateModelPrice(ctx, price); !errors.Is(err, ErrMixedCurrency) {
		t.Fatalf("new model expanded legacy ambiguity: %v", err)
	}
	price.ModelName, price.Currency = "old-cny", ""
	if _, err := store.CreateModelPrice(ctx, price); !errors.Is(err, ErrMixedCurrency) {
		t.Fatalf("implicit repair guessed a denomination: %v", err)
	}
	price.Currency = "USD"
	if _, err := store.CreateModelPrice(ctx, price); err != nil {
		t.Fatalf("explicit existing-model repair: %v", err)
	}
	if currency, err := store.BillingCurrencyForTenant(ctx, tenant); err != nil || currency != "USD" {
		t.Fatalf("repaired currency=%s err=%v", currency, err)
	}
}
