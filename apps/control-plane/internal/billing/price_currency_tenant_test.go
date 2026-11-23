package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestModelPriceDefaultsToLockedTenantCurrencyWithOrWithoutAllowance(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-allowance", true: "allowance"}[enabled], func(t *testing.T) {
			store, _, tenant, _ := setupBillingStoreTest(t)
			ctx := context.Background()
			cfg := EmployeeSettings{Currency: "USD", Timezone: "UTC"}
			if enabled {
				cap := int64(100_000)
				cfg.DefaultMonthlyMicros = &cap
			}
			if err := store.SaveEmployeeSettings(ctx, tenant, cfg); err != nil {
				t.Fatal(err)
			}
			price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "tenant-default", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000}, EffectiveAt: time.Now().Add(-time.Minute)})
			if err != nil || price.Currency != "USD" {
				t.Fatalf("price=%+v err=%v", price, err)
			}
			resolved, err := store.ResolveModelPrice(ctx, tenant, "tenant-default", DefaultCustomerGroup, time.Now())
			if err != nil || resolved.Currency != "USD" {
				t.Fatalf("resolved=%+v err=%v", resolved, err)
			}
		})
	}
}

func TestModelPriceRejectsExplicitConfiguredTenantCurrencyMismatch(t *testing.T) {
	store, db, tenant, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	_, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "wrong-unit", PricingMode: PricingModeDirect, Currency: "CNY", DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000}})
	if !errors.Is(err, ErrAllowanceCurrency) {
		t.Fatalf("mismatch=%v", err)
	}
	var rows int
	if err = db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_model_prices WHERE tenant_id=$1`, tenant).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("rows=%d err=%v", rows, err)
	}
}

func TestUnconfiguredTenantPriceKeepsProcessDefaultAndAllowsExplicitUSDFirstPrice(t *testing.T) {
	store, _, tenant, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "default-unit", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000}})
	if err != nil || price.Currency != store.DefaultCurrency() {
		t.Fatalf("default price=%+v err=%v", price, err)
	}
	otherStore, _, otherTenant, _ := setupBillingStoreTest(t)
	price, err = otherStore.CreateModelPrice(ctx, NewModelPrice{TenantID: otherTenant, ModelName: "legacy-usd", PricingMode: PricingModeDirect, Currency: "USD", DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000}})
	if err != nil || price.Currency != "USD" {
		t.Fatalf("legacy explicit USD=%+v err=%v", price, err)
	}
}
