package billing

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestLegacyUSDPriceAndPersonalAllowanceUseCanonicalCurrency(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	_, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "legacy-usd", Currency: "USD", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000}, EffectiveAt: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := store.GetEmployeeSettings(ctx, tenant)
	if err != nil || cfg.Currency != "USD" || cfg.DefaultMonthlyMicros != nil {
		t.Fatalf("projection=%+v err=%v", cfg, err)
	}
	cap := int64(1000)
	if err = store.SetEmployeeAllowances(ctx, tenant, []string{user}, &cap); err != nil {
		t.Fatal(err)
	}
	if err = store.ReserveEmployeeAllowance(ctx, tenant, user, "legacy-usd-hold", "USD", 100, time.Now()); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "implicit-usd", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000}})
	if err != nil || price.Currency != "USD" {
		t.Fatalf("default price=%+v err=%v", price, err)
	}
	var currency string
	if err = db.QueryRow(ctx, `SELECT currency FROM billing_wallet_monthly_grants WHERE tenant_id=$1`, tenant).Scan(&currency); err != nil || currency != "USD" {
		t.Fatalf("hold currency=%s err=%v", currency, err)
	}
	if err = store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "Asia/Shanghai"}); err != nil {
		t.Fatalf("same inferred currency must not reinterpret active allowance: %v", err)
	}
}

func TestFundedWalletPreventsPriceAndSettingsDenominationChange(t *testing.T) {
	store, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Credit(ctx, tenant, wallet.ID, "unit-credit", 100, "test"); err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "wrong-usd", Currency: "USD", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1}})
	if !errors.Is(err, ErrAllowanceCurrency) {
		t.Fatalf("funded CNY wallet changed unit: %v", err)
	}
	if err = store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "Asia/Shanghai"}); !errors.Is(err, ErrAllowanceCurrency) {
		t.Fatalf("funded unit changed: %v", err)
	}
	cfg, err := store.GetEmployeeSettings(ctx, tenant)
	if err != nil || cfg.Currency != "CNY" {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
}

func TestCanonicalCurrencyAllowsRepairingLegacyPriceAndCostInEitherOrder(t *testing.T) {
	for _, costFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "cost-first", false: "price-first"}[costFirst], func(t *testing.T) {
			store, db, tenant, _ := setupBillingStoreTest(t)
			ctx := context.Background()
			if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "UTC"}); err != nil {
				t.Fatal(err)
			}
			price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "repair", Currency: "USD", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1}, EffectiveAt: time.Now().Add(-time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			provider := "repair_" + tenant
			if _, err = db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,$1,'openai')`, provider, tenant); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name) VALUES($1,$2,'repair')`, provider+"_model", provider); err != nil {
				t.Fatal(err)
			}
			// These states were accepted before tenant-denomination validation existed.
			if _, err = db.Exec(ctx, `UPDATE billing_model_prices SET currency='CNY' WHERE id=$1`, price.ID); err != nil {
				t.Fatal(err)
			}
			legacy := UpstreamRate{ProviderID: provider, ModelName: "repair", Currency: "CNY", InputMicros: 1}
			blob, _ := json.Marshal(legacy)
			if _, err = db.Exec(ctx, `INSERT INTO billing_upstream_rates(tenant_id,provider_id,model_name,currency,price_json) VALUES($1,$2,$3,'CNY',$4)`, tenant, provider, legacy.ModelName, blob); err != nil {
				t.Fatal(err)
			}
			fixCost := func() {
				legacy.Currency = "USD"
				if err = store.SaveUpstreamRate(ctx, tenant, legacy); err != nil {
					t.Fatalf("repair cost: %v", err)
				}
			}
			fixPrice := func() {
				_, err = store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "repair", Currency: "USD", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1}})
				if err != nil {
					t.Fatalf("repair price: %v", err)
				}
			}
			if costFirst {
				fixCost()
				fixPrice()
			} else {
				fixPrice()
				fixCost()
			}
		})
	}
}
