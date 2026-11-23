package billing

import (
	"context"
	"testing"
	"time"
)

func TestUSDTenantPreservesCurrentAndLegacyUnpricedCounts(t *testing.T) {
	_, db, tenant, user := setupBillingStoreTest(t)
	store := NewStore(db)
	store.defaultCurrency = "USD"
	ctx := context.Background()
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "Asia/Shanghai"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "paid-usd", Currency: "USD", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 1_000_000}, EffectiveAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, model := range []string{"paid-usd", "unpriced-usd"} {
		fact, err := store.RecordMeteringUsage(ctx, MeteringInput{TenantID: tenant, UserID: user, RequestID: user + "-" + model, ModelName: model, RequestStatus: "success", Usage: Usage{PromptTokens: 2, OutputTokens: 3}})
		if err != nil || fact.Currency != "USD" {
			t.Fatalf("model=%s fact=%+v err=%v", model, fact, err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,user_id,model_name,currency,status,prompt_tokens,occurred_at,admitted_at) VALUES($1,$2,$1,'metering',$3,'legacy-unpriced','CNY','unpriced',2,NOW(),NOW())`, user+"-legacy", tenant, user); err != nil {
		t.Fatal(err)
	}
	filter := AnalyticsFilter{TenantID: tenant, Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour), FullTenant: true}
	for _, currency := range []string{"", "USD"} {
		filter.Currency = currency
		summary, err := store.GetAnalyticsSummary(ctx, filter)
		if err != nil || summary.Currency != "USD" || summary.UnpricedRequests != 2 || summary.BillableMicros != 5 {
			t.Fatalf("summary=%+v err=%v", summary, err)
		}
		if _, err := store.GetAnalyticsBreakdown(ctx, filter, "model", 20); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetAnalyticsSeries(ctx, filter, "day"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetAnalyticsDepartmentProviderMatrix(ctx, filter); err != nil {
			t.Fatal(err)
		}
	}
	statement, err := store.MonthlyStatement(ctx, tenant, time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01"))
	if err != nil || statement.Currency != "USD" || statement.Total.UnpricedRequests != 2 || statement.Total.BilledMicros != 5 {
		t.Fatalf("statement=%+v err=%v", statement, err)
	}
}

func TestTenantCurrencySummaryAndCustomerListsUseFundedUSDWallet(t *testing.T) {
	store, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "USD", Timezone: "Asia/Shanghai"}); err != nil {
		t.Fatal(err)
	}
	wallet, err := store.CreditUserWallet(ctx, tenant, user, "fund-tenant-usd", 1000, "test")
	if err != nil || wallet.Currency != "USD" {
		t.Fatalf("wallet=%+v err=%v", wallet, err)
	}
	summary, err := store.CustomerSummary(ctx, tenant, user, time.Now().Add(-time.Hour), 20)
	if err != nil || summary.Wallet.Currency != "USD" || summary.Wallet.BalanceMicros != 1000 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	list, err := store.ListAdminCustomers(ctx, tenant, 20)
	if err != nil || len(list) != 1 || list[0].Currency != "USD" || list[0].BalanceMicros != 1000 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	page, _, err := store.ListAdminCustomersPage(ctx, tenant, 20, "")
	if err != nil || len(page) != 1 || page[0].Currency != "USD" || page[0].BalanceMicros != 1000 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}

func TestTenantCurrencyIgnoresHistoricAndLegacyGroupPriceCurrencies(t *testing.T) {
	store, db, tenant, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	if err := store.EnsureDefaultCustomerGroup(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateCustomerGroup(ctx, NewCustomerGroup{TenantID: tenant, Code: "legacy-group", Name: "legacy-group", RatioPPM: 1_000_000}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO billing_model_prices(id,tenant_id,model_name,customer_group,version,pricing_mode,currency,input_per_million_micros,output_per_million_micros,status,effective_at) VALUES($1,$4,'current-model','default',1,'direct','CNY',1,1,'active',NOW()-INTERVAL '2 hours'),($2,$4,'current-model','default',2,'direct','USD',1,1,'active',NOW()-INTERVAL '1 hour'),($3,$4,'current-model','legacy-group',1,'direct','CNY',1,1,'active',NOW()-INTERVAL '1 hour')`, tenant+"-old", tenant+"-new", tenant+"-group", tenant); err != nil {
		t.Fatal(err)
	}
	currency, err := store.BillingCurrencyForTenant(ctx, tenant)
	if err != nil || currency != "USD" {
		t.Fatalf("currency=%s err=%v", currency, err)
	}
}

func TestMeteringZeroAmountReservationSettlesWithoutInvalidWalletState(t *testing.T) {
	store, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.CreditUserWallet(ctx, tenant, user, "fund-free", 1000, "test")
	if err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "free-priced", Currency: "CNY", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{}, EffectiveAt: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	request := user + "-free-priced"
	if _, _, err := store.ReservePricedWithUsage(ctx, tenant, wallet.ID, request, 0, 1, price); err != nil {
		t.Fatal(err)
	}
	fact, err := store.RecordMeteringUsage(ctx, MeteringInput{TenantID: tenant, UserID: user, RequestID: request, ModelName: "free-priced", QuotePriceID: price.ID, RequestStatus: "success", Usage: Usage{PromptTokens: 1}})
	if err != nil || fact.BillableAmountMicros == nil || *fact.BillableAmountMicros != 0 {
		t.Fatalf("fact=%+v err=%v", fact, err)
	}
	wallet, err = store.GetWallet(ctx, tenant, wallet.ID)
	if err != nil || wallet.BalanceMicros != 1000 || wallet.ReservedMicros != 0 {
		t.Fatalf("wallet=%+v err=%v", wallet, err)
	}
}
