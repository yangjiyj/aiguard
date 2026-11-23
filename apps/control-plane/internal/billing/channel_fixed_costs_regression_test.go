package billing

import (
	"context"
	"testing"
	"time"
)

func TestChannelFixedCostUpdateReturnsOriginalCreator(t *testing.T) {
	store, db, tenant, creator := setupBillingStoreTest(t)
	ctx := context.Background()
	provider, editor := "creator_"+tenant, "editor_"+tenant
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,$1,'openai')`, provider, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,email,password_hash,role,status) VALUES($1,$2,$1,$3,'x','developer','active')`, editor, tenant, editor+"@test.invalid"); err != nil {
		t.Fatal(err)
	}
	first, err := store.SaveChannelFixedCost(ctx, tenant, ChannelFixedCost{ProviderID: provider, Currency: "CNY", AmountMicros: 100, Period: "month", EffectiveFrom: "2024-01-01", CreatedBy: creator})
	if err != nil {
		t.Fatal(err)
	}
	update := *first
	update.CreatedBy, update.Note, update.AmountMicros = editor, "updated", 200
	second, err := store.SaveChannelFixedCost(ctx, tenant, update)
	if err != nil {
		t.Fatal(err)
	}
	var storedCreator, storedNote string
	var storedAmount int64
	if err := db.QueryRow(ctx, `SELECT created_by,note,amount_micros FROM billing_channel_fixed_costs WHERE id=$1`, first.ID).Scan(&storedCreator, &storedNote, &storedAmount); err != nil {
		t.Fatal(err)
	}
	if second.CreatedBy != creator || storedCreator != creator || !second.CreatedAt.Equal(first.CreatedAt) || second.AmountMicros != 200 || storedAmount != 200 || second.Note != "updated" || storedNote != "updated" || !second.UpdatedAt.After(first.UpdatedAt) {
		t.Fatalf("update=%+v storedCreator=%s storedAmount=%d storedNote=%s", second, storedCreator, storedAmount, storedNote)
	}
}

func TestChannelFixedCostHistoricalCurrenciesAreNeverAddedTogether(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	provider := "currencies_" + tenant
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,$1,'openai')`, provider, tenant); err != nil {
		t.Fatal(err)
	}
	to := "2024-03-01"
	if _, err := db.Exec(ctx, `INSERT INTO billing_channel_fixed_costs(id,tenant_id,provider_id,currency,amount_micros,period,effective_from,effective_to) VALUES($1,$2,$3,'CNY',29000000,'month','2024-02-01',$4)`, tenant+"-legacy-cny", tenant, provider, to); err != nil {
		t.Fatal(err)
	}
	// Historical cost segments can retain the old denomination after prices change.
	if _, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "currency-model", PricingMode: PricingModeDirect, Currency: "USD", DirectPrice: DirectPrice{InputPerMillionMicros: 1}, Status: PriceStatusActive, EffectiveAt: time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveChannelFixedCost(ctx, tenant, ChannelFixedCost{ProviderID: provider, Currency: "USD", AmountMicros: 31_000_000, Period: "month", EffectiveFrom: to}); err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation("Asia/Shanghai")
	start, end := time.Date(2024, 2, 28, 0, 0, 0, 0, loc), time.Date(2024, 3, 2, 0, 0, 0, 0, loc)
	for _, fact := range []struct {
		currency     string
		at           time.Time
		billed, cost int64
	}{
		{"CNY", start, 3_000_000, 100_000}, {"USD", end.Add(-time.Hour), 2_000_000, 200_000},
	} {
		id := tenant + "-" + fact.currency
		if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,user_id,provider_id,provider_name,model_name,billable_amount_micros,upstream_cost_micros,currency,status,usage_source,occurred_at,admitted_at) VALUES($1,$2,$1,$3,$4,$4,'currency-model',$5,$6,$7,'settled','gateway',$8,$8)`, id, tenant, user, provider, fact.billed, fact.cost, fact.currency, fact.at); err != nil {
			t.Fatal(err)
		}
	}
	groups, err := store.ChannelMargins(ctx, tenant, start, end)
	if err != nil || len(groups) != 1 || len(groups[0].Channels) != 2 {
		t.Fatalf("groups=%+v err=%v", groups, err)
	}
	wants := map[string]int64{"CNY": 2_000_000, "USD": 1_000_000}
	seen := map[string]bool{}
	for _, channel := range groups[0].Channels {
		if seen[channel.Currency] || channel.FixedCostMicros != wants[channel.Currency] || channel.CostMicros != channel.VariableCostMicros+channel.FixedCostMicros {
			t.Fatalf("currency cost mixed: %+v", channel)
		}
		seen[channel.Currency] = true
		if channel.Currency == "CNY" && (!channel.CurrencyMismatch || channel.CurrencyWarning == "" || channel.MarginMicros != nil) {
			t.Fatalf("legacy mismatch not reported: %+v", channel)
		}
	}
	if !seen["CNY"] || !seen["USD"] {
		t.Fatalf("currencies=%+v", seen)
	}
	// Idle channels also retain one fixed-cost row per currency.
	fixed, err := store.ListChannelFixedCosts(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	groups = BuildChannelMargins(nil, nil, ChannelMarginWindow{FixedCosts: fixed, Start: start, End: end, Location: loc, Currency: "USD"})
	if len(groups) != 1 || groups[0].ModelName != "" || len(groups[0].Channels) != 2 {
		t.Fatalf("idle groups=%+v", groups)
	}
	for _, channel := range groups[0].Channels {
		if channel.FixedCostMicros != wants[channel.Currency] {
			t.Fatalf("idle currency cost mixed: %+v", channel)
		}
	}
}
