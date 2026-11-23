package billing

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestUpstreamCostPrepaidSnapshotsIncludeExtrasAndSurviveRateEdits(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	provider := "cost-provider-" + user
	modelID := "cost-model-" + user
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,'成本渠道','openai')`, provider, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name) VALUES($1,$2,'cost-model')`, modelID, provider); err != nil {
		t.Fatal(err)
	}
	reasoning := Micros(40_000_000)
	rate := UpstreamRate{ProviderID: provider, ModelName: "cost-model", Currency: "CNY", InputMicros: 10_000_000, CachedMicros: 2_000_000, CacheWriteMicros: 20_000_000, OutputMicros: 30_000_000,
		Extensions: PriceExtensions{ImagePerImageMicros: 2_000_000, ReasoningPerMillionMicros: &reasoning, ToolPricesPerThousandMicros: map[string]Micros{"web_search": 50_000_000}}}
	if err := store.SaveUpstreamRate(ctx, tenant, rate); err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Credit(ctx, tenant, wallet.ID, "cost-credit", 100_000_000, "admin"); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "cost-model", CustomerGroup: DefaultCustomerGroup, PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 1_000_000}, EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	usage := Usage{PromptTokens: 1_000_000, CachedInputTokens: 200_000, CacheWriteInputTokens: 100_000, OutputTokens: 500_000, ReasoningTokens: 100_000, UsageExtensions: UsageExtensions{ImageCount: 2, ToolCalls: map[string]int64{"web_search": 4}}}
	settle := func(request string) *ChargeRecord {
		t.Helper()
		if _, _, err := store.ReservePricedWithUsageForGroup(ctx, tenant, wallet.ID, request, 5_000_000, 1_500_000, price, DefaultCustomerGroup, ratioScale); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,user_id,provider_id,model_id,endpoint_type,request_status,created_at) VALUES($1,$2,$3,$4,$5,$6,'chat_completion','success',NOW())`, request+"-"+user, request, tenant, user, provider, modelID); err != nil {
			t.Fatal(err)
		}
		charge, _, err := store.SettleCharge(ctx, tenant, request, price, usage, []byte(`{}`), nil)
		if err != nil {
			t.Fatal(err)
		}
		return charge
	}
	first := settle("upstream-first")
	const firstCost = Micros(29_600_000) // input 7 + cache .4 + write 2 + output 12 + reasoning 4 + images 4 + tools .2
	if first.UpstreamCostMicros == nil || *first.UpstreamCostMicros != firstCost {
		t.Fatalf("cost breakdown=%v, want %d", first.UpstreamCostMicros, firstCost)
	}
	var chargeCost, factCost *int64
	if err := db.QueryRow(ctx, `SELECT c.upstream_cost_micros,f.upstream_cost_micros FROM billing_charge_records c JOIN billing_usage_facts f ON f.tenant_id=c.tenant_id AND f.request_id=c.request_id WHERE c.tenant_id=$1 AND c.request_id='upstream-first'`, tenant).Scan(&chargeCost, &factCost); err != nil {
		t.Fatal(err)
	}
	if chargeCost == nil || factCost == nil || *chargeCost != int64(firstCost) || *factCost != *chargeCost {
		t.Fatalf("charge/fact cost snapshots=%v / %v", chargeCost, factCost)
	}
	// A retried gateway finalize provides no explicit cost. It must return
	// the original charge without charging the employee wallet a second time.
	repeated, replayWallet, err := store.SettleCharge(ctx, tenant, "upstream-first", price, usage, []byte(`{}`), nil)
	if err != nil || repeated.ID != first.ID || repeated.UpstreamCostMicros == nil || *repeated.UpstreamCostMicros != firstCost {
		t.Fatalf("same finalize was not idempotent: %#v, err=%v", repeated, err)
	}
	if replayWallet.BalanceMicros != 100_000_000-first.AmountMicros || replayWallet.ReservedMicros != 0 {
		t.Fatalf("repeat finalize changed wallet: %#v", replayWallet)
	}
	var chargeCount, factCount int
	if err := db.QueryRow(ctx, `SELECT (SELECT COUNT(*) FROM billing_charge_records WHERE tenant_id=$1 AND request_id='upstream-first'),(SELECT COUNT(*) FROM billing_usage_facts WHERE tenant_id=$1 AND request_id='upstream-first')`, tenant).Scan(&chargeCount, &factCount); err != nil || chargeCount != 1 || factCount != 1 {
		t.Fatalf("repeat finalize duplicated charge/fact: %d/%d, err=%v", chargeCount, factCount, err)
	}
	explicitDifferentCost := firstCost + 1
	if _, _, err := store.SettleCharge(ctx, tenant, "upstream-first", price, usage, []byte(`{}`), &explicitDifferentCost); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("explicit changed cost must conflict: %v", err)
	}
	rate.InputMicros = 20_000_000
	if err := store.SaveUpstreamRate(ctx, tenant, rate); err != nil {
		t.Fatal(err)
	}
	second := settle("upstream-second")
	if second.UpstreamCostMicros == nil || *second.UpstreamCostMicros != 36_600_000 {
		t.Fatalf("new request did not use updated procurement cost: %v", second.UpstreamCostMicros)
	}
	replay, _, err := store.SettleCharge(ctx, tenant, "upstream-first", price, usage, []byte(`{}`), nil)
	if err != nil || replay.UpstreamCostMicros == nil || *replay.UpstreamCostMicros != firstCost {
		t.Fatalf("historical replay cost changed: %#v, err=%v", replay, err)
	}
	if err := db.QueryRow(ctx, `SELECT upstream_cost_micros FROM billing_usage_facts WHERE tenant_id=$1 AND request_id='upstream-first'`, tenant).Scan(&factCost); err != nil || factCost == nil || *factCost != int64(firstCost) {
		t.Fatalf("historical exported fact changed: %v, err=%v", factCost, err)
	}
}

func TestUpstreamCostUnknownCurrencyAndTenantRemainNull(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	provider := "null-cost-" + user
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,'unknown-cost','openai')`, provider, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name) VALUES($1,$2,'cost-null')`, "null-model-"+user, provider); err != nil {
		t.Fatal(err)
	}
	compute := func(scope, currency string) *Micros {
		t.Helper()
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		cost, err := ComputeUpstreamCost(ctx, tx, scope, provider, "", "cost-null", currency, Usage{PromptTokens: 1000})
		if err != nil {
			t.Fatal(err)
		}
		return cost
	}
	if cost := compute(tenant, "CNY"); cost != nil {
		t.Fatalf("missing cost must be unknown, got %v", cost)
	}
	rate := UpstreamRate{ProviderID: provider, ModelName: "cost-null", Currency: "USD", InputMicros: 1_000_000}
	if err := store.SaveUpstreamRate(ctx, tenant, rate); !errors.Is(err, ErrAllowanceCurrency) {
		t.Fatalf("currency mismatch save=%v", err)
	}
	// Simulate pre-upgrade mismatched rates; existing history must not convert.
	blob, err := json.Marshal(rate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO billing_upstream_rates(tenant_id,provider_id,model_name,currency,price_json) VALUES($1,$2,$3,$4,$5)`, tenant, provider, rate.ModelName, rate.Currency, blob); err != nil {
		t.Fatal(err)
	}
	if cost := compute(tenant, "CNY"); cost != nil {
		t.Fatalf("different currency must not convert, got %v", cost)
	}
	if cost := compute(tenant+"_foreign", "USD"); cost != nil {
		t.Fatalf("foreign tenant inherited cost %v", cost)
	}
	if err := store.SaveUpstreamRate(ctx, tenant+"_foreign", rate); !errors.Is(err, ErrInvalidPrice) {
		t.Fatalf("cross-tenant cost update=%v", err)
	}
	rate.Currency = "CNY"
	rate.InputMicros = 0
	if err := store.SaveUpstreamRate(ctx, tenant, rate); err != nil {
		t.Fatal(err)
	}
	if cost := compute(tenant, "CNY"); cost == nil || *cost != 0 {
		t.Fatalf("explicit free rate must be known zero, got %v", cost)
	}
}
