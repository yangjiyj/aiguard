package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExtendedPriceAndMeteringUsageRoundTripRemainIdempotent(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "extended-image", Currency: "CNY", PricingMode: PricingModeDirect, EffectiveAt: at.Add(-time.Minute), Extensions: PriceExtensions{ImagePerImageMicros: 50000, RequestPerCallMicros: 10000, ToolPricesPerThousandMicros: map[string]Micros{"web_search": 10000000}}})
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := store.GetModelPriceByID(ctx, tenant, price.ID)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := persisted.AsDirectPrice()
	if err != nil || direct.Extensions.ImagePerImageMicros != 50000 || direct.Extensions.ToolPricesPerThousandMicros["web_search"] != 10000000 {
		t.Fatalf("price extras did not roundtrip: %+v %v", direct, err)
	}
	input := MeteringInput{TenantID: tenant, UserID: user, RequestID: "extended-usage", ModelName: "extended-image", RequestStatus: "success", AdmittedAt: at, Usage: Usage{UsageExtensions: UsageExtensions{ImageCount: 2, ToolCalls: map[string]int64{"web_search": 2}}}}
	first, err := store.RecordMeteringUsage(ctx, input)
	if err != nil || first.BillableAmountMicros == nil || *first.BillableAmountMicros != 130000 {
		t.Fatalf("first metering fact: %+v %v", first, err)
	}
	replay, err := store.RecordMeteringUsage(ctx, input)
	if err != nil || replay.ID != first.ID {
		t.Fatalf("same measurement replay: %+v %v", replay, err)
	}
	changed := input
	changed.Usage.UsageExtensions = UsageExtensions{ImageCount: 3, ToolCalls: map[string]int64{"web_search": 2}}
	if _, err := store.RecordMeteringUsage(ctx, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed image evidence accepted: %v", err)
	}
	var images, calls int64
	if err := db.QueryRow(ctx, `SELECT (usage_extras->>'image_count')::bigint,(usage_extras->'tool_calls'->>'web_search')::bigint FROM billing_usage_facts WHERE tenant_id=$1 AND request_id=$2`, tenant, input.RequestID).Scan(&images, &calls); err != nil || images != 2 || calls != 2 {
		t.Fatalf("durable usage extras: %d %d %v", images, calls, err)
	}
}

func TestExtendedPrepaidSettlementFreezesPriceAndMeasuredQuantity(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Credit(ctx, tenant, wallet.ID, "extended-credit", 1000000, "test"); err != nil {
		t.Fatal(err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "fixed-image", Currency: "CNY", PricingMode: PricingModeDirect, Extensions: PriceExtensions{RequestPerCallMicros: 40000, NewAPIFixedQuantity: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Reserve(ctx, tenant, wallet.ID, "extended-prepaid", 200000); err != nil {
		t.Fatal(err)
	}
	usage := Usage{UsageExtensions: UsageExtensions{ImageCount: 3}}
	first, _, err := store.SettleCharge(ctx, tenant, "extended-prepaid", price, usage, []byte(`{"source":"test"}`), nil)
	if err != nil || first.AmountMicros != 120000 {
		t.Fatalf("settlement: %+v %v", first, err)
	}
	replay, _, err := store.SettleCharge(ctx, tenant, "extended-prepaid", price, usage, []byte(`{"source":"test"}`), nil)
	if err != nil || replay.ID != first.ID || replay.UsageExtras.ImageCount != 3 || !replay.PricingExtras.NewAPIFixedQuantity {
		t.Fatalf("frozen settlement replay: %+v %v", replay, err)
	}
	var amount int64
	if err := db.QueryRow(ctx, `SELECT billable_amount_micros FROM billing_usage_facts WHERE tenant_id=$1 AND request_id='extended-prepaid'`, tenant).Scan(&amount); err != nil || amount != 120000 {
		t.Fatalf("prepaid fact: %d %v", amount, err)
	}
}
