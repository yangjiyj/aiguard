package billing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/billingmedia"
)

func TestImageMeteringQuoteFreezesMatrixGroupTariffAndCost(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	createPrice := func(matrix *ImagePricing, effective time.Time) *ModelPrice {
		t.Helper()
		p, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "quoted-image", Currency: "CNY", PricingMode: PricingModeDirect, EffectiveAt: effective, Extensions: PriceExtensions{ImagePricing: matrix}})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	price := createPrice(imageMatrix(), at.Add(-time.Hour))
	group, err := store.CreateCustomerGroup(ctx, NewCustomerGroup{TenantID: tenant, Code: "image-contract", Name: "image-contract", RatioPPM: 800_000, CreatedBy: user})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AssignCustomerGroup(ctx, tenant, user, group.Code, user); err != nil {
		t.Fatal(err)
	}
	publish := func(ratio int64) {
		t.Helper()
		plan, err := store.CreateTariffPlan(ctx, NewTariffPlan{TenantID: tenant, Name: "image-band", Timezone: "Asia/Shanghai", EffectiveAt: at.Add(-time.Hour), CreatedBy: user, Rules: []TariffRule{{Code: "all-day", Name: "image-band", ModelName: "quoted-image", Band: TariffBandFlat, Weekdays: []int16{1, 2, 3, 4, 5, 6, 7}, StartMinute: 0, EndMinute: 1440, MultiplierPPM: ratio}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishTariffPlan(ctx, tenant, plan.ID); err != nil {
			t.Fatal(err)
		}
	}
	publish(500_000)
	tariff, err := store.ResolveTariffQuoteForModel(ctx, tenant, "quoted-image", at)
	if err != nil || tariff.MultiplierPPM != 500_000 {
		t.Fatalf("fixture quote does not match image model: %+v %v", tariff, err)
	}
	provider, model := "matrix-provider-"+user, "matrix-model-"+user
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,'matrix','openai')`, provider, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name) VALUES($1,$2,'quoted-image')`, model, provider); err != nil {
		t.Fatal(err)
	}
	rate := UpstreamRate{ProviderID: provider, ModelName: "quoted-image", Currency: "CNY", Extensions: PriceExtensions{ImagePricing: &ImagePricing{Mode: "per_image", Variants: []ImageVariantPrice{{Size: "1024x1024", Quality: "hd", PricePerImageMicros: 10_001}, {Size: "1792x1024", Quality: "hd", PricePerImageMicros: 20_007}}}}}
	if err := store.SaveUpstreamRate(ctx, tenant, rate); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,user_id,provider_id,model_id,endpoint_type,request_status,created_at) VALUES($1,'matrix-quoted',$2,$3,$4,$5,'images','success',NOW())`, "matrix-log-"+user, tenant, user, provider, model); err != nil {
		t.Fatal(err)
	}
	// Publish changed pricing, group and tariff before the admitted call returns.
	newMatrix := imageMatrix()
	newMatrix.Variants[1].PricePerImageMicros = 900_000
	createPrice(newMatrix, at.Add(-time.Second))
	if _, err := store.UpdateCustomerGroup(ctx, tenant, group.ID, CustomerGroupUpdate{Name: group.Name, Status: CustomerGroupActive, RatioPPM: 900_000}); err != nil {
		t.Fatal(err)
	}
	publish(700_000)
	input := MeteringInput{TenantID: tenant, UserID: user, RequestID: "matrix-quoted", ModelName: "quoted-image", RequestStatus: "success", AdmittedAt: at,
		QuotePriceID: price.ID, QuoteGroupRatioPPM: &group.RatioPPM, QuoteTariff: &tariff, RawUsage: []byte(`{"provider_sequence":9007199254740993}`),
		Usage: Usage{PromptTokens: 100, OutputTokens: 200, UsageExtensions: UsageExtensions{ImageRequest: true, ImageCount: 2, ImageVariants: []billingmedia.ImageVariantUsage{{Size: "1024x1024", Quality: "hd", Count: 1}, {Size: "1792x1024", Quality: "hd", Count: 1}}}}}
	fact, err := store.RecordMeteringUsage(ctx, input)
	// Each rate is ceil(original *.8 *.5): 32,002 + 48,003.
	if err != nil || fact.BillableAmountMicros == nil || *fact.BillableAmountMicros != 80_005 {
		t.Fatalf("settlement did not use quote snapshot: %+v %v", fact, err)
	}
	var priceID, rawSequence string
	var multiplier, cost int64
	if err := db.QueryRow(ctx, `SELECT price_id,tariff_multiplier_ppm,upstream_cost_micros,raw_usage_json->>'provider_sequence' FROM billing_usage_facts WHERE id=$1`, fact.ID).Scan(&priceID, &multiplier, &cost, &rawSequence); err != nil || priceID != price.ID || multiplier != 500_000 || cost != 30_008 || rawSequence != "9007199254740993" {
		t.Fatalf("frozen price/tariff/cost/evidence=%s/%d/%d/%s %v", priceID, multiplier, cost, rawSequence, err)
	}
	rate.Extensions.ImagePricing.Variants[0].PricePerImageMicros = 999_999
	if err := store.SaveUpstreamRate(ctx, tenant, rate); err != nil {
		t.Fatal(err)
	}
	replay, err := store.RecordMeteringUsage(ctx, input)
	if err != nil || replay.ID != fact.ID || *replay.BillableAmountMicros != 80_005 {
		t.Fatalf("quoted replay changed: %+v %v", replay, err)
	}
	if err := db.QueryRow(ctx, `SELECT upstream_cost_micros FROM billing_usage_facts WHERE id=$1`, fact.ID).Scan(&cost); err != nil || cost != 30_008 {
		t.Fatalf("replay recalculated old procurement cost: %d %v", cost, err)
	}
	changed := input
	changed.QuoteGroupRatioPPM = new(int64)
	*changed.QuoteGroupRatioPPM = 900_000
	if _, err := store.RecordMeteringUsage(ctx, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed quote evidence replayed: %v", err)
	}
	var facts, charges, ledger int
	if err := db.QueryRow(ctx, `SELECT (SELECT COUNT(*) FROM billing_usage_facts WHERE tenant_id=$1 AND request_id='matrix-quoted'),(SELECT COUNT(*) FROM billing_charge_records WHERE tenant_id=$1),(SELECT COUNT(*) FROM billing_ledger_entries WHERE tenant_id=$1)`, tenant).Scan(&facts, &charges, &ledger); err != nil || facts != 1 || charges != 0 || ledger != 0 {
		t.Fatalf("metering duplicated/debited: %d/%d/%d %v", facts, charges, ledger, err)
	}
}

func TestImageQuoteRejectsForeignModelAndInvalidMultipliers(t *testing.T) {
	store, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "bound-image", Currency: "CNY", PricingMode: PricingModeDirect, Extensions: PriceExtensions{ImagePricing: imageMatrix()}})
	if err != nil {
		t.Fatal(err)
	}
	input := MeteringInput{TenantID: tenant, UserID: user, RequestID: "foreign-quote", ModelName: "bound-image", QuotePriceID: price.ID, RequestStatus: "success", Usage: Usage{UsageExtensions: UsageExtensions{ImageRequest: true, ImageCount: 1}}}
	bad := input
	bad.ModelName = "other-model"
	if _, err := store.RecordMeteringUsage(ctx, bad); !errors.Is(err, ErrInvalidPrice) {
		t.Fatalf("cross-model quote accepted: %v", err)
	}
	_, _, other, otherUser := setupBillingStoreTest(t)
	bad = input
	bad.TenantID, bad.UserID = other, otherUser
	if _, err := store.RecordMeteringUsage(ctx, bad); !errors.Is(err, ErrInvalidPrice) {
		t.Fatalf("cross-tenant quote accepted: %v", err)
	}
	for _, ratio := range []int64{0, -1, MaxCustomerGroupRatioPPM + 1} {
		bad = input
		bad.QuoteGroupRatioPPM = &ratio
		if _, err := store.RecordMeteringUsage(ctx, bad); !errors.Is(err, ErrInvalidPrice) {
			t.Fatalf("invalid quote group multiplier accepted: %d %v", ratio, err)
		}
		bad = input
		bad.QuoteTariff = &TariffQuote{MultiplierPPM: ratio}
		if _, err := store.RecordMeteringUsage(ctx, bad); !errors.Is(err, ErrInvalidPrice) {
			t.Fatalf("invalid quote tariff multiplier accepted: %d %v", ratio, err)
		}
	}
}

func TestImagePrepaidQuoteFreezesMatrixAndActualSpecifications(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	price, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "prepaid-matrix", Currency: "CNY", PricingMode: PricingModeDirect, Extensions: PriceExtensions{ImagePricing: imageMatrix()}})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Credit(ctx, tenant, wallet.ID, "matrix-credit", 1_000_000, "test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReservePricedWithUsageForGroup(ctx, tenant, wallet.ID, "prepaid-matrix", 200_005, 300, price, DefaultCustomerGroup, ratioScale); err != nil {
		t.Fatal(err)
	}
	newMatrix := imageMatrix()
	newMatrix.Variants[1].PricePerImageMicros = 999_999
	if _, err := store.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "prepaid-matrix", Currency: "CNY", PricingMode: PricingModeDirect, Extensions: PriceExtensions{ImagePricing: newMatrix}}); err != nil {
		t.Fatal(err)
	}
	frozen, err := store.GetModelPriceByID(ctx, tenant, price.ID)
	if err != nil {
		t.Fatal(err)
	}
	usage := Usage{PromptTokens: 100, OutputTokens: 200, UsageExtensions: UsageExtensions{ImageRequest: true, ImageCount: 2, ImageVariants: []billingmedia.ImageVariantUsage{{Size: "1024x1024", Quality: "hd", Count: 1}, {Size: "1792x1024", Quality: "hd", Count: 1}}}}
	first, after, err := store.SettleCharge(ctx, tenant, "prepaid-matrix", frozen, usage, []byte(`{}`), nil)
	if err != nil || first.AmountMicros != 200_010 || after.BalanceMicros != 799_990 || after.ReservedMicros != 0 {
		t.Fatalf("actual matrix charge: %+v %+v %v", first, after, err)
	}
	replay, again, err := store.SettleCharge(ctx, tenant, "prepaid-matrix", frozen, usage, []byte(`{}`), nil)
	if err != nil || replay.ID != first.ID || again.BalanceMicros != after.BalanceMicros {
		t.Fatalf("prepaid replay charged twice: %+v %v", replay, err)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_charge_records WHERE tenant_id=$1 AND request_id='prepaid-matrix'`, tenant).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate charges: %d %v", count, err)
	}
}
