package billing

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// 7.6: an unbounded request reserves the model's observed P95 output from
// provider-metered charges instead of a flat 4096; estimated or recovered
// usage never feeds the estimate, and thin history keeps the ceiling.
func TestEstimateOutputTokensUsesProviderMeteredP95(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "p95-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 1_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Credit(ctx, tenantID, wallet.ID, "p95-credit", 1_000_000_000, "test"); err != nil {
		t.Fatal(err)
	}
	settle := func(requestID string, output int64, source string) {
		t.Helper()
		if _, _, err := store.ReservePricedWithUsageForGroup(ctx, tenantID, wallet.ID, requestID, 10, 4096, price, DefaultCustomerGroup, ratioScale); err != nil {
			t.Fatalf("reserve %s: %v", requestID, err)
		}
		if _, _, err := store.SettleCharge(ctx, tenantID, requestID, price, Usage{PromptTokens: 10, OutputTokens: output},
			[]byte(fmt.Sprintf(`{"usage_source":%q}`, source)), nil); err != nil {
			t.Fatalf("settle %s: %v", requestID, err)
		}
	}

	if got, source, err := store.EstimateOutputTokens(ctx, tenantID, "p95-model"); err != nil || got != DefaultOutputTokenCeiling || source != OutputEstimateCeiling {
		t.Fatalf("no history estimate=%d source=%s err=%v", got, source, err)
	}
	// 19 metered samples: still below the minimum, ceiling kept.
	for i := 1; i <= 19; i++ {
		settle(fmt.Sprintf("p95-%d-%s", i, tenantID), int64(i*10), "upstream")
	}
	if got, source, _ := store.EstimateOutputTokens(ctx, tenantID, "p95-model"); got != DefaultOutputTokenCeiling || source != OutputEstimateCeiling {
		t.Fatalf("thin history estimate=%d source=%s", got, source)
	}
	settle("p95-20-"+tenantID, 200, "upstream")
	// Estimated and recovered charges are excluded even when larger.
	for i := 0; i < 10; i++ {
		settle(fmt.Sprintf("p95-est-%d-%s", i, tenantID), 4000, "estimated_reservation")
		settle(fmt.Sprintf("p95-rec-%d-%s", i, tenantID), 4000, "recovered_request_log")
	}
	got, source, err := store.EstimateOutputTokens(ctx, tenantID, "p95-model")
	if err != nil {
		t.Fatal(err)
	}
	// Outputs 10..200: percentile_disc(0.95) over 20 samples is the 19th, 190.
	if got != 190 || source != OutputEstimateHistoryP95 {
		t.Fatalf("P95 estimate=%d source=%s want 190/%s", got, source, OutputEstimateHistoryP95)
	}
	if got, source, _ := store.EstimateOutputTokens(ctx, tenantID, "other-model"); got != DefaultOutputTokenCeiling || source != OutputEstimateCeiling {
		t.Fatalf("other model estimate=%d source=%s", got, source)
	}
}
