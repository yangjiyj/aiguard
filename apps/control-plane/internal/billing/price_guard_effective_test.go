package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

// 价格表只追加：管理接口不得补录更早生效的版本（会改写已经计费的那段历史）。

func TestSaveModelPriceRejectsEffectiveTimeInThePast(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	pgSeed(t, store, tenantID, "past-model", pgFull())

	past := pgSubmit(tenantID, "past-model", DirectPrice{InputPerMillionMicros: 1, OutputPerMillionMicros: 1})
	past.EffectiveAt = time.Now().UTC().Add(-2 * time.Hour)
	if _, err := store.SaveModelPrice(ctx, past, SavePriceOptions{}); !errors.Is(err, ErrPriceEffectiveInPast) {
		t.Fatalf("a backdated price must be refused, err=%v", err)
	}
	if got := pgVersionCount(t, store, tenantID, "past-model"); got != 1 {
		t.Fatalf("a refused backdated price must not add a version, versions=%d", got)
	}
}

func TestSaveModelPriceAllowsNowAndFutureAndSmallClockSkew(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	for i, offset := range []time.Duration{0, -30 * time.Second, 2 * time.Hour} {
		next := pgSubmit(tenantID, "skew-model", DirectPrice{InputPerMillionMicros: Micros(i+1) * 1_000_000, OutputPerMillionMicros: 2_000_000})
		next.EffectiveAt = time.Now().UTC().Add(offset)
		if _, err := store.SaveModelPrice(ctx, next, SavePriceOptions{}); err != nil {
			t.Fatalf("offset %s must be accepted: %v", offset, err)
		}
	}
	// 没给生效时间 = 现在，不受影响。
	none := pgSubmit(tenantID, "skew-model", DirectPrice{InputPerMillionMicros: 9_000_000, OutputPerMillionMicros: 9_000_000})
	none.EffectiveAt = time.Time{}
	if _, err := store.SaveModelPrice(ctx, none, SavePriceOptions{}); err != nil {
		t.Fatalf("an omitted effective_at means now: %v", err)
	}
}

func TestCreateModelPriceKeepsLegacyBackdatingForSeedsAndFixtures(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	// CreateModelPrice 是内部种子/测试夹具入口，保持原语义（现有大量测试依赖它写过去时间）。
	if _, err := store.CreateModelPrice(context.Background(), NewModelPrice{
		TenantID: tenantID, ModelName: "legacy-seed", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY", Status: PriceStatusActive,
		DirectPrice: DirectPrice{InputPerMillionMicros: 1, OutputPerMillionMicros: 1},
		EffectiveAt: time.Now().UTC().Add(-24 * time.Hour), CreatedBy: "seed",
	}); err != nil {
		t.Fatalf("CreateModelPrice must keep accepting past effective times: %v", err)
	}
}
