package billing

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// ListEffectiveModelPrices 供控制台取「每个模型当前生效的一版」：
// 1. 选价口径必须与计费实际使用的 ResolveModelPrice 完全一致（effective_at DESC, version DESC）；
// 2. 不受 ListModelPrices 的历史行数截断影响。

func TestListEffectiveModelPricesMatchesResolveModelPriceForBackdatedVersions(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	// v1 生效时间较晚（1 小时前），v2 是补录的更早生效时间（3 小时前）：
	// 计费按 effective_at 取最新者 = v1，而不是版本号最大的 v2。
	v1, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "backdated", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY", Status: PriceStatusActive,
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
		EffectiveAt: now.Add(-time.Hour), CreatedBy: "admin-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "backdated", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY", Status: PriceStatusActive,
		DirectPrice: DirectPrice{InputPerMillionMicros: 9_000_000, OutputPerMillionMicros: 9_000_000},
		EffectiveAt: now.Add(-3 * time.Hour), CreatedBy: "admin-a",
	}); err != nil {
		t.Fatal(err)
	}
	billed, err := store.ResolveModelPrice(ctx, tenantID, "backdated", "", now)
	if err != nil || billed.ID != v1.ID {
		t.Fatalf("precondition: billing resolves %v err=%v, want v1 %s", billed, err, v1.ID)
	}
	listed, err := store.ListEffectiveModelPrices(ctx, tenantID, 100)
	if err != nil || len(listed) != 1 {
		t.Fatalf("effective list = %#v err=%v", listed, err)
	}
	if listed[0].ID != v1.ID {
		t.Fatalf("the effective list must show the version billing actually uses (%s), got %s v%d", v1.ID, listed[0].ID, listed[0].Version)
	}
}

func TestListEffectiveModelPricesIsNotTruncatedByVersionHistory(t *testing.T) {
	store, db, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.EnsureDefaultCustomerGroup(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	// 模型 aaa 有 120 个历史版本：ListModelPrices(limit 100) 会被它占满，后面的 zzz 完全看不到。
	for version := 1; version <= 120; version++ {
		if _, err := db.Exec(ctx, `
			INSERT INTO billing_model_prices (id, tenant_id, model_name, customer_group, version, pricing_mode, currency,
				input_per_million_micros, output_per_million_micros, status, effective_at, created_by)
			VALUES ($1,$2,'aaa-many-versions','default',$3,'direct','CNY',$4,$4,'active',$5,'seed')`,
			fmt.Sprintf("price_many_%s_%d", tenantID, version), tenantID, version, int64(version)*1000, now.Add(-time.Duration(200-version)*time.Minute)); err != nil {
			t.Fatalf("seed version %d: %v", version, err)
		}
	}
	if _, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "zzz-priced", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY", Status: PriceStatusActive,
		DirectPrice: DirectPrice{InputPerMillionMicros: 3_000_000, OutputPerMillionMicros: 6_000_000},
		EffectiveAt: now.Add(-time.Hour), CreatedBy: "admin-a",
	}); err != nil {
		t.Fatal(err)
	}
	history, err := store.ListModelPrices(ctx, tenantID, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range history {
		if item.ModelName == "zzz-priced" {
			t.Fatal("precondition: the 100-row history list is expected to be full of the older model")
		}
	}
	effective, err := store.ListEffectiveModelPrices(ctx, tenantID, 100)
	if err != nil || len(effective) != 2 {
		t.Fatalf("effective list = %d rows err=%v, want 2 (one per model)", len(effective), err)
	}
	byModel := map[string]ModelPrice{}
	for _, item := range effective {
		byModel[item.ModelName] = item
	}
	if byModel["zzz-priced"].DirectPrice.InputPerMillionMicros != 3_000_000 {
		t.Fatalf("zzz-priced missing or wrong in effective list: %#v", byModel)
	}
	if byModel["aaa-many-versions"].Version != 120 {
		t.Fatalf("aaa current version = %d, want 120", byModel["aaa-many-versions"].Version)
	}
}
