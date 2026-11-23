package billing

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestStoreCreatesOneVersionedBasePriceForEveryCustomerGroup(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	first, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "billing-model-a", CustomerGroup: "default",
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 4_000_000},
		EffectiveAt: now.Add(-time.Hour), Status: PriceStatusActive, CreatedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("create first price: %v", err)
	}
	second, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "billing-model-a", CustomerGroup: "default",
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 2_000_000, OutputPerMillionMicros: 8_000_000},
		EffectiveAt: now.Add(time.Hour), Status: PriceStatusActive, CreatedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("create second price: %v", err)
	}
	if first.Version != 1 || second.Version != 2 {
		t.Fatalf("price versions = %d/%d, want 1/2", first.Version, second.Version)
	}

	resolved, err := store.ResolveModelPrice(ctx, tenantID, "billing-model-a", "vip", now)
	if err != nil {
		t.Fatalf("resolve fallback price: %v", err)
	}
	if resolved.ID != first.ID {
		t.Fatalf("resolved fallback price = %s, want %s", resolved.ID, first.ID)
	}
	resolved, err = store.ResolveModelPrice(ctx, tenantID, "billing-model-a", "vip", now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("resolve future price: %v", err)
	}
	if resolved.ID != second.ID {
		t.Fatalf("resolved future price = %s, want %s", resolved.ID, second.ID)
	}
	if _, err := store.CreateCustomerGroup(ctx, NewCustomerGroup{
		TenantID: tenantID, Code: "vip", Name: "VIP customers", RatioPPM: 800_000, CreatedBy: "admin-a",
	}); err != nil {
		t.Fatalf("create vip customer group: %v", err)
	}

	vip, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "billing-model-a", CustomerGroup: "vip",
		PricingMode: PricingModeNewAPIRatio, Currency: "CNY",
		RatioPrice: RatioPrice{
			BaseInputPerMillionMicros: 2_000_000,
			ModelRatioPPM:             1_500_000, CompletionRatioPPM: 2_000_000, GroupRatioPPM: 800_000,
			HasCachedInputRatio: true, CachedInputRatioPPM: 250_000,
		},
		EffectiveAt: now.Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("create global ratio price: %v", err)
	}
	if vip.CustomerGroup != DefaultCustomerGroup || vip.RatioPrice.GroupRatioPPM != ratioScale || vip.Version != 3 {
		t.Fatalf("global ratio price = %#v", vip)
	}
	resolved, err = store.ResolveModelPrice(ctx, tenantID, "billing-model-a", "vip", now)
	if err != nil {
		t.Fatalf("resolve vip price: %v", err)
	}
	if resolved.ID != vip.ID {
		t.Fatalf("resolved vip price = %s, want %s", resolved.ID, vip.ID)
	}
	normalized, err := resolved.AsDirectPrice()
	if err != nil {
		t.Fatalf("normalize resolved vip price: %v", err)
	}
	if normalized.InputPerMillionMicros != 3_000_000 || normalized.OutputPerMillionMicros != 6_000_000 || normalized.CachedInputPerMillionMicros != 750_000 {
		t.Fatalf("normalized global base price: %#v", normalized)
	}
	effective, err := ApplyCustomerGroupRatio(normalized, 800_000)
	if err != nil {
		t.Fatalf("apply vip customer-group ratio: %v", err)
	}
	if effective.InputPerMillionMicros != 2_400_000 || effective.OutputPerMillionMicros != 4_800_000 || effective.CachedInputPerMillionMicros != 600_000 {
		t.Fatalf("effective vip price: %#v", effective)
	}
}

func TestStoreZeroPriceUsageDoesNotRequireWalletBalance(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "zero-price-model", CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("create zero price: %v", err)
	}
	if _, err = store.SetCustomerLimits(ctx, tenantID, userID, CustomerLimits{DailyTokenLimit: 1_000}); err != nil {
		t.Fatalf("set token limit: %v", err)
	}

	const reservedTokens int64 = 100
	reservation, wallet, err := store.ReservePricedWithUsageForGroup(
		ctx, tenantID, wallet.ID, "req-zero-price", 0, reservedTokens,
		price, DefaultCustomerGroup, ratioScale,
	)
	if err != nil {
		t.Fatalf("zero-price reserve with zero balance: %v", err)
	}
	if reservation.ReservedMicros != 0 || wallet.BalanceMicros != 0 || wallet.ReservedMicros != 0 {
		t.Fatalf("zero-price reservation changed wallet: reservation=%#v wallet=%#v", reservation, wallet)
	}

	usage := Usage{PromptTokens: 60, OutputTokens: 20}
	charge, wallet, err := store.SettleCharge(ctx, tenantID, "req-zero-price", price, usage, []byte(`{"provider":"test-provider"}`), nil)
	if err != nil {
		t.Fatalf("zero-price settlement: %v", err)
	}
	if charge.AmountMicros != 0 || wallet.BalanceMicros != 0 || wallet.ReservedMicros != 0 {
		t.Fatalf("zero-price settlement changed wallet: charge=%#v wallet=%#v", charge, wallet)
	}
	summary, err := store.GetCustomerLimitSummary(ctx, tenantID, userID, time.Now())
	if err != nil {
		t.Fatalf("get limit summary: %v", err)
	}
	if summary.Daily.SettledTokens != 80 || summary.Daily.ReservedTokens != 0 {
		t.Fatalf("zero-price tokens were not settled: %#v", summary.Daily)
	}
}

func TestStoreSettleChargeWritesUsageAndPriceSnapshotAtomically(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	wallet, err = store.Credit(ctx, tenantID, wallet.ID, "charge-seed", 1_000_000, "admin-a")
	if err != nil {
		t.Fatalf("credit wallet: %v", err)
	}
	if _, _, err := store.Reserve(ctx, tenantID, wallet.ID, "req-charge-1", 1_000); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "billing-model-charge", CustomerGroup: "default",
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{
			InputPerMillionMicros: 1_000_000,
			HasCachedInputPrice:   true, CachedInputPerMillionMicros: 100_000,
			OutputPerMillionMicros: 4_000_000,
		},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("create price: %v", err)
	}
	usage := Usage{PromptTokens: 100, CachedInputTokens: 20, OutputTokens: 10}
	upstream := Micros(80)
	charge, wallet, err := store.SettleCharge(ctx, tenantID, "req-charge-1", price, usage, []byte(`{"provider":"test-provider"}`), &upstream)
	if err != nil {
		t.Fatalf("settle charge: %v", err)
	}
	if charge.CustomerGroup != DefaultCustomerGroup || charge.AmountMicros != 122 || charge.CachedInputTokens != 20 ||
		charge.InputPerMillionMicros != 1_000_000 || charge.CachedInputPerMillionMicros != 100_000 {
		t.Fatalf("charge snapshot: %#v", charge)
	}
	if wallet.BalanceMicros != 999_878 || wallet.ReservedMicros != 0 {
		t.Fatalf("wallet after charge: %#v", wallet)
	}

	same, wallet, err := store.SettleCharge(ctx, tenantID, "req-charge-1", price, usage, []byte(`{"provider":"test-provider"}`), &upstream)
	if err != nil || same.ID != charge.ID || wallet.BalanceMicros != 999_878 {
		t.Fatalf("idempotent charge: charge=%#v wallet=%#v err=%v", same, wallet, err)
	}
	changedUsage := usage
	changedUsage.OutputTokens++
	if _, _, err := store.SettleCharge(ctx, tenantID, "req-charge-1", price, changedUsage, nil, &upstream); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed usage error = %v, want ErrIdempotencyConflict", err)
	}

	var chargeCount, settleLedgerCount int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_charge_records WHERE tenant_id = $1`, tenantID).Scan(&chargeCount); err != nil {
		t.Fatalf("count charges: %v", err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_ledger_entries WHERE tenant_id = $1 AND event_type = 'settle'`, tenantID).Scan(&settleLedgerCount); err != nil {
		t.Fatalf("count settlement ledger: %v", err)
	}
	if chargeCount != 1 || settleLedgerCount != 1 {
		t.Fatalf("atomic records = charges:%d settlements:%d, want 1/1", chargeCount, settleLedgerCount)
	}
	if _, err := db.Exec(ctx, `
		UPDATE billing_charge_records SET amount_micros = amount_micros + 1
		WHERE tenant_id = $1 AND request_id = 'req-charge-1'
	`, tenantID); err == nil {
		t.Fatal("immutable charge snapshot unexpectedly accepted an update")
	}
}

func TestStoreSettlesAgainstAdmissionPriceAndGroupRatioSnapshots(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenantID, userID, "CNY")
	if err != nil {
		t.Fatalf("ensure wallet: %v", err)
	}
	wallet, err = store.Credit(ctx, tenantID, wallet.ID, "quoted-credit", 1_000_000, "admin-a")
	if err != nil {
		t.Fatalf("credit wallet: %v", err)
	}
	price, err := store.CreateModelPrice(ctx, NewModelPrice{
		TenantID: tenantID, ModelName: "quoted-model", CustomerGroup: "default",
		PricingMode: PricingModeDirect, Currency: "CNY",
		DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
		EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive,
	})
	if err != nil {
		t.Fatalf("create price: %v", err)
	}
	vip, err := store.CreateCustomerGroup(ctx, NewCustomerGroup{
		TenantID: tenantID, Code: "vip", Name: "VIP", RatioPPM: 800_000,
	})
	if err != nil {
		t.Fatalf("create vip group: %v", err)
	}
	if _, _, err := store.ReservePricedWithUsageForGroup(ctx, tenantID, wallet.ID, "req-quoted", 1_000, 0, price, vip.Code, vip.RatioPPM); err != nil {
		t.Fatalf("reserve quoted: %v", err)
	}
	if _, err := store.UpdateCustomerGroup(ctx, tenantID, vip.ID, CustomerGroupUpdate{Name: vip.Name, Status: CustomerGroupActive, RatioPPM: 500_000}); err != nil {
		t.Fatalf("change current vip ratio: %v", err)
	}
	if _, err := db.Exec(ctx, `UPDATE billing_model_prices SET status = 'retired' WHERE tenant_id=$1 AND id=$2`, tenantID, price.ID); err != nil {
		t.Fatalf("retire price: %v", err)
	}
	historic, err := store.GetModelPriceByID(ctx, tenantID, price.ID)
	if err != nil || historic.Status != PriceStatusRetired {
		t.Fatalf("historic price = %#v err=%v", historic, err)
	}
	charge, _, err := store.SettleCharge(ctx, tenantID, "req-quoted", historic, Usage{PromptTokens: 10}, []byte(`{}`), nil)
	if err != nil || charge.PriceID != price.ID || charge.CustomerGroup != "vip" ||
		charge.CustomerGroupRatioPPM != 800_000 || charge.InputPerMillionMicros != 800_000 || charge.AmountMicros != 8 {
		t.Fatalf("settle historic quote: charge=%#v err=%v", charge, err)
	}
	if _, _, err := store.SettleCharge(ctx, tenantID, "req-quoted", &ModelPrice{ID: "other", TenantID: tenantID, ModelName: "quoted-model", Currency: "CNY", PricingMode: PricingModeDirect, DirectPrice: price.DirectPrice}, Usage{PromptTokens: 10}, []byte(`{}`), nil); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("mismatched quote error=%v", err)
	}
}

func TestStoreCreatesUniquePriceVersionsUnderConcurrency(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	const workers = 12
	versions := make(chan int, workers)
	errorsSeen := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			price, err := store.CreateModelPrice(ctx, NewModelPrice{
				TenantID: tenantID, ModelName: "billing-concurrent-price", CustomerGroup: "default",
				PricingMode: PricingModeDirect, Currency: "CNY",
				DirectPrice: DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000},
				EffectiveAt: time.Now().Add(-time.Minute), Status: PriceStatusActive, CreatedBy: "admin-a",
			})
			if err != nil {
				errorsSeen <- err
				return
			}
			versions <- price.Version
		}()
	}
	wg.Wait()
	close(versions)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatalf("concurrent price creation: %v", err)
	}
	seen := make(map[int]bool, workers)
	for version := range versions {
		if seen[version] {
			t.Fatalf("duplicate price version %d", version)
		}
		seen[version] = true
	}
	for version := 1; version <= workers; version++ {
		if !seen[version] {
			t.Fatalf("missing price version %d; got %v", version, seen)
		}
	}
}
