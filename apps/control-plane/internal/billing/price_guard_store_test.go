package billing

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// SaveModelPrice 的数据库测试：并发幂等、确认标志、草稿与定时版本。

func pgSeed(t *testing.T, store *Store, tenantID, model string, direct DirectPrice) *ModelPrice {
	t.Helper()
	created, err := store.CreateModelPrice(context.Background(), NewModelPrice{
		TenantID: tenantID, ModelName: model, CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "USD", DirectPrice: direct,
		EffectiveAt: time.Now().UTC().Add(-time.Hour), Status: PriceStatusActive, CreatedBy: "seed-admin",
	})
	if err != nil {
		t.Fatalf("seed price: %v", err)
	}
	return created
}

func pgSubmit(tenantID, model string, direct DirectPrice) NewModelPrice {
	return NewModelPrice{
		TenantID: tenantID, ModelName: model, CustomerGroup: DefaultCustomerGroup,
		PricingMode: PricingModeDirect, Currency: "USD", DirectPrice: direct,
		EffectiveAt: time.Now().UTC(), Status: PriceStatusActive, CreatedBy: "admin-a",
	}
}

func pgVersionCount(t *testing.T, store *Store, tenantID, model string) int {
	t.Helper()
	all, err := store.ListModelPrices(context.Background(), tenantID, 500)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, item := range all {
		if item.ModelName == model {
			count++
		}
	}
	return count
}

func TestSaveModelPriceNoChangeReturnsCurrentVersionWithoutWriting(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	seed := pgSeed(t, store, tenantID, "idem-model", pgFull())

	result, err := store.SaveModelPrice(ctx, pgSubmit(tenantID, "idem-model", pgFull()), SavePriceOptions{})
	if err != nil {
		t.Fatalf("identical save: %v", err)
	}
	if !result.Unchanged || result.Price == nil || result.Price.ID != seed.ID || result.Price.Version != 1 {
		t.Fatalf("identical save must return the version in force: %#v", result)
	}
	if got := pgVersionCount(t, store, tenantID, "idem-model"); got != 1 {
		t.Fatalf("versions = %d, want 1", got)
	}
}

func TestSaveModelPriceConcurrentIdenticalSubmissionsCreateOneVersion(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	const workers = 12
	results := make(chan *SavePriceResult, workers)
	failures := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// 模型此前没有任何价格：并发提交同一份价格，只能有一个提交真正写入。
			result, err := store.SaveModelPrice(ctx, pgSubmit(tenantID, "race-model", pgFull()), SavePriceOptions{})
			if err != nil {
				failures <- err
				return
			}
			results <- result
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatalf("concurrent save: %v", err)
	}
	created, unchanged := 0, 0
	for result := range results {
		if result.Unchanged {
			unchanged++
		} else {
			created++
		}
	}
	if created != 1 || unchanged != workers-1 {
		t.Fatalf("created=%d unchanged=%d, want 1/%d", created, unchanged, workers-1)
	}
	if got := pgVersionCount(t, store, tenantID, "race-model"); got != 1 {
		t.Fatalf("versions = %d, want exactly 1", got)
	}
}

func TestSaveModelPriceRequiresConfirmationBeforeZeroing(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	seed := pgSeed(t, store, tenantID, "zero-model", pgFull())

	_, err := store.SaveModelPrice(ctx, pgSubmit(tenantID, "zero-model", DirectPrice{}), SavePriceOptions{})
	var zeroErr *ZeroPriceError
	if !errors.As(err, &zeroErr) || !errors.Is(err, ErrZeroPriceNotConfirmed) {
		t.Fatalf("zeroing without confirmation error = %v, want *ZeroPriceError", err)
	}
	if zeroErr.Previous.ID != seed.ID || zeroErr.Attempted.DirectPrice.InputPerMillionMicros != 0 {
		t.Fatalf("zero error context = %#v", zeroErr)
	}
	if got := pgVersionCount(t, store, tenantID, "zero-model"); got != 1 {
		t.Fatalf("a refused save must not append a version, versions=%d", got)
	}

	result, err := store.SaveModelPrice(ctx, pgSubmit(tenantID, "zero-model", DirectPrice{}), SavePriceOptions{ConfirmZeroPrice: true})
	if err != nil {
		t.Fatalf("confirmed zero save: %v", err)
	}
	if result.Unchanged || !result.ZeroConfirmed || result.Price.Version != 2 || result.Previous == nil || result.Previous.ID != seed.ID {
		t.Fatalf("confirmed zero result = %#v", result)
	}
	// 历史版本原样保留（只追加）。
	history, err := store.GetModelPriceByID(ctx, tenantID, seed.ID)
	if err != nil || history.DirectPrice.InputPerMillionMicros != 4_000_000 || history.Version != 1 {
		t.Fatalf("history version must be untouched: %#v err=%v", history, err)
	}
	// 之后再提交同样的 0 价格：已经是 0，不是清零，也不需要确认，且是空操作。
	again, err := store.SaveModelPrice(ctx, pgSubmit(tenantID, "zero-model", DirectPrice{}), SavePriceOptions{})
	if err != nil || !again.Unchanged {
		t.Fatalf("free to free must be an unconfirmed no-op: %#v err=%v", again, err)
	}
}

func TestSaveModelPriceGuardsScheduledZeroButNotDrafts(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	pgSeed(t, store, tenantID, "sched-model", pgFull())

	scheduled := pgSubmit(tenantID, "sched-model", DirectPrice{})
	scheduled.EffectiveAt = time.Now().UTC().Add(24 * time.Hour)
	if _, err := store.SaveModelPrice(ctx, scheduled, SavePriceOptions{}); !errors.Is(err, ErrZeroPriceNotConfirmed) {
		t.Fatalf("a future-dated zero price will replace the current one and needs confirmation, err=%v", err)
	}

	draft := pgSubmit(tenantID, "sched-model", DirectPrice{})
	draft.Status = PriceStatusDraft
	result, err := store.SaveModelPrice(ctx, draft, SavePriceOptions{})
	if err != nil || result.Unchanged || result.Price.Status != PriceStatusDraft {
		t.Fatalf("a draft never bills, so it is not guarded: %#v err=%v", result, err)
	}
}

func TestSaveModelPriceChangedTermsAppendVersions(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	pgSeed(t, store, tenantID, "chg-model", pgFull())

	cheaper := pgFull()
	cheaper.OutputPerMillionMicros = 10_000_000
	second, err := store.SaveModelPrice(ctx, pgSubmit(tenantID, "chg-model", cheaper), SavePriceOptions{})
	if err != nil || second.Unchanged || second.Price.Version != 2 {
		t.Fatalf("changed output price: %#v err=%v", second, err)
	}
	if second.Previous == nil || second.Previous.DirectPrice.OutputPerMillionMicros != 20_000_000 {
		t.Fatalf("the previous version must be handed back for the audit trail: %#v", second.Previous)
	}

	dropCache := cheaper
	dropCache.HasCachedInputPrice, dropCache.CachedInputPerMillionMicros = false, 0
	third, err := store.SaveModelPrice(ctx, pgSubmit(tenantID, "chg-model", dropCache), SavePriceOptions{})
	if err != nil || third.Unchanged || third.Price.Version != 3 {
		t.Fatalf("clearing the cache read price is a change: %#v err=%v", third, err)
	}
}
