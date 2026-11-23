package billing

import (
	"context"
	"errors"
	"testing"
)

func TestMeteringWalletCurrencyMismatchCannotSilentlySkipDebit(t *testing.T) {
	store, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	wallet, err := store.EnsureWallet(ctx, tenant, user, "USD")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Credit(ctx, tenant, wallet.ID, "fund-usd", 1000, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindWalletForUser(ctx, tenant, user, "CNY"); !errors.Is(err, ErrAllowanceCurrency) {
		t.Fatalf("currency mismatch=%v", err)
	}
	got, err := store.FindWalletForUser(ctx, tenant, user, "USD")
	if err != nil || got == nil || got.ID != wallet.ID {
		t.Fatalf("matching wallet=%+v err=%v", got, err)
	}
}
