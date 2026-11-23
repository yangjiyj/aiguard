package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFullyFreePriceChecksAllFeeDimensionsAndRequiresBinding(t *testing.T) {
	zero := Micros(0)
	one := Micros(1)
	p := &ModelPrice{ID: "free", TenantID: "tenant", ModelName: "model", PricingMode: PricingModeDirect, Currency: "CNY"}
	if !p.IsFullyFree() {
		t.Fatal("explicit all-zero price must be fully free")
	}
	if (*ModelPrice)(nil).IsFullyFree() {
		t.Fatal("missing price is not an explicit free price")
	}
	unbound := *p
	unbound.ID = ""
	if unbound.IsFullyFree() {
		t.Fatal("unbound zero data must not bypass funds")
	}
	for _, rate := range []DirectPrice{{InputPerMillionMicros: 1}, {CachedInputPerMillionMicros: 1, HasCachedInputPrice: true}, {CacheWritePerMillionMicros: 1, HasCacheWritePrice: true}, {OutputPerMillionMicros: 1}} {
		paid := *p
		paid.DirectPrice = rate
		if paid.IsFullyFree() {
			t.Fatal("nonzero token rate was marked free")
		}
	}
	variants := []PriceExtensions{
		{RequestPerCallMicros: 1}, {ImagePerImageMicros: 1}, {ImageOutputPerMillionMicros: &one}, {ImageInputPerMillionMicros: &one}, {CachedImageInputPerMillionMicros: &one}, {ReasoningPerMillionMicros: &one},
		{ToolPricesPerThousandMicros: map[string]Micros{"search": 1}},
		{ImagePricing: &ImagePricing{Mode: "per_image", Variants: []ImageVariantPrice{{Size: "*", Quality: "*", PricePerImageMicros: 1}}}},
	}
	for _, extension := range variants {
		paid := *p
		paid.Extensions = extension
		if paid.IsFullyFree() {
			t.Fatal("nonzero extension rate was marked free")
		}
	}
	p.Extensions = PriceExtensions{ImageInputPerMillionMicros: &zero, ToolPricesPerThousandMicros: map[string]Micros{"search": 0}, ImagePricing: &ImagePricing{Mode: "per_image", Variants: []ImageVariantPrice{{Size: "*", Quality: "*", PricePerImageMicros: 0}}}}
	if !p.IsFullyFree() {
		t.Fatal("all-zero declared extensions should be free")
	}
}

func TestMonthlyWalletFullyFreeFailureReleasesTokenCountersIdempotently(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	at := time.Now().UTC()
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", at)
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "fully-free", Currency: "CNY", PricingMode: PricingModeDirect})
	if e != nil || !p.IsFullyFree() {
		t.Fatalf("free binding=%+v %v", p, e)
	}
	if _, e = db.Exec(ctx, `INSERT INTO billing_customer_limits(tenant_id,user_id,daily_token_limit,monthly_token_limit) VALUES($1,$2,10,20)`, tenant, user); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.ReservePricedWithUsage(ctx, tenant, w.ID, "free-fail", 0, 2, p); e != nil {
		t.Fatal(e)
	}
	var tokens int64
	if e = db.QueryRow(ctx, `SELECT sum(reserved_tokens) FROM billing_limit_counters WHERE tenant_id=$1 AND user_id=$2`, tenant, user).Scan(&tokens); e != nil || tokens != 4 {
		t.Fatalf("token freeze did not occur: %d %v", tokens, e)
	}
	for i := 0; i < 2; i++ {
		r, w, e := s.Release(ctx, tenant, "free-fail")
		if e != nil || r.Status != ReservationReleased || w.BalanceMicros != 0 || w.ReservedMicros != 0 {
			t.Fatalf("free failure release=%+v wallet=%+v %v", r, w, e)
		}
	}
	if e = db.QueryRow(ctx, `SELECT sum(reserved_tokens) FROM billing_limit_counters WHERE tenant_id=$1 AND user_id=$2`, tenant, user).Scan(&tokens); e != nil || tokens != 0 {
		t.Fatalf("free failed request retained token holds: %d %v", tokens, e)
	}
	var moneyEvents int
	if e = db.QueryRow(ctx, `SELECT count(*) FROM billing_ledger_entries WHERE tenant_id=$1`, tenant).Scan(&moneyEvents); e != nil || moneyEvents != 0 {
		t.Fatalf("zero money failure created financial event: %d %v", moneyEvents, e)
	}
}

func TestNonfreeZeroQuoteCannotReserveAfterWalletWasExhausted(t *testing.T) {
	s, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	w, e := s.EnsureMonthlyWalletGrant(ctx, tenant, user, "CNY", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.CreateModelPrice(ctx, NewModelPrice{TenantID: tenant, ModelName: "paid-zero-estimate", Currency: "CNY", PricingMode: PricingModeDirect, DirectPrice: DirectPrice{InputPerMillionMicros: 1}})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.ReservePricedWithUsage(ctx, tenant, w.ID, "empty-estimate", 0, 1, p); !errors.Is(e, ErrInsufficientBalance) {
		t.Fatalf("zero paid estimate bypassed empty wallet: %v", e)
	}
	var reservations int
	if e = db.QueryRow(ctx, `SELECT count(*) FROM billing_reservations WHERE tenant_id=$1`, tenant).Scan(&reservations); e != nil || reservations != 0 {
		t.Fatalf("rejected quote froze tokens: %d %v", reservations, e)
	}
}
