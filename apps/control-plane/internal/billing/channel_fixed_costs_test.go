package billing

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestProrateChannelFixedCostCalendarBoundaries(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	at := func(s string) time.Time {
		v, err := time.ParseInLocation("2006-01-02", s, loc)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	stop := "2024-03-02"
	tests := []struct {
		name       string
		cost       ChannelFixedCost
		start, end string
		want       int64
	}{
		{"leap-month", ChannelFixedCost{AmountMicros: 29_000_000, Period: "month", EffectiveFrom: "2024-02-01"}, "2024-02-01", "2024-03-01", 29_000_000},
		{"cross-month", ChannelFixedCost{AmountMicros: 899_000_000, Period: "month", EffectiveFrom: "2024-01-01"}, "2024-02-29", "2024-03-02", 60_000_000},
		{"clipped", ChannelFixedCost{AmountMicros: 899_000_000, Period: "month", EffectiveFrom: "2024-02-29", EffectiveTo: &stop}, "2024-02-01", "2024-03-31", 60_000_000},
		{"annual", ChannelFixedCost{AmountMicros: 348_000_000, Period: "year", EffectiveFrom: "2024-02-01"}, "2024-02-01", "2024-03-01", 29_000_000},
		{"not-effective", ChannelFixedCost{AmountMicros: 29_000_000, Period: "month", EffectiveFrom: "2024-02-01"}, "2024-01-01", "2024-02-01", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ProrateChannelFixedCost(tt.cost, at(tt.start), at(tt.end), loc)
			if err != nil || got != tt.want {
				t.Fatalf("got=%d err=%v want=%d", got, err, tt.want)
			}
		})
	}
}

func TestBuildChannelMarginsAllocatesFixedCostOnceAndReportsMismatch(t *testing.T) {
	start := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	fixed := []ChannelFixedCost{{ProviderID: "p1", Currency: "CNY", AmountMicros: 101, Period: "month", EffectiveFrom: "2024-02-01"}, {ProviderID: "idle", Currency: "CNY", AmountMicros: 50, Period: "month", EffectiveFrom: "2024-02-01"}}
	usage := []ChannelUsage{{ProviderID: "p1", ModelName: "a", Currency: "CNY", Requests: 1, CostKnownRequests: 1, BilledMicros: 100, BilledCostKnownMicros: 100, CostMicros: 10}, {ProviderID: "p1", ModelName: "b", Currency: "CNY", Requests: 2, CostKnownRequests: 2, BilledMicros: 200, BilledCostKnownMicros: 200, CostMicros: 20}}
	groups := BuildChannelMargins(nil, usage, ChannelMarginWindow{FixedCosts: fixed, Start: start, End: end, Currency: "CNY"})
	var allocated int64
	for _, g := range groups {
		for _, c := range g.Channels {
			if c.ProviderID == "p1" {
				allocated += c.FixedCostMicros
				if c.CostMicros != c.VariableCostMicros+c.FixedCostMicros {
					t.Fatalf("cost parts=%+v", c)
				}
			}
		}
	}
	if allocated != 101 || len(groups) != 3 {
		t.Fatalf("allocated=%d groups=%+v", allocated, groups)
	}
	mismatched := BuildChannelMargins([]UpstreamRate{{ProviderID: "p1", ModelName: "a", Currency: "USD"}}, usage, ChannelMarginWindow{Currency: "CNY"})
	if !mismatched[0].Channels[0].CurrencyMismatch || mismatched[0].Channels[0].MarginMicros != nil {
		t.Fatalf("mismatch=%+v", mismatched)
	}
}

func TestChannelFixedCostStoreIsolationOverlapAndCurrency(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	provider := "fixed_" + tenant
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,$1,'openai')`, provider, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name) VALUES($1,$2,'fixed-model')`, provider+"_model", provider); err != nil {
		t.Fatal(err)
	}
	base := ChannelFixedCost{ProviderID: provider, Currency: "CNY", AmountMicros: 31_000_000, Period: "month", EffectiveFrom: "2026-01-01", CreatedBy: user}
	to := "2026-02-01"
	base.EffectiveTo = &to
	saved, err := store.SaveChannelFixedCost(ctx, tenant, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.SaveChannelFixedCost(ctx, tenant, base); !errors.Is(err, ErrFixedCostOverlap) {
		t.Fatalf("overlap=%v", err)
	}
	// Adjacent half-open intervals are valid, and an open-ended tail conflicts.
	tail := base
	tail.EffectiveFrom = to
	tail.EffectiveTo = nil
	tailSaved, err := store.SaveChannelFixedCost(ctx, tenant, tail)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.DeleteChannelFixedCost(ctx, tenant+"_other", saved.ID); !errors.Is(err, ErrFixedCostNotFound) {
		t.Fatalf("cross tenant=%v", err)
	}
	tailSaved.Currency = "USD"
	if _, err = store.SaveChannelFixedCost(ctx, tenant, *tailSaved); !errors.Is(err, ErrAllowanceCurrency) {
		t.Fatalf("currency=%v", err)
	}
	if err = store.SaveUpstreamRate(ctx, tenant, UpstreamRate{ProviderID: provider, ModelName: "fixed-model", Currency: "USD"}); !errors.Is(err, ErrAllowanceCurrency) {
		t.Fatalf("upstream currency=%v", err)
	}
	if err = store.SaveUpstreamRate(ctx, tenant, UpstreamRate{ProviderID: provider, ModelName: "fixed-model", Currency: "CNY", InputMicros: 1}); err != nil {
		t.Fatal(err)
	}
	if err = store.DeleteUpstreamRate(ctx, tenant+"_other", provider, "fixed-model"); !errors.Is(err, ErrPriceNotFound) {
		t.Fatalf("cross tenant upstream=%v", err)
	}
	if err = store.DeleteUpstreamRate(ctx, tenant, provider, "fixed-model"); err != nil {
		t.Fatal(err)
	}
	if err = store.DeleteChannelFixedCost(ctx, tenant, tailSaved.ID); err != nil {
		t.Fatal(err)
	}
	// Concurrent requests must never create overlapping intervals.
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := store.SaveChannelFixedCost(ctx, tenant, tail); results <- err }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrFixedCostOverlap) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("successes=%d", successes)
	}
}
