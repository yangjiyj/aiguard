package budget

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestSnapshotPresenceAndInvalidEvidence(t *testing.T) {
	for _, field := range []string{"tokens", "requests", "cost_micros", "cost_estimated_requests", "cost_unpriced_requests"} {
		for _, value := range []string{"-1", "bad", ""} {
			t.Run(field+"/"+value, func(t *testing.T) {
				mini := miniredis.RunT(t)
				mini.SetTime(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
				rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
				t.Cleanup(func() { _ = rdb.Close() })
				if err := rdb.HSet(context.Background(), BudgetKey("key", "k", "2026-10"), field, value).Err(); err != nil {
					t.Fatal(err)
				}
				_, err := NewSnapshotReader(rdb).Get(context.Background(), "t", []SnapshotScope{{Scope: "key", ID: "k"}})
				if err == nil {
					t.Fatalf("corrupt %s=%q was accepted", field, value)
				}
			})
		}
	}
	mini := miniredis.RunT(t)
	mini.SetTime(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	rdb.HSet(context.Background(), BudgetKey("key", "k", "2026-10"), "cost_micros", "0", "cost_estimated_requests", "0", "cost_unpriced_requests", "0")
	got, err := NewSnapshotReader(rdb).Get(context.Background(), "t", []SnapshotScope{{Scope: "key", ID: "k"}})
	if err != nil {
		t.Fatal(err)
	}
	u := got["key:k"]
	if !u.MonthFields["cost_micros"] || !u.MonthFields["cost_estimated_requests"] || u.MonthFields["tokens"] || u.DayFields["cost_micros"] {
		t.Fatalf("presence lost: %+v", u)
	}
	if ClassifyCostQuality(u.MonthCostMicros, u.MonthCostEstimatedRequests, u.MonthCostUnpricedRequests) != CostQualityUnknown {
		t.Fatal("zero counters cannot prove actual")
	}
}

func TestGetMultiScopeSnapshot(t *testing.T) {
	s := miniredis.RunT(t)
	s.SetTime(time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC))
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	ctx := context.Background()

	// Seed exactly what AtomicAdmission settles: integer cost_micros, no float "cost".
	rdb.HSet(ctx, "budget:project:pj1:2026-05", "tokens", "500", "cost_micros", "20000", "requests", "3")
	rdb.HSet(ctx, "budget:project:pj1:2026-05-29", "tokens", "200", "cost_micros", "8000", "requests", "1")

	snap := NewSnapshotReader(rdb)
	got, err := snap.Get(ctx, "tn1", []SnapshotScope{{Scope: "project", ID: "pj1"}})
	if err != nil {
		t.Fatal(err)
	}
	u, ok := got["project:pj1"]
	if !ok {
		t.Fatal("key project:pj1 not found in snapshot")
	}
	if u.MonthTokens != 500 || u.MonthCostMicros != 20000 || u.MonthRequests != 3 {
		t.Errorf("month usage: %+v", u)
	}
	if u.DayTokens != 200 || u.DayCostMicros != 8000 {
		t.Errorf("day usage: %+v", u)
	}
}

func TestGetMultiScopeSnapshot_MultipleScopes(t *testing.T) {
	s := miniredis.RunT(t)
	s.SetTime(time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC))
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	ctx := context.Background()

	rdb.HSet(ctx, "budget:tenant:tn1:2026-05", "tokens", "9999", "requests", "50")
	rdb.HSet(ctx, "budget:project:pj2:2026-05", "tokens", "100", "requests", "5")

	snap := NewSnapshotReader(rdb)
	got, err := snap.Get(ctx, "tn1", []SnapshotScope{{Scope: "tenant", ID: "tn1"}, {Scope: "project", ID: "pj2"}})
	if err != nil {
		t.Fatal(err)
	}
	if got["tenant:tn1"].MonthTokens != 9999 {
		t.Errorf("tenant MonthTokens: got %d", got["tenant:tn1"].MonthTokens)
	}
	if got["project:pj2"].MonthTokens != 100 {
		t.Errorf("project MonthTokens: got %d", got["project:pj2"].MonthTokens)
	}
}

func TestGetMultiScopeSnapshot_EmptyIDSkipped(t *testing.T) {
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	ctx := context.Background()

	snap := NewSnapshotReader(rdb)
	got, err := snap.Get(ctx, "tn1", []SnapshotScope{{Scope: "project", ID: ""}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result for empty ID, got %v", got)
	}
}

// 7.1/7.2: the float "cost" field, "rpm:<scope>:<id>" ZSET and
// "concurrency:<scope>:<id>" STRING are never written by the gateway. The
// snapshot must ignore them and read the AtomicAdmission layout instead,
// including the @hash bucket of a non-Shanghai policy timezone.
func TestSnapshotReadsAtomicAdmissionLayoutAndIgnoresLegacyKeys(t *testing.T) {
	s := miniredis.RunT(t)
	at := time.Date(2026, 9, 29, 15, 30, 0, 0, time.UTC) // 23:30 Shanghai, 11:30 New York
	s.SetTime(at)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	ctx := context.Background()
	minute := at.Unix() / 60

	rdb.HSet(ctx, "budget:project:project-a:2026-09@acb2a3287bc6", "tokens", "16", "cost_micros", "3234567")
	rdb.HSet(ctx, "budget:project:project-a:2026-09-29@acb2a3287bc6", "tokens", "16", "cost_micros", "3234567")
	rdb.Set(ctx, RpmKey("tenant-a", "project", "project-a", minute), "3", 0)
	rdb.Set(ctx, RpmKey("tenant-a", "project", "project-a", minute-1), "40", 0) // previous minute is not "now"
	rdb.ZAdd(ctx, ConcurrencyKey("tenant-a", "project", "project-a"),
		redis.Z{Score: float64(at.UnixMilli() + 60_000), Member: "live"},
		redis.Z{Score: float64(at.UnixMilli() - 1), Member: "expired"},
	)
	// Legacy decoys that must not leak into the snapshot.
	rdb.HSet(ctx, "budget:project:project-a:2026-09", "cost", "99.5", "tokens", "7")
	rdb.ZAdd(ctx, "rpm:project:project-a", redis.Z{Score: 1, Member: "x"})
	rdb.Set(ctx, "concurrency:project:project-a", "9", 0)

	got, err := NewSnapshotReader(rdb).Get(ctx, "tenant-a", []SnapshotScope{{Scope: "project", ID: "project-a", Timezone: "America/New_York"}})
	if err != nil {
		t.Fatal(err)
	}
	u := got["project:project-a"]
	if u.MonthCostMicros != 3234567 || u.DayCostMicros != 3234567 || u.MonthTokens != 16 {
		t.Fatalf("timezone bucket money/tokens not read: %+v", u)
	}
	if u.Rpm != 3 || u.Concurrency != 1 {
		t.Fatalf("rpm/concurrency must come from orgquota keys: %+v", u)
	}
	if u.MonthBucket != "2026-09@acb2a3287bc6" || u.DayBucket != "2026-09-29@acb2a3287bc6" {
		t.Fatalf("bucket labels: %+v", u)
	}
}

func TestSnapshotRejectsCorruptCounters(t *testing.T) {
	s := miniredis.RunT(t)
	s.SetTime(time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC))
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	ctx := context.Background()
	rdb.HSet(ctx, "budget:tenant:tn1:2026-05", "cost_micros", "1.5")
	if _, err := NewSnapshotReader(rdb).Get(ctx, "tn1", []SnapshotScope{{Scope: "tenant", ID: "tn1"}}); err == nil {
		t.Fatal("non-integer cost_micros must be reported, not read as 0")
	}
}

// TestClassifyCostQuality pins the label precedence and, most importantly, that
// a bucket with no positive quality counter is "unknown" and NEVER "actual",
// even when it holds real money. Full pricing coverage is unprovable: the
// budget hash has no settled-request total written by the same writer as the
// quality counters, so a clean-looking bucket is not evidence of correct
// pricing. Only a positive counter is evidence, and the money is never adjusted.
func TestClassifyCostQuality(t *testing.T) {
	cases := []struct {
		name                       string
		total, estimated, unpriced int64
		want                       CostQuality
	}{
		{"no money no counters is unknown", 0, 0, 0, CostQualityUnknown},
		{"money with no counters is unknown not actual", 5000, 0, 0, CostQualityUnknown},
		{"large money with no counters is still unknown", 999999999, 0, 0, CostQualityUnknown},
		{"one estimate is evidence of degradation", 5000, 1, 0, CostQualityEstimated},
		{"one unpriced outranks estimated", 5000, 3, 1, CostQualityUnpriced},
		{"unpriced with no money is still unpriced", 0, 0, 1, CostQualityUnpriced},
		{"estimated with no money is still estimated", 0, 2, 0, CostQualityEstimated},
		{"negative counters are not evidence", 100, -1, -1, CostQualityUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyCostQuality(tc.total, tc.estimated, tc.unpriced); got != tc.want {
				t.Fatalf("ClassifyCostQuality(%d, %d, %d) = %q, want %q",
					tc.total, tc.estimated, tc.unpriced, got, tc.want)
			}
		})
	}
}

// TestClassifyCostQualityNeverReturnsActual guards the deliberate absence of an
// "actual" label: no input may produce it, because that would assert full
// pricing coverage the data cannot support.
func TestClassifyCostQualityNeverReturnsActual(t *testing.T) {
	for _, total := range []int64{0, 1, 5000, 1 << 40} {
		for _, estimated := range []int64{0, 1, 100} {
			for _, unpriced := range []int64{0, 1, 100} {
				got := ClassifyCostQuality(total, estimated, unpriced)
				if string(got) == "actual" {
					t.Fatalf("ClassifyCostQuality(%d, %d, %d) = actual; full pricing coverage is unprovable",
						total, estimated, unpriced)
				}
			}
		}
	}
}
