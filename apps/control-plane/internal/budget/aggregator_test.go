package budget

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestIncrementAllScopes(t *testing.T) {
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	agg := NewAggregator(rdb)
	ctx := context.Background()

	err := agg.IncrementAllScopes(ctx, IncrementArgs{
		Scopes: []ScopeKey{
			{"tenant", "tn1"},
			{"team", "tm1"},
			{"project", "pj1"},
			{"user", "u1"},
			{"key", "sk-x"},
		},
		Tokens:   1000,
		Cost:     0.05,
		Requests: 1,
		YYYYMM:   "2026-05",
		YYYYMMDD: "2026-05-29",
	})
	if err != nil {
		t.Fatal(err)
	}

	// monthly tenant tokens
	if got, _ := rdb.HGet(ctx, "budget:tenant:tn1:2026-05", "tokens").Result(); got != "1000" {
		t.Errorf("tenant monthly tokens: got %q, want %q", got, "1000")
	}
	// daily project requests
	if got, _ := rdb.HGet(ctx, "budget:project:pj1:2026-05-29", "requests").Result(); got != "1" {
		t.Errorf("project day requests: got %q, want %q", got, "1")
	}
	// monthly team cost (HINCRBYFLOAT stores as float string)
	if got, _ := rdb.HGet(ctx, "budget:team:tm1:2026-05", "cost").Result(); got == "" {
		t.Errorf("team monthly cost not set")
	}
	// daily user tokens
	if got, _ := rdb.HGet(ctx, "budget:user:u1:2026-05-29", "tokens").Result(); got != "1000" {
		t.Errorf("user day tokens: got %q, want %q", got, "1000")
	}
}

func TestIncrementAllScopes_EmptyIDSkipped(t *testing.T) {
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	agg := NewAggregator(rdb)
	ctx := context.Background()

	// ID="" scope should be skipped, no error
	err := agg.IncrementAllScopes(ctx, IncrementArgs{
		Scopes: []ScopeKey{
			{"tenant", ""},
			{"project", "pj2"},
		},
		Tokens:   50,
		Cost:     0.01,
		Requests: 1,
		YYYYMM:   "2026-05",
		YYYYMMDD: "2026-05-29",
	})
	if err != nil {
		t.Fatal(err)
	}
	// tenant key should NOT exist
	n, _ := rdb.Exists(ctx, "budget:tenant::2026-05").Result()
	if n != 0 {
		t.Errorf("empty-ID tenant key should not exist")
	}
	// project key should exist
	if got, _ := rdb.HGet(ctx, "budget:project:pj2:2026-05", "tokens").Result(); got != "50" {
		t.Errorf("project tokens: got %q, want 50", got)
	}
}
