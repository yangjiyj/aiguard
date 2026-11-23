package auth

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

type recordingEvaler struct {
	result     interface{}
	err        error
	script     string
	keys       []string
	args       []interface{}
	contextErr error
}

func (r *recordingEvaler) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
	r.script = script
	r.keys = append([]string(nil), keys...)
	r.args = append([]interface{}(nil), args...)
	r.contextErr = ctx.Err()
	return redis.NewCmdResult(r.result, r.err)
}

func TestCheckConcurrencyAtomicallyRollsBackDeniedAcquire(t *testing.T) {
	store := &recordingEvaler{result: []interface{}{int64(0), int64(5)}}
	limiter := &RateLimiter{concurrency: store}

	allowed, current, err := limiter.CheckConcurrency(context.Background(), "project-1", 5)

	if err != nil || allowed || current != 5 {
		t.Fatalf("allowed=%v current=%d err=%v", allowed, current, err)
	}
	if len(store.keys) != 1 || store.keys[0] != "concurrency:project-1" {
		t.Fatalf("unexpected concurrency key: %#v", store.keys)
	}
	if !strings.Contains(store.script, "DECR") || !strings.Contains(store.script, "current > limit") {
		t.Fatalf("denied acquisition must roll back inside the same script:\n%s", store.script)
	}
}

func TestReleaseConcurrencyUsesContextAfterRequestCancellation(t *testing.T) {
	store := &recordingEvaler{result: int64(0)}
	limiter := &RateLimiter{concurrency: store}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := limiter.ReleaseConcurrency(ctx, "project-1"); err != nil {
		t.Fatalf("release failed: %v", err)
	}
	if store.contextErr != nil {
		t.Fatalf("release inherited canceled request context: %v", store.contextErr)
	}
	if !strings.Contains(store.script, "current <= 1") {
		t.Fatalf("release must clamp the counter at zero:\n%s", store.script)
	}
}

func rateLimiterRedis(t *testing.T) *redis.Client {
	t.Helper()
	rawURL := os.Getenv("ATOMIC_QUOTA_TEST_REDIS_URL")
	if rawURL == "" {
		t.Skip("ATOMIC_QUOTA_TEST_REDIS_URL is not set")
	}
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	t.Cleanup(func() {
		_ = client.FlushDB(context.Background()).Err()
		_ = client.Close()
	})
	if err := client.FlushDB(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	return client
}

// 7.7: 18:30 UTC is already the next day in the quota timezone. The legacy
// limiter must bucket by quota_timezone, not by the container's UTC clock.
func TestLegacyTokenCountersBucketByQuotaTimezone(t *testing.T) {
	client := rateLimiterRedis(t)
	limiter := NewRateLimiter(client)
	instant := time.Date(2026, 9, 30, 18, 30, 0, 0, time.UTC)
	limiter.now = func() time.Time { return instant }
	ctx := context.Background()

	if err := limiter.IncrementTokenUsage(ctx, "project-tz", 70, 30); err != nil {
		t.Fatal(err)
	}
	for key, wantTTL := range map[string]time.Duration{
		"daily_tokens:project-tz:2026-10-01": 48 * time.Hour,
		"monthly_tokens:project-tz:2026-10":  35 * 24 * time.Hour,
	} {
		value, err := client.Get(ctx, key).Int64()
		if err != nil || value != 100 {
			t.Fatalf("%s=%d err=%v", key, value, err)
		}
		if ttl := client.PTTL(ctx, key).Val(); ttl <= 0 || ttl > wantTTL {
			t.Fatalf("%s ttl=%v want (0,%v]", key, ttl, wantTTL)
		}
	}
	if n := client.Exists(ctx, "daily_tokens:project-tz:2026-09-30", "monthly_tokens:project-tz:2026-09").Val(); n != 0 {
		t.Fatalf("UTC-dated buckets were written: %d", n)
	}
	allowed, current, err := limiter.CheckDailyTokenLimit(ctx, "project-tz", 100)
	if err != nil || allowed || current != 100 {
		t.Fatalf("daily check allowed=%v current=%d err=%v", allowed, current, err)
	}
	allowed, current, err = limiter.CheckMonthlyTokenLimit(ctx, "project-tz", 101)
	if err != nil || !allowed || current != 100 {
		t.Fatalf("monthly check allowed=%v current=%d err=%v", allowed, current, err)
	}
}

// 7.7: the RPM counter and its TTL are written by one script, so concurrent
// requests never exceed the limit and the window key always expires.
func TestLegacyRPMCounterIsAtomicAndAlwaysExpires(t *testing.T) {
	client := rateLimiterRedis(t)
	limiter := NewRateLimiter(client)
	instant := time.Date(2026, 9, 30, 18, 30, 0, 0, time.UTC)
	limiter.now = func() time.Time { return instant }
	ctx := context.Background()
	key := fmt.Sprintf("rpm:project-rpm:%d", instant.Unix()/60)
	// A leftover counter without TTL (a crash between INCR and EXPIRE) must
	// still expire instead of throttling the project forever.
	const leftover = 3
	if err := client.Set(ctx, key, leftover, 0).Err(); err != nil {
		t.Fatal(err)
	}
	const limit, callers = 10, 40
	var wg sync.WaitGroup
	var admitted atomic.Int64
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := limiter.CheckRPM(ctx, "project-rpm", limit); err == nil && ok {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != limit-leftover {
		t.Fatalf("admitted=%d want %d", admitted.Load(), limit-leftover)
	}
	if ttl := client.PTTL(ctx, key).Val(); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("rpm window ttl=%v", ttl)
	}
}

func TestIncrementTokenUsageWritesBothBucketsInOneScript(t *testing.T) {
	store := &recordingEvaler{result: int64(1)}
	limiter := &RateLimiter{counters: store, location: time.UTC, now: func() time.Time {
		return time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC)
	}}
	if err := limiter.IncrementTokenUsage(context.Background(), "p", 1, 2); err != nil {
		t.Fatal(err)
	}
	if len(store.keys) != 2 || store.keys[0] != "daily_tokens:p:2026-01-31" || store.keys[1] != "monthly_tokens:p:2026-01" {
		t.Fatalf("keys=%v", store.keys)
	}
	if len(store.args) != 3 || store.args[0] != int64(3) {
		t.Fatalf("args=%v", store.args)
	}
}
