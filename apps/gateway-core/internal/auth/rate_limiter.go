package auth

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter handles rate limiting using Redis. It is the legacy path used
// only when the governor is disabled (UAG_GOVERNOR_DISABLED=true).
type RateLimiter struct {
	client      *redis.Client
	concurrency redisEvaler
	// counters runs the RPM/token counter scripts; nil falls back to client.
	counters redisEvaler
	// location is the quota day/month boundary (7.7). It defaults to the
	// platform quota timezone rather than the process's local zone, which is
	// UTC in containers and split the day eight hours early.
	location *time.Location
	now      func() time.Time
}

// defaultQuotaTimezone matches the governor's default quota_timezone.
const defaultQuotaTimezone = "Asia/Shanghai"

func defaultQuotaLocation() *time.Location {
	if location, err := time.LoadLocation(defaultQuotaTimezone); err == nil {
		return location
	}
	// Images without tzdata: Asia/Shanghai has had no DST since 1991.
	return time.FixedZone(defaultQuotaTimezone, 8*60*60)
}

// incrementWindowLua increments a counter and guarantees a TTL in the same
// script, so a crash between INCR and EXPIRE cannot leave a permanent key.
const incrementWindowLua = `
local current = redis.call('INCRBY', KEYS[1], ARGV[1])
if redis.call('PTTL', KEYS[1]) < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return current
`

// incrementTokenUsageLua updates the daily and monthly counters atomically.
const incrementTokenUsageLua = `
local amount = tonumber(ARGV[1])
redis.call('INCRBY', KEYS[1], amount)
redis.call('PEXPIRE', KEYS[1], ARGV[2])
redis.call('INCRBY', KEYS[2], amount)
redis.call('PEXPIRE', KEYS[2], ARGV[3])
return 1
`

type redisEvaler interface {
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
}

const acquireConcurrencyLua = `
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local ttl_ms = tonumber(ARGV[2])
local current = redis.call('INCR', key)
redis.call('PEXPIRE', key, ttl_ms)
if current > limit then
  current = redis.call('DECR', key)
  return {0, current}
end
return {1, current}
`

const releaseConcurrencyLua = `
local key = KEYS[1]
local current = tonumber(redis.call('GET', key) or '0')
if current <= 1 then
  redis.call('DEL', key)
  return 0
end
return redis.call('DECR', key)
`

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(client *redis.Client) *RateLimiter {
	return &RateLimiter{client: client, concurrency: client, counters: client, location: defaultQuotaLocation()}
}

func (r *RateLimiter) counterStore() redisEvaler {
	if r.counters != nil {
		return r.counters
	}
	if r.client != nil {
		return r.client
	}
	return nil
}

// quotaNow returns the current instant in the quota timezone.
func (r *RateLimiter) quotaNow() time.Time {
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	location := r.location
	if location == nil {
		location = defaultQuotaLocation()
	}
	return now().In(location)
}

func dailyTokenKey(projectID string, at time.Time) string {
	return fmt.Sprintf("daily_tokens:%s:%s", projectID, at.Format("2006-01-02"))
}

func monthlyTokenKey(projectID string, at time.Time) string {
	return fmt.Sprintf("monthly_tokens:%s:%s", projectID, at.Format("2006-01"))
}

// CheckRPM checks if the requests per minute limit is exceeded
func (r *RateLimiter) CheckRPM(ctx context.Context, projectID string, rpmLimit int) (bool, error) {
	if rpmLimit <= 0 {
		return true, nil // No limit configured
	}

	key := fmt.Sprintf("rpm:%s:%d", projectID, r.quotaNow().Unix()/60) // Minute bucket
	store := r.counterStore()
	if store == nil {
		return false, fmt.Errorf("rate limit store is unavailable")
	}
	count, err := store.Eval(ctx, incrementWindowLua, []string{key}, 1, (60 * time.Second).Milliseconds()).Int64()
	if err != nil {
		return false, err
	}
	return count <= int64(rpmLimit), nil
}

// CheckConcurrency checks if the concurrency limit is exceeded
// Returns (allowed, currentCount, error)
// IMPORTANT: Caller must call ReleaseConcurrency after request completes (success or failure)
func (r *RateLimiter) CheckConcurrency(ctx context.Context, projectID string, concurrencyLimit int) (bool, int64, error) {
	if concurrencyLimit <= 0 {
		return true, 0, nil // No limit configured
	}

	key := fmt.Sprintf("concurrency:%s", projectID)
	if r.concurrency == nil {
		return false, 0, fmt.Errorf("concurrency store is unavailable")
	}

	values, err := r.concurrency.Eval(
		ctx, acquireConcurrencyLua, []string{key}, concurrencyLimit, (5 * time.Minute).Milliseconds(),
	).Slice()
	if err != nil {
		return false, 0, err
	}
	if len(values) != 2 {
		return false, 0, fmt.Errorf("invalid concurrency admission response")
	}
	allowed, err := redisInteger(values[0])
	if err != nil {
		return false, 0, err
	}
	current, err := redisInteger(values[1])
	if err != nil {
		return false, 0, err
	}
	return allowed == 1, current, nil
}

// ReleaseConcurrency decrements the concurrency counter
func (r *RateLimiter) ReleaseConcurrency(ctx context.Context, projectID string) error {
	if projectID == "" {
		return nil
	}
	if r.concurrency == nil {
		return fmt.Errorf("concurrency store is unavailable")
	}
	key := fmt.Sprintf("concurrency:%s", projectID)
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return r.concurrency.Eval(releaseCtx, releaseConcurrencyLua, []string{key}).Err()
}

func redisInteger(value interface{}) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case int:
		return int64(typed), nil
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid redis integer %q: %w", typed, err)
		}
		return parsed, nil
	case []byte:
		return redisInteger(string(typed))
	default:
		return 0, fmt.Errorf("invalid redis integer type %T", value)
	}
}

// CheckDailyTokenLimit checks if daily token limit is exceeded
func (r *RateLimiter) CheckDailyTokenLimit(ctx context.Context, projectID string, dailyLimit int64) (bool, int64, error) {
	if dailyLimit <= 0 {
		return true, 0, nil // No limit configured
	}

	key := dailyTokenKey(projectID, r.quotaNow())

	current, err := r.client.Get(ctx, key).Int64()
	if err == redis.Nil {
		current = 0
	} else if err != nil {
		return false, 0, err
	}

	return current < dailyLimit, current, nil
}

// CheckMonthlyTokenLimit checks if monthly token limit is exceeded
func (r *RateLimiter) CheckMonthlyTokenLimit(ctx context.Context, projectID string, monthlyLimit int64) (bool, int64, error) {
	if monthlyLimit <= 0 {
		return true, 0, nil // No limit configured
	}

	key := monthlyTokenKey(projectID, r.quotaNow())

	current, err := r.client.Get(ctx, key).Int64()
	if err == redis.Nil {
		current = 0
	} else if err != nil {
		return false, 0, err
	}

	return current < monthlyLimit, current, nil
}

// IncrementTokenUsage increments the token usage counters
func (r *RateLimiter) IncrementTokenUsage(ctx context.Context, projectID string, inputTokens, outputTokens int64) error {
	store := r.counterStore()
	if store == nil {
		return fmt.Errorf("rate limit store is unavailable")
	}
	// One timestamp for both buckets so a request at a month boundary cannot
	// land in different periods, and one script so both counters and their
	// TTLs are written together (7.7).
	at := r.quotaNow()
	return store.Eval(ctx, incrementTokenUsageLua,
		[]string{dailyTokenKey(projectID, at), monthlyTokenKey(projectID, at)},
		inputTokens+outputTokens, (48 * time.Hour).Milliseconds(), (35 * 24 * time.Hour).Milliseconds(),
	).Err()
}
