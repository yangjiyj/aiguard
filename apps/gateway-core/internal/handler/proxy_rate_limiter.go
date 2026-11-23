package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ProxyRateLimiter handles rate limiting for proxy (no-token) requests.
// Uses sliding window counters in Redis for multi-layer rate control.
type ProxyRateLimiter interface {
	// CheckIPRPM checks per-IP rate limit for a specific model.
	CheckIPRPM(ctx context.Context, clientIP, modelID string, rpmLimit, windowSec int) (bool, error)
	// CheckGlobalRPM checks global rate limit for a specific model.
	CheckGlobalRPM(ctx context.Context, modelID string, globalRPM int) (bool, error)
	// CheckDailyCap checks daily request cap for a specific model.
	CheckDailyCap(ctx context.Context, modelID string, dailyCap int) (bool, error)
	// IncrementUsage increments the usage counters after a successful request.
	IncrementUsage(ctx context.Context, modelID string, inputTokens, outputTokens int64) error
}

// RealProxyRateLimiter implements ProxyRateLimiter using Redis.
type RealProxyRateLimiter struct {
	client *redis.Client
}

// NewRealProxyRateLimiter creates a new proxy rate limiter.
func NewRealProxyRateLimiter(client *redis.Client) *RealProxyRateLimiter {
	return &RealProxyRateLimiter{client: client}
}

// CheckIPRPM checks per-IP rate limit using a sliding window.
// Key: proxy:ip:{modelID}:{clientIP}:{minuteBucket}
func (r *RealProxyRateLimiter) CheckIPRPM(ctx context.Context, clientIP, modelID string, rpmLimit, windowSec int) (bool, error) {
	if rpmLimit <= 0 {
		return true, nil
	}

	minuteBucket := time.Now().Unix() / int64(windowSec)
	key := fmt.Sprintf("proxy:ip:%s:%s:%d", modelID, clientIP, minuteBucket)

	count, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}

	// Set expiry on first increment
	if count == 1 {
		r.client.Expire(ctx, key, time.Duration(windowSec)*time.Second+5*time.Second)
	}

	return count <= int64(rpmLimit), nil
}

// CheckGlobalRPM checks global rate limit for a model.
// Key: proxy:global:{modelID}:{minuteBucket}
func (r *RealProxyRateLimiter) CheckGlobalRPM(ctx context.Context, modelID string, globalRPM int) (bool, error) {
	if globalRPM <= 0 {
		return true, nil
	}

	minuteBucket := time.Now().Unix() / 60
	key := fmt.Sprintf("proxy:global:%s:%d", modelID, minuteBucket)

	count, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}

	if count == 1 {
		r.client.Expire(ctx, key, 65*time.Second)
	}

	return count <= int64(globalRPM), nil
}

// CheckDailyCap checks the daily request cap for a model.
// Key: proxy:daily:{modelID}:{date}
func (r *RealProxyRateLimiter) CheckDailyCap(ctx context.Context, modelID string, dailyCap int) (bool, error) {
	if dailyCap <= 0 {
		return true, nil
	}

	today := time.Now().Format("2006-01-02")
	key := fmt.Sprintf("proxy:daily:%s:%s", modelID, today)

	count, err := r.client.Get(ctx, key).Int64()
	if err == redis.Nil {
		return true, nil
	} else if err != nil {
		return true, nil // Fail-open on Redis error
	}

	return count < int64(dailyCap), nil
}

// IncrementUsage increments the daily usage counters for a model.
func (r *RealProxyRateLimiter) IncrementUsage(ctx context.Context, modelID string, inputTokens, outputTokens int64) error {
	today := time.Now().Format("2006-01-02")
	key := fmt.Sprintf("proxy:daily:%s:%s", modelID, today)

	if err := r.client.IncrBy(ctx, key, 1).Err(); err != nil {
		return err
	}
	r.client.Expire(ctx, key, 72*time.Hour)

	return nil
}
