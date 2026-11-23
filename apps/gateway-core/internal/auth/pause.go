package auth

import (
	"context"

	"github.com/redis/go-redis/v9"
)

// redisExister is the minimal Redis surface the manual-pause gate needs.
// Abstracting it lets the gate be unit-tested without a live Redis.
type redisExister interface {
	Exists(ctx context.Context, keys ...string) *redis.IntCmd
}

// isKeyPaused reports whether the given API key prefix has been manually paused.
//
// The pause flag is written by the control-plane budget handler as the Redis
// key pause:<keyPrefix> (see control-plane budget.PauseKey). gateway-core is a
// separate Go module and cannot import that package, so the "pause:" prefix is
// a cross-module string contract that MUST stay in sync.
//
// Posture mirrors the rate limiter (handler/chat_completions.go): on any Redis
// error the request is treated as not-paused (fail-open for availability) — a
// Redis blip must not take down gateway auth. A nil client likewise reports
// not-paused.
func isKeyPaused(ctx context.Context, rc redisExister, keyPrefix string) bool {
	if rc == nil {
		return false
	}
	paused, err := rc.Exists(ctx, "pause:"+keyPrefix).Result()
	return err == nil && paused > 0
}
