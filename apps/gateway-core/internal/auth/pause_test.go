package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/redis/go-redis/v9"
)

// fakeExister drives isKeyPaused with canned EXISTS results so the manual-pause
// gate's fail-open behavior can be unit-tested without a live Redis.
type fakeExister struct {
	val  int64
	err  error
	seen string
}

func (f *fakeExister) Exists(ctx context.Context, keys ...string) *redis.IntCmd {
	if len(keys) > 0 {
		f.seen = keys[0]
	}
	return redis.NewIntResult(f.val, f.err)
}

func TestIsKeyPaused(t *testing.T) {
	ctx := context.Background()

	t.Run("nil client reports not paused", func(t *testing.T) {
		if isKeyPaused(ctx, nil, "abc123") {
			t.Fatal("nil redis client must report not-paused")
		}
	})

	t.Run("EXISTS>0 reports paused and queries pause:<prefix>", func(t *testing.T) {
		f := &fakeExister{val: 1}
		if !isKeyPaused(ctx, f, "abc123") {
			t.Fatal("EXISTS=1 must report paused")
		}
		if f.seen != "pause:abc123" {
			t.Fatalf("pause gate must query key %q, got %q", "pause:abc123", f.seen)
		}
	})

	t.Run("EXISTS=0 reports not paused", func(t *testing.T) {
		f := &fakeExister{val: 0}
		if isKeyPaused(ctx, f, "abc123") {
			t.Fatal("EXISTS=0 must report not-paused")
		}
	})

	t.Run("redis error fails open (not paused)", func(t *testing.T) {
		f := &fakeExister{val: 1, err: errors.New("redis down")}
		if isKeyPaused(ctx, f, "abc123") {
			t.Fatal("a Redis error must fail open (not-paused) for availability")
		}
	})
}
