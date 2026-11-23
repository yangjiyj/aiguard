package handler

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// 真实 valkey 上的读写与过期；不可达时必须很快按未命中返回。
// RESPONSE_CACHE_TEST_REDIS_URL 未设置时跳过。
func TestRedisResponseCacheAgainstRealServer(t *testing.T) {
	url := os.Getenv("RESPONSE_CACHE_TEST_REDIS_URL")
	if url == "" {
		t.Skip("RESPONSE_CACHE_TEST_REDIS_URL is not set")
	}
	options, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	defer client.Close()
	cache := NewRedisResponseCache(client)
	ctx := context.Background()
	key := responseCacheKeyPrefix + "test-" + time.Now().Format("150405.000000000")
	t.Cleanup(func() { client.Del(context.Background(), key) })

	if _, hit := cache.Get(ctx, key); hit {
		t.Fatal("fresh key should miss")
	}
	cache.Set(ctx, key, []byte(`{"choices":[]}`), 2*time.Second)
	value, hit := cache.Get(ctx, key)
	if !hit || string(value) != `{"choices":[]}` {
		t.Fatalf("get after set = %q, %v", value, hit)
	}
	if ttl := client.TTL(ctx, key).Val(); ttl <= 0 || ttl > 2*time.Second {
		t.Fatalf("ttl = %v", ttl)
	}
	time.Sleep(2100 * time.Millisecond)
	if _, hit := cache.Get(ctx, key); hit {
		t.Fatal("key should expire")
	}

	dead := NewRedisResponseCache(redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: 0, DialTimeout: time.Second}))
	start := time.Now()
	if _, hit := dead.Get(ctx, key); hit {
		t.Fatal("unreachable store must miss")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("unreachable store took %v; lookups must stay within the request budget", elapsed)
	}
}
