package handler

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor/providers"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/redis/go-redis/v9"
)

func TestAtomicQuotaManagedAuditDoesNotDoubleCountTokens(t *testing.T) {
	rawURL := os.Getenv("ATOMIC_QUOTA_TEST_REDIS_URL")
	if rawURL == "" {
		t.Skip("ATOMIC_QUOTA_TEST_REDIS_URL is not set")
	}
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	defer client.Close()
	ctx := context.Background()
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}

	location, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Now().In(location)
	monthKey := providers.BudgetKey("tenant", "tenant-a", now.Format("2006-01"))
	if err := client.HSet(ctx, monthKey, "tokens", 8).Err(); err != nil {
		t.Fatal(err)
	}
	limiter := &mockTokenIncrementer{}
	writer := &RealAuditWriter{db: &mockDBExecutor{}, limiter: limiter, aggregator: providers.NewAggregator(client)}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "request-once", TenantID: "tenant-a", ProjectID: "project-a",
		ClientID: "key-a", QuotaAdmissionManaged: true,
	}
	writer.FinalizeRequestLog(ctx, envelope, []byte(`{"usage":{"prompt_tokens":5,"completion_tokens":3}}`), "success", 200, 1, nil)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if client.HGet(ctx, monthKey, "requests").Val() == "1" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := client.HGet(ctx, monthKey, "tokens").Val(); got != "8" {
		t.Fatalf("audit fanout double-counted atomic tokens: got %q want 8", got)
	}
	if len(limiter.incrementCalls) != 0 {
		t.Fatalf("legacy project token limiter was called after atomic accounting: %+v", limiter.incrementCalls)
	}
}
