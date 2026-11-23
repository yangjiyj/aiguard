package eventbus

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type StreamClient interface {
	XAdd(ctx context.Context, stream string, values map[string]any, maxLen int64) (string, error)
}

type Publisher struct {
	client StreamClient
	stream string
	maxLen int64
}

func NewPublisher(client StreamClient, stream string, maxLen int64) *Publisher {
	if stream == "" {
		stream = DefaultStreamName
	}
	return &Publisher{client: client, stream: stream, maxLen: maxLen}
}

func (p *Publisher) Publish(ctx context.Context, event Event) (string, error) {
	if p == nil || p.client == nil {
		return "", fmt.Errorf("event publisher client is required")
	}
	if err := event.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("marshal event: %w", err)
	}
	values := map[string]any{
		"event":          string(data),
		"event_id":       event.ID,
		"event_type":     event.Type,
		"tenant_id":      event.TenantID,
		"schema_version": event.SchemaVersion,
		"occurred_at":    event.OccurredAt.Format(time.RFC3339Nano),
	}
	if event.TraceID != "" {
		values["trace_id"] = event.TraceID
	}
	if event.RequestID != "" {
		values["request_id"] = event.RequestID
	}
	streamID, err := p.client.XAdd(ctx, p.stream, values, p.maxLen)
	if err != nil {
		return "", fmt.Errorf("publish event: %w", err)
	}
	return streamID, nil
}

type RedisStreamClient struct {
	client redis.UniversalClient
}

func NewRedisStreamClient(client redis.UniversalClient) *RedisStreamClient {
	return &RedisStreamClient{client: client}
}

func (c *RedisStreamClient) XAdd(ctx context.Context, stream string, values map[string]any, maxLen int64) (string, error) {
	if c == nil || c.client == nil {
		return "", fmt.Errorf("redis client is required")
	}
	args := &redis.XAddArgs{Stream: stream, Values: values}
	if maxLen > 0 {
		args.MaxLen = maxLen
		args.Approx = true
	}
	return c.client.XAdd(ctx, args).Result()
}
