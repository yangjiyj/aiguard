package provider

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"io"
	"strings"
	"testing"
)

func TestNativeAnthropicFinalUsageCorrection(t *testing.T) {
	r := &nativeAnthropicStreamReader{}
	start, err := r.anthropicEventToRelay(relay.SSEEvent{Data: `{"type":"message_start","message":{"usage":{"input_tokens":100,"output_tokens":1,"cache_read_input_tokens":800,"cache_creation_input_tokens":20}}}`})
	if err != nil {
		t.Fatal(err)
	}
	last, err := r.anthropicEventToRelay(relay.SSEEvent{Data: `{"type":"message_delta","usage":{"input_tokens":10,"output_tokens":0,"cache_read_input_tokens":0}}`})
	if err != nil || last.Usage.InputTokens != 10 || last.Usage.OutputTokens != 0 || last.Usage.CacheReadInputTokens != 0 || last.Usage.CacheCreationInputTokens != 20 {
		t.Fatalf("%+v %v", last.Usage, err)
	}
	if start.Usage.InputTokens != 100 {
		t.Fatal("previous snapshot mutated")
	}
	partial, _ := r.anthropicEventToRelay(relay.SSEEvent{Data: `{"type":"message_delta","usage":{"output_tokens":3}}`})
	if partial.Usage.InputTokens != 10 || partial.Usage.CacheCreationInputTokens != 20 {
		t.Fatalf("%+v", partial.Usage)
	}
}

func TestOpenAIReadsCorrectionsAfterFirstUsageAndPreservesPartialFields(t *testing.T) {
	wire := strings.Join([]string{
		`data: {"id":"c","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":null}],"usage":{"prompt_tokens":100,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":80,"cache_creation_tokens":10}}}`,
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		`data: {"usage":{"completion_tokens":3}}`,
		`data: {"usage":{"prompt_tokens":50,"prompt_tokens_details":{"cached_tokens":0,"cache_creation_tokens":0}}}`,
		`data: [DONE]`, ""}, "\n\n")
	r := &httpStreamReader{events: relay.NewSSEReader(strings.NewReader(wire), relay.SSELimits{})}
	var last *relay.Usage
	for {
		e, err := r.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if e.Usage != nil {
			last = e.Usage
		}
	}
	if last == nil || last.InputTokens != 50 || last.OutputTokens != 3 || last.CacheReadInputTokens != 0 || last.CacheCreationInputTokens != 0 {
		t.Fatalf("%+v", last)
	}
	body, err := accumulateOpenAISSE(strings.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Usage struct {
			Prompt int `json:"prompt_tokens"`
			Output int `json:"completion_tokens"`
		}
	}
	if json.Unmarshal(body, &payload) != nil || payload.Usage.Prompt != 50 || payload.Usage.Output != 3 {
		t.Fatalf("%s", body)
	}
}
func TestOpenAIStreamCacheWriteDetailsAliases(t *testing.T) {
	for _, key := range []string{"cache_creation_tokens", "cache_creation_input_tokens", "cache_write_tokens"} {
		u := openAIStreamUsage(map[string]any{"prompt_tokens": float64(100), "input_tokens_details": map[string]any{"cached_tokens": float64(60), key: float64(20)}})
		if u.CacheReadInputTokens != 60 || u.CacheCreationInputTokens != 20 {
			t.Fatalf("%s: %+v", key, u)
		}
	}
}

func TestOpenAIExplicitZeroInputRemainsAuthoritative(t *testing.T) {
	u := openAIStreamUsage(map[string]any{"prompt_tokens": float64(0), "completion_tokens": float64(0), "prompt_tokens_details": map[string]any{"cached_tokens": float64(80)}})
	if u.InputTokens != 0 || u.CacheReadInputTokens != 0 {
		t.Fatalf("%+v", u)
	}
}
