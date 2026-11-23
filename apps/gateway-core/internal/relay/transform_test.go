package relay

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestResponsesEventToChatPreservesReasoningToolsAndUsage(t *testing.T) {
	tests := []struct {
		name string
		data string
		want StreamEventType
	}{
		{name: "text", data: `{"type":"response.output_text.delta","delta":"hello"}`, want: EventTextDelta},
		{name: "reasoning", data: `{"type":"response.reasoning_summary_text.delta","delta":"think"}`, want: EventReasoningDelta},
		{name: "tool", data: `{"type":"response.function_call_arguments.delta","item_id":"call-1","delta":"{\"x\":1}"}`, want: EventToolArgumentsDelta},
		{name: "done", data: `{"type":"response.completed","response":{"usage":{"input_tokens":4,"output_tokens":2}}}`, want: EventMessageEnd},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event, err := ResponsesSSEToEvent(SSEEvent{Event: tc.name, Data: tc.data})
			if err != nil {
				t.Fatal(err)
			}
			if event.Type != tc.want {
				t.Fatalf("type=%s; want %s", event.Type, tc.want)
			}
		})
	}

	encoder := NewChatEncoder("resp-1", "public-model")
	text, err := encoder.Encode(StreamEvent{Type: EventTextDelta, Delta: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if string(text) == "" || string(text) == "[DONE]" {
		t.Fatalf("text chunk=%q", text)
	}
	tool, err := encoder.Encode(StreamEvent{Type: EventToolArgumentsDelta, ToolCall: &ToolCall{ID: "call-1", Name: "lookup"}, Delta: `{"x":1}`})
	if err != nil {
		t.Fatal(err)
	}
	if string(tool) == "" {
		t.Fatal("tool chunk is empty")
	}
	usage, err := encoder.Encode(StreamEvent{Type: EventUsageFinal, Usage: &Usage{InputTokens: 4, OutputTokens: 2}})
	if err != nil {
		t.Fatal(err)
	}
	var chunk map[string]any
	if err := json.Unmarshal(usage, &chunk); err != nil {
		t.Fatal(err)
	}
	if chunk["usage"] == nil {
		t.Fatalf("usage chunk=%s", usage)
	}
}

func TestResponsesFunctionCallArgumentsFinalSnapshotHandling(t *testing.T) {
	tests := []struct {
		name   string
		events []string
		want   map[int]string
	}{
		{
			name: "streamed deltas suppress final snapshot",
			events: []string{
				`{"type":"response.function_call_arguments.delta","item_id":"call-1","output_index":0,"delta":"{\"skill\":\""}`,
				`{"type":"response.function_call_arguments.delta","item_id":"call-1","output_index":0,"delta":"deploy\"}"}`,
				`{"type":"response.function_call_arguments.done","item_id":"call-1","output_index":0,"arguments":"{\"skill\":\"deploy\"}"}`,
			},
			want: map[int]string{0: `{"skill":"deploy"}`},
		},
		{
			name: "done only is a compatibility fallback",
			events: []string{
				`{"type":"response.function_call_arguments.done","item_id":"call-1","output_index":0,"arguments":"{\"skill\":\"deploy\"}"}`,
			},
			want: map[int]string{0: `{"skill":"deploy"}`},
		},
		{
			name: "parallel tools keep independent state and streamed data wins",
			events: []string{
				`{"type":"response.function_call_arguments.delta","item_id":"call-1","output_index":0,"delta":"{\"path\":\"a\"}"}`,
				`{"type":"response.function_call_arguments.done","item_id":"call-2","output_index":1,"arguments":"{\"path\":\"b\"}"}`,
				`{"type":"response.function_call_arguments.done","item_id":"call-1","output_index":0,"arguments":"{\"path\":\"wrong\"}"}`,
			},
			want: map[int]string{0: `{"path":"a"}`, 1: `{"path":"b"}`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := encodeResponsesToolArgumentsByIndex(t, tc.events...)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("tool arguments=%#v; want %#v", got, tc.want)
			}
			for index, arguments := range got {
				if !json.Valid([]byte(arguments)) {
					t.Fatalf("tool %d arguments are not valid JSON: %q", index, arguments)
				}
			}
		})
	}
}

func encodeResponsesToolArgumentsByIndex(t *testing.T, data ...string) map[int]string {
	t.Helper()
	encoder := NewChatEncoder("resp-1", "public-model")
	argumentsByIndex := make(map[int]string)
	for _, raw := range data {
		event, err := ResponsesSSEToEvent(SSEEvent{Data: raw})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := encoder.Encode(event)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) == 0 {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						Index    int `json:"index"`
						Function struct {
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(payload, &chunk); err != nil {
			t.Fatal(err)
		}
		for _, choice := range chunk.Choices {
			for _, tool := range choice.Delta.ToolCalls {
				argumentsByIndex[tool.Index] += tool.Function.Arguments
			}
		}
	}
	return argumentsByIndex
}

func TestChatEncoderAddsAnthropicCacheToPromptTokens(t *testing.T) {
	usage := &Usage{InputTokens: 10, OutputTokens: 5, CacheReadInputTokens: 2000, CacheCreationInputTokens: 30}
	decode := func(encoder *ChatEncoder) map[string]any {
		payload, err := encoder.Encode(StreamEvent{Type: EventUsageFinal, Usage: usage})
		if err != nil {
			t.Fatal(err)
		}
		var chunk map[string]any
		if err := json.Unmarshal(payload, &chunk); err != nil {
			t.Fatal(err)
		}
		return chunk["usage"].(map[string]any)
	}

	legacy := decode(NewChatEncoder("r", "m"))
	if legacy["prompt_tokens"].(float64) != 10 || legacy["prompt_tokens_details"] != nil {
		t.Fatalf("OpenAI-style usage must stay unchanged: %#v", legacy)
	}

	encoder := NewChatEncoder("r", "m")
	encoder.PromptIncludesCache = true
	got := decode(encoder)
	if got["prompt_tokens"].(float64) != 2040 || got["total_tokens"].(float64) != 2045 {
		t.Fatalf("Anthropic cache must be part of prompt_tokens: %#v", got)
	}
	details, _ := got["prompt_tokens_details"].(map[string]any)
	if details["cached_tokens"].(float64) != 2000 || details["cache_creation_input_tokens"].(float64) != 30 {
		t.Fatalf("prompt_tokens_details missing: %#v", got)
	}
}
