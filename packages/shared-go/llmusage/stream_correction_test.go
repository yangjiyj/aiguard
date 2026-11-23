package llmusage

import "testing"

func TestStreamFinalCorrectionsPreserveOmittedInput(t *testing.T) {
	for _, tc := range []struct {
		name, body               string
		prompt, read, write, out int64
	}{
		{"anthropic", `data: {"type":"message_start","message":{"usage":{"input_tokens":100,"output_tokens":1,"cache_read_input_tokens":800,"cache_creation_input_tokens":20}}}

data: {"type":"message_delta","usage":{"input_tokens":10,"output_tokens":0,"cache_read_input_tokens":0}}

`, 30, 0, 20, 0},
		{"partial", `data: {"message":{"usage":{"input_tokens":100,"cache_read_input_tokens":800}}}

data: {"usage":{"output_tokens":4}}

`, 900, 800, 0, 4},
		{"openai", `data: {"usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_tokens_details":{"cached_tokens":80}}}

data: {"usage":{"prompt_tokens":50,"completion_tokens":0,"prompt_tokens_details":{"cached_tokens":0}}}

`, 50, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, ok := FromResponseBody([]byte(tc.body), "text/event-stream")
			if !ok || u.PromptTokens != tc.prompt || u.CachedInputTokens != tc.read || u.CacheWriteTokens != tc.write || u.OutputTokens != tc.out {
				t.Fatalf("%+v trusted=%v", u, ok)
			}
		})
	}
}

func TestStreamMultilineDataUsage(t *testing.T) {
	u, ok := FromResponseBody([]byte("event: response.completed\r\ndata: {\r\ndata: \"response\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":2}}}\r\n\r\n"), "text/event-stream")
	if !ok || u.PromptTokens != 10 || u.OutputTokens != 2 {
		t.Fatalf("%+v trusted=%v", u, ok)
	}
}
