package llmusage

import "testing"

func TestFromResponseBody(t *testing.T) {
	cases := []struct {
		name, contentType, body string
		wantOK                  bool
		prompt, output, cached  int64
		parser                  string
	}{
		{name: "OpenAI 非流式", contentType: "application/json",
			body:   `{"id":"x","usage":{"prompt_tokens":120,"completion_tokens":30,"prompt_tokens_details":{"cached_tokens":20}}}`,
			wantOK: true, prompt: 120, output: 30, cached: 20, parser: "json"},
		{name: "OpenAI 流式最后一帧带 usage", contentType: "text/event-stream",
			body:   "data: {\"choices\":[{\"delta\":{\"content\":\"你\"}}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":4}}\n\ndata: [DONE]\n",
			wantOK: true, prompt: 10, output: 4, parser: "sse"},
		{name: "Anthropic 流式 message_start + message_delta 合并", contentType: "text/event-stream",
			body: "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":50,\"cache_read_input_tokens\":10,\"output_tokens\":1}}}\n\n" +
				"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\n",
			wantOK: true, prompt: 60, output: 42, cached: 10, parser: "sse"},
		{name: "Responses 流式 response.completed", contentType: "text/event-stream",
			body:   "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":300,\"output_tokens\":70,\"output_tokens_details\":{\"reasoning_tokens\":20}}}}\n\n",
			wantOK: true, prompt: 300, output: 70, parser: "sse"},
		{name: "网页版 ChatGPT 没有 usage", contentType: "text/event-stream",
			body:   "data: {\"message\":{\"content\":{\"parts\":[\"你好\"]}}}\n\ndata: [DONE]\n",
			wantOK: false},
		{name: "非法数值视为解析不出", contentType: "application/json", body: `{"usage":{"prompt_tokens":-1}}`, wantOK: false},
		{name: "空响应", contentType: "application/json", body: ``, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := FromResponseBody([]byte(tc.body), tc.contentType)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v usage=%+v", ok, tc.wantOK, got)
			}
			if !ok {
				return
			}
			if got.PromptTokens != tc.prompt || got.OutputTokens != tc.output || got.CachedInputTokens != tc.cached || got.Parser != tc.parser {
				t.Fatalf("usage=%+v", got)
			}
		})
	}
}
