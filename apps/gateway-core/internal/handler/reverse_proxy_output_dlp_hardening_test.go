package handler

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestReverseOutputDLPIncludesToolArgumentsAndReasoning(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	const secret = "sk-proj-secret-output-regression-token"
	for _, tc := range []struct{ name, path, contentType, body string }{
		{"chat tool", "/v1/chat/completions", "application/json", `{"choices":[{"message":{"role":"assistant","content":"safe","tool_calls":[{"function":{"name":"send","arguments":"` + secret + `"}}]}}]}`},
		{"chat reasoning", "/v1/chat/completions", "application/json", `{"choices":[{"message":{"role":"assistant","reasoning_content":"` + secret + `"}}]}`},
		{"chat legacy tool", "/v1/chat/completions", "application/json", `{"choices":[{"message":{"role":"assistant","function_call":{"name":"send","arguments":"` + secret + `"}}}]}`},
		{"responses tool", "/v1/responses", "application/json", `{"output_text":"safe","instructions":"trusted-input","output":[{"type":"function_call","name":"send","arguments":"` + secret + `"}]}`},
		{"responses custom tool", "/v1/responses", "application/json", `{"output":[{"type":"custom_tool_call","name":"send","input":"` + secret + `"}]}`},
		{"responses computer tool", "/v1/responses", "application/json", `{"output":[{"type":"computer_call","action":{"url":"https://example.invalid/` + secret + `"}}]}`},
		{"responses reasoning", "/v1/responses", "application/json", `{"output":[{"type":"reasoning","summary":[{"type":"summary_text","text":"` + secret + `"}]}]}`},
		{"anthropic tool", "/v1/messages", "application/json", `{"role":"assistant","content":[{"type":"tool_use","name":"send","input":{"secret":"` + secret + `"}}]}`},
		{"anthropic reasoning", "/v1/messages", "application/json", `{"role":"assistant","content":[{"type":"thinking","thinking":"` + secret + `"}]}`},
		{"chat tool SSE", "/v1/chat/completions", "text/event-stream", "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"" + secret + "\"}}]}}]}\n\ndata: [DONE]\n\n"},
		{"chat reasoning SSE", "/v1/chat/completions", "text/event-stream", "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"" + secret + "\"}}]}\n\ndata: [DONE]\n\n"},
		{"responses tool SSE", "/v1/responses", "text/event-stream", "event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"call_1\",\"delta\":\"" + secret + "\"}\n\n"},
		{"responses custom tool SSE", "/v1/responses", "text/event-stream", "event: response.custom_tool_call_input.delta\ndata: {\"type\":\"response.custom_tool_call_input.delta\",\"item_id\":\"call_1\",\"delta\":\"" + secret + "\"}\n\n"},
		{"responses reasoning SSE", "/v1/responses", "text/event-stream", "event: response.reasoning_summary_text.delta\ndata: {\"type\":\"response.reasoning_summary_text.delta\",\"item_id\":\"reason_1\",\"delta\":\"" + secret + "\"}\n\n"},
		{"anthropic tool SSE", "/v1/messages", "text/event-stream", "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"" + secret + "\"}}\n\n"},
		{"anthropic reasoning SSE", "/v1/messages", "text/event-stream", "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"" + secret + "\"}}\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, payloads := captureEngine(t, func(p map[string]interface{}) string {
				if strings.Contains(p["content"].(string), secret) {
					return `{"action":"block","findings":[]}`
				}
				return `{"action":"allow","findings":[]}`
			})
			defer engine.Close()
			h := newStructuredTestHandler(engine)
			d, err := h.checkResponseSecurityStructured(context.Background(), "req-output-dlp", []byte(tc.body), tc.contentType, "api.example.com", tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allowed || d.Action != "block" {
				t.Fatalf("tool/reasoning secret escaped: %+v payloads=%#v", d, payloads())
			}
			for _, p := range payloads() {
				if strings.Contains(p["content"].(string), "trusted-input") {
					t.Fatal("trusted request instructions entered output inspection")
				}
			}
		})
	}
}

func TestReverseOutputDLPHoldsInterleavedToolAndReasoningFrames(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	filler := strings.Repeat("safe filler ", 300)
	for _, tc := range []struct{ name, path, body string }{
		{"chat tool", "/v1/chat/completions",
			`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"credential-"}}]}}]}` + "\n\n" +
				`data: {"choices":[{"index":1,"delta":{"content":"` + filler + `"}}]}` + "\n\n" +
				`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"canary"}}]}}]}` + "\n\ndata: [DONE]\n\n"},
		{"chat reasoning", "/v1/chat/completions",
			`data: {"choices":[{"delta":{"reasoning_content":"credential-"}}]}` + "\n\n" +
				`data: {"choices":[{"delta":{"content":"` + filler + `"}}]}` + "\n\n" +
				`data: {"choices":[{"delta":{"reasoning_content":"canary"}}]}` + "\n\ndata: [DONE]\n\n"},
		{"responses tool benign final", "/v1/responses",
			"event: response.function_call_arguments.delta\ndata: " + `{"type":"response.function_call_arguments.delta","item_id":"call1","delta":"credential-"}` + "\n\n" +
				"event: response.output_text.delta\ndata: " + `{"type":"response.output_text.delta","delta":"` + filler + `"}` + "\n\n" +
				"event: response.function_call_arguments.delta\ndata: " + `{"type":"response.function_call_arguments.delta","item_id":"call1","delta":"canary"}` + "\n\n" +
				"event: response.function_call_arguments.done\ndata: " + `{"type":"response.function_call_arguments.done","item_id":"call1","arguments":"safe final"}` + "\n\n" +
				"event: response.completed\ndata: " + `{"type":"response.completed","response":{"output":[]}}` + "\n\n"},
		{"messages tool", "/v1/messages",
			"event: content_block_delta\ndata: " + `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"credential-"}}` + "\n\n" +
				"event: content_block_delta\ndata: " + `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"` + filler + `"}}` + "\n\n" +
				"event: content_block_delta\ndata: " + `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"canary"}}` + "\n\n" +
				"event: message_stop\ndata: " + `{"type":"message_stop"}` + "\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, route, audit, _ := reverseHardeningFixture(t, tc.path, "text/event-stream", tc.body, reverseHardeningEngine, failClosedClient(t, false, false))
			w := reverseHardeningForward(t, h, route, http.MethodGet, "")
			if strings.Contains(w.Body.String(), "credential-") || strings.Contains(w.Body.String(), `"canary"`) || !strings.Contains(w.Body.String(), "output_security_blocked") {
				t.Fatalf("interleaved secret fragments escaped: %s", w.Body.String())
			}
			if len(audit.records) != 1 || audit.records[0].Status != "blocked" {
				t.Fatalf("blocked output audit=%+v", audit.records)
			}
		})
	}
}
