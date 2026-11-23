package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func parseResponsesSSE(t *testing.T, body string) []map[string]interface{} {
	t.Helper()
	var events []map[string]interface{}
	for _, block := range strings.Split(strings.TrimSpace(body), "\n\n") {
		var eventName, data string
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "event: ") {
				eventName = strings.TrimPrefix(line, "event: ")
			}
			if strings.HasPrefix(line, "data: ") {
				data = strings.TrimPrefix(line, "data: ")
			}
		}
		if eventName == "" || data == "" {
			t.Fatalf("invalid SSE block: %q", block)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			t.Fatalf("invalid JSON for %s: %v", eventName, err)
		}
		if payload["type"] != eventName {
			t.Fatalf("event=%q payload.type=%v", eventName, payload["type"])
		}
		events = append(events, payload)
	}
	return events
}

func eventTypes(events []map[string]interface{}) []string {
	out := make([]string, 0, len(events))
	for _, event := range events {
		out = append(out, event["type"].(string))
	}
	return out
}

func assertSequenceNumbers(t *testing.T, events []map[string]interface{}) {
	t.Helper()
	for i, event := range events {
		if event["sequence_number"] != float64(i) {
			t.Fatalf("event %d sequence_number=%v", i, event["sequence_number"])
		}
	}
}

func TestWriteResponsesStreamText(t *testing.T) {
	w := httptest.NewRecorder()
	response := &ResponsesResponse{
		ID: "resp_test", Object: "response", CreatedAt: 1716399600,
		Status: "completed", Model: "gpt-5.5",
		Output: []ResponsesOutput{{
			ID: "msg_test", Type: "message", Status: "completed", Role: "assistant",
			Content: []ResponsesContent{{Type: "output_text", Text: "hello Codex", Annotations: []interface{}{}}},
		}},
		Usage: &ResponsesUsage{InputTokens: 11, OutputTokens: 7, TotalTokens: 18},
	}

	if err := writeResponsesStream(w, response); err != nil {
		t.Fatal(err)
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("Content-Type=%q", got)
	}
	events := parseResponsesSSE(t, w.Body.String())
	assertSequenceNumbers(t, events)
	got := strings.Join(eventTypes(events), ",")
	want := strings.Join([]string{
		"response.created", "response.in_progress", "response.output_item.added",
		"response.content_part.added", "response.output_text.delta",
		"response.output_text.done", "response.content_part.done",
		"response.output_item.done", "response.completed",
	}, ",")
	if got != want {
		t.Fatalf("event sequence\n got: %s\nwant: %s", got, want)
	}
	created := events[0]["response"].(map[string]interface{})
	if created["usage"] != nil {
		t.Fatalf("created usage=%v, want null", created["usage"])
	}
	if _, ok := created["output"].([]interface{}); !ok {
		t.Fatalf("created output=%T, want array", created["output"])
	}
	added := events[2]["item"].(map[string]interface{})
	content, exists := added["content"]
	if !exists {
		t.Fatalf("response.output_item.added item.content is absent: %v", added)
	}
	contentArray, ok := content.([]interface{})
	if !ok || len(contentArray) != 0 {
		t.Fatalf("response.output_item.added item.content=%T(%v), want []", content, content)
	}
	for _, event := range events {
		if event["type"] == "response.output_text.delta" && event["logprobs"] == nil {
			t.Fatalf("delta event missing logprobs: %v", event)
		}
	}
	completed := events[len(events)-1]["response"].(map[string]interface{})
	usage := completed["usage"].(map[string]interface{})
	if usage["input_tokens"] != float64(11) || usage["output_tokens"] != float64(7) || usage["total_tokens"] != float64(18) {
		t.Fatalf("completed usage=%v", usage)
	}
}

func TestWriteResponsesStreamFunctionCall(t *testing.T) {
	w := httptest.NewRecorder()
	response := &ResponsesResponse{
		ID: "resp_tool", Object: "response", Status: "completed", Model: "gpt-5.5",
		Output: []ResponsesOutput{{
			ID: "fc_test", Type: "function_call", Status: "completed",
			CallID: "call_test", Name: "shell", Arguments: `{"command":"pwd"}`,
		}},
	}
	if err := writeResponsesStream(w, response); err != nil {
		t.Fatal(err)
	}
	events := parseResponsesSSE(t, w.Body.String())
	got := strings.Join(eventTypes(events), ",")
	if !strings.Contains(got, "response.function_call_arguments.delta,response.function_call_arguments.done") {
		t.Fatalf("missing function argument events: %s", got)
	}
	done := events[len(events)-2]["item"].(map[string]interface{})
	if done["call_id"] != "call_test" || done["name"] != "shell" || done["arguments"] != `{"command":"pwd"}` {
		t.Fatalf("function item=%v", done)
	}
}

func TestWriteResponsesStreamFailure(t *testing.T) {
	w := httptest.NewRecorder()
	if err := writeResponsesStreamFailure(w, "resp_failed", "provider_unavailable", "upstream disconnected"); err != nil {
		t.Fatal(err)
	}
	events := parseResponsesSSE(t, w.Body.String())
	assertSequenceNumbers(t, events)
	got := strings.Join(eventTypes(events), ",")
	if got != "error,response.failed" {
		t.Fatalf("events=%s", got)
	}
}
