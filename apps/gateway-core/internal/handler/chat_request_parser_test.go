package handler

import (
	"bytes"
	"encoding/json"
	stdErrors "errors"
	"net/http/httptest"
	"testing"
)

func TestParseChatCompletionRequestKeepsRawBodyAndStreamFlag(t *testing.T) {
	raw := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}],"stream":true}`)

	parsed, err := parseChatCompletionRequest(raw)
	if err != nil {
		t.Fatalf("expected valid chat request, got error: %v", err)
	}
	if !bytes.Equal(parsed.raw, raw) {
		t.Fatalf("raw body changed: got %q want %q", string(parsed.raw), string(raw))
	}
	if parsed.request.Model != "gpt-4" {
		t.Fatalf("expected model gpt-4, got %q", parsed.request.Model)
	}
	if !parsed.request.Stream {
		t.Fatalf("expected stream flag to be preserved")
	}
	if len(parsed.request.Messages) != 1 || messageText(parsed.request.Messages[0].Content) != "hello" {
		t.Fatalf("unexpected messages: %+v", parsed.request.Messages)
	}
}

func TestMarshalChatProviderBodyPreservesPromptCacheAndProviderExtensions(t *testing.T) {
	raw := []byte("{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"hello\",\"cache_control\":{\"type\":\"ephemeral\"}}]}],\"stream\":true,\"prompt_cache_key\":\"client-cache\",\"provider_cache_extension\":{\"enabled\":true}}")
	parsed, err := parseChatCompletionRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	body, err := marshalChatProviderBody(raw, &parsed.request)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["prompt_cache_key"] != "client-cache" || got["provider_cache_extension"] == nil {
		t.Fatalf("provider cache extensions were dropped: %s", body)
	}
	content := got["messages"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)
	if content["cache_control"].(map[string]any)["type"] != "ephemeral" {
		t.Fatalf("Anthropic cache_control was dropped: %v", content)
	}
}

func TestMarshalChatProviderBodyClearsOriginalStreamForBufferedUpstream(t *testing.T) {
	raw := []byte(`{"model":"gpt-4","messages":[],"stream":true}`)
	request := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{}}

	body, err := marshalChatProviderBody(raw, request)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if stream, ok := got["stream"].(bool); !ok || stream {
		t.Fatalf("buffered provider request retained stream=true: %s", body)
	}
}

func TestParseChatCompletionRequestReturnsPartialRequestOnInvalidJSON(t *testing.T) {
	raw := []byte(`{"model":"gpt-4","messages":"not-an-array"}`)

	parsed, err := parseChatCompletionRequest(raw)
	if err == nil {
		t.Fatal("expected invalid JSON error")
	}
	var parseErr *chatRequestParseError
	if !stdErrors.As(err, &parseErr) {
		t.Fatalf("expected chatRequestParseError, got %T", err)
	}
	if parseErr.failure != chatRequestInvalidJSON {
		t.Fatalf("expected invalid JSON failure, got %s", parseErr.failure)
	}
	if !bytes.Equal(parsed.raw, raw) {
		t.Fatalf("raw body changed on invalid JSON: got %q want %q", string(parsed.raw), string(raw))
	}
	if parsed.request.Model != "gpt-4" {
		t.Fatalf("expected partially parsed model for early audit, got %q", parsed.request.Model)
	}
}

func TestParseChatCompletionRequestRejectsEmptyBody(t *testing.T) {
	parsed, err := parseChatCompletionRequest(nil)
	if err == nil {
		t.Fatal("expected empty body to be rejected")
	}
	var parseErr *chatRequestParseError
	if !stdErrors.As(err, &parseErr) {
		t.Fatalf("expected chatRequestParseError, got %T", err)
	}
	if parseErr.failure != chatRequestInvalidJSON {
		t.Fatalf("expected invalid JSON failure, got %s", parseErr.failure)
	}
	if parsed.raw != nil {
		t.Fatalf("expected nil raw body for empty body, got %q", string(parsed.raw))
	}
	if parsed.request.Model != "" {
		t.Fatalf("expected empty model for empty body, got %q", parsed.request.Model)
	}
}

func TestReadChatCompletionRequestClassifiesBodyReadFailure(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/chat/completions", failingChatRequestBody{})

	parsed, err := readChatCompletionRequest(req, maxAPIRequestBodyBytes)
	if err == nil {
		t.Fatal("expected body read error")
	}
	var parseErr *chatRequestParseError
	if !stdErrors.As(err, &parseErr) {
		t.Fatalf("expected chatRequestParseError, got %T", err)
	}
	if parseErr.failure != chatRequestReadFailed {
		t.Fatalf("expected read failure, got %s", parseErr.failure)
	}
	if parsed.raw != nil {
		t.Fatalf("expected no raw body on read failure, got %q", string(parsed.raw))
	}
	if parsed.request.Model != "" {
		t.Fatalf("expected empty model on read failure, got %q", parsed.request.Model)
	}
}

func TestReadChatCompletionRequestRejectsOversizedBody(t *testing.T) {
	const limitBytes int64 = 1024
	body := bytes.NewReader(bytes.Repeat([]byte("a"), int(limitBytes)+1))
	req := httptest.NewRequest("POST", "/v1/chat/completions", body)

	parsed, err := readChatCompletionRequest(req, limitBytes)
	if err == nil {
		t.Fatal("expected request body too large error")
	}
	var parseErr *chatRequestParseError
	if !stdErrors.As(err, &parseErr) {
		t.Fatalf("expected chatRequestParseError, got %T", err)
	}
	if parseErr.failure != chatRequestBodyTooLarge {
		t.Fatalf("expected body too large failure, got %s", parseErr.failure)
	}
	if parsed.raw != nil {
		t.Fatalf("expected no raw body for oversized request, got %d bytes", len(parsed.raw))
	}
}

type failingChatRequestBody struct{}

func (failingChatRequestBody) Read([]byte) (int, error) {
	return 0, stdErrors.New("simulated chat body read failure")
}
