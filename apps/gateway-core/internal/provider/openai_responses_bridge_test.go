package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func chatResponsesBridgeEnvelope() *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{
		EndpointType:    "chat",
		Model:           "logical-model",
		UpstreamModelID: "vendor-model",
		ProtocolCapabilities: modelrouter.ProtocolCapabilities{
			Explicit:            true,
			ResponsesNative:     true,
			ChatResponsesBridge: true,
		},
	}
}

func TestOpenAIAdapterDoesNotInferChatResponsesBridge(t *testing.T) {
	envelope := chatResponsesBridgeEnvelope()
	envelope.Model = "customer-text-model"
	envelope.UpstreamModelID = "vendor-text-model"
	envelope.ProtocolCapabilities.ChatResponsesBridge = false
	raw := []byte(`{"model":"customer-text-model","messages":[{"role":"user","content":"hello"}]}`)

	got, err := (&OpenAIAdapter{}).TransformRequest(envelope, raw)
	if err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("request body is invalid JSON: %v", err)
	}
	if body["model"] != "vendor-text-model" || body["messages"] == nil {
		t.Fatalf("Chat request was not preserved: %#v", body)
	}
	if _, exists := body["input"]; exists {
		t.Fatalf("Responses input was inferred without bridge authorization: %#v", body)
	}
}

func TestOpenAIAdapterDualProtocolRoutePreservesChatRequest(t *testing.T) {
	envelope := chatResponsesBridgeEnvelope()
	envelope.Model = "customer-text-model"
	envelope.UpstreamModelID = "vendor-text-model"
	envelope.ProtocolCapabilities.ChatCompletions = true
	envelope.ProtocolCapabilities.ChatResponsesBridge = false
	raw := []byte(`{"model":"customer-text-model","messages":[{"role":"user","content":"hello"}]}`)

	got, err := (&OpenAIAdapter{}).TransformRequest(envelope, raw)
	if err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("request body is invalid JSON: %v", err)
	}
	if body["model"] != "vendor-text-model" || body["messages"] == nil {
		t.Fatalf("dual-protocol Chat request was not preserved: %#v", body)
	}
	if _, exists := body["input"]; exists {
		t.Fatalf("dual-protocol Chat request was converted to Responses: %#v", body)
	}
}

func TestOpenAIAdapterDualProtocolRouteHonorsPerRequestResponsesSelection(t *testing.T) {
	envelope := chatResponsesBridgeEnvelope()
	envelope.Model = "customer-text-model"
	envelope.UpstreamModelID = "vendor-text-model"
	envelope.UpstreamProtocol = "responses"
	envelope.ProtocolCapabilities.ChatCompletions = true
	envelope.ProtocolCapabilities.ChatResponsesBridge = false
	raw := []byte(`{"model":"customer-text-model","messages":[{"role":"user","content":"hello"}]}`)

	got, err := (&OpenAIAdapter{}).TransformRequest(envelope, raw)
	if err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("request body is invalid JSON: %v", err)
	}
	if body["model"] != "vendor-text-model" || body["input"] == nil {
		t.Fatalf("per-request Responses selection was ignored: %#v", body)
	}
	if _, exists := body["messages"]; exists {
		t.Fatalf("Chat messages leaked after Responses selection: %#v", body)
	}
}

func TestOpenAIAdapterChatResponsesBridgeTransformsRequest(t *testing.T) {
	adapter := &OpenAIAdapter{}
	raw := []byte(`{"model":"logical-model","messages":[{"role":"system","content":"be concise"},{"role":"developer","content":"follow policy"},{"role":"user","content":"hello"},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"shell","arguments":"{\"cmd\":\"pwd\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"/tmp"}],"tools":[{"type":"function","function":{"name":"shell","description":"run a command","parameters":{"type":"object"},"strict":true}}],"tool_choice":{"type":"function","function":{"name":"shell"}},"max_completion_tokens":123,"temperature":0.2,"top_p":0.7,"reasoning_effort":"high","response_format":{"type":"json_schema","json_schema":{"name":"answer","schema":{"type":"object"},"strict":true}},"parallel_tool_calls":false,"store":true,"metadata":{"trace":"x"}}`)

	got, err := adapter.TransformRequest(chatResponsesBridgeEnvelope(), raw)
	if err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("bridge body is invalid JSON: %v", err)
	}
	if body["model"] != "vendor-model" || body["instructions"] != "be concise\n\nfollow policy" {
		t.Fatalf("model/instructions mismatch: %#v", body)
	}
	if body["max_output_tokens"] != float64(123) || body["temperature"] != 0.2 {
		t.Fatalf("generation parameters mismatch: %#v", body)
	}
	if _, ok := body["messages"]; ok {
		t.Fatalf("Chat messages leaked into Responses request: %#v", body)
	}
	input, ok := body["input"].([]any)
	if !ok || len(input) != 4 {
		t.Fatalf("input=%#v, want user/assistant/function_call/function_call_output", body["input"])
	}
	assistantMessage, ok := input[1].(map[string]any)
	if !ok || assistantMessage["role"] != "assistant" || assistantMessage["content"] != "" {
		t.Fatalf("assistant message mismatch: %#v", input[1])
	}
	functionCall, ok := input[2].(map[string]any)
	if !ok || functionCall["type"] != "function_call" || functionCall["call_id"] != "call_1" || functionCall["name"] != "shell" {
		t.Fatalf("function call mismatch: %#v", input[2])
	}
	functionOutput, ok := input[3].(map[string]any)
	if !ok || functionOutput["type"] != "function_call_output" || functionOutput["call_id"] != "call_1" || functionOutput["output"] != "/tmp" {
		t.Fatalf("function output mismatch: %#v", input[3])
	}
	tools, ok := body["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools=%#v", body["tools"])
	}
	tool, ok := tools[0].(map[string]any)
	if !ok || tool["type"] != "function" || tool["name"] != "shell" {
		t.Fatalf("Responses tool mismatch: %#v", tools[0])
	}
	if tool["strict"] != true {
		t.Fatalf("Responses tool strict contract was lost: %#v", tool)
	}
	toolChoice, ok := body["tool_choice"].(map[string]any)
	if !ok || toolChoice["type"] != "function" || toolChoice["name"] != "shell" {
		t.Fatalf("tool choice mismatch: %#v", body["tool_choice"])
	}
	if body["top_p"] != 0.7 || body["parallel_tool_calls"] != false || body["store"] != true {
		t.Fatalf("Responses-compatible parameters were dropped: %#v", body)
	}
	reasoning, ok := body["reasoning"].(map[string]any)
	if !ok || reasoning["effort"] != "high" {
		t.Fatalf("reasoning_effort mismatch: %#v", body["reasoning"])
	}
	textConfig, ok := body["text"].(map[string]any)
	if !ok {
		t.Fatalf("response_format did not become text config: %#v", body["text"])
	}
	format, ok := textConfig["format"].(map[string]any)
	if !ok || format["type"] != "json_schema" || format["name"] != "answer" || format["strict"] != true {
		t.Fatalf("response_format mismatch: %#v", textConfig["format"])
	}
	metadata, ok := body["metadata"].(map[string]any)
	if !ok || metadata["trace"] != "x" {
		t.Fatalf("metadata mismatch: %#v", body["metadata"])
	}
}

func TestOpenAIAdapterChatResponsesBridgeDoesNotForwardUnsupportedTruncation(t *testing.T) {
	got, err := (&OpenAIAdapter{}).TransformRequest(
		chatResponsesBridgeEnvelope(),
		[]byte(`{"model":"logical-model","messages":[{"role":"user","content":"hello"}],"truncation":"auto"}`),
	)
	if err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("bridge body is invalid JSON: %v", err)
	}
	if _, ok := body["truncation"]; ok {
		t.Fatalf("unsupported truncation leaked upstream: %#v", body)
	}
}

func TestOpenAIAdapterChatResponsesBridgePreservesLargeHistoryForGPT56(t *testing.T) {
	envelope := chatResponsesBridgeEnvelope()
	envelope.UpstreamModelID = "gpt-5.6-sol"
	latest := strings.Repeat("y", 300<<10)
	old := strings.Repeat("x", 700<<10)
	raw, err := json.Marshal(map[string]any{
		"model": "logical-model",
		"messages": []map[string]any{
			{"role": "system", "content": "keep policy"},
			{"role": "user", "content": old},
			{"role": "assistant", "content": "old answer"},
			{"role": "user", "content": latest},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := (&OpenAIAdapter{}).TransformRequest(envelope, raw)
	if err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}
	if len(got) <= 896<<10 {
		t.Fatalf("fixture must exceed the removed local budget, got %d bytes", len(got))
	}

	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("bridge body is invalid JSON: %v", err)
	}
	if _, ok := body["truncation"]; ok {
		t.Fatalf("unsupported truncation leaked upstream: %#v", body)
	}
	if body["instructions"] != "keep policy" {
		t.Fatalf("instructions=%v, want policy retained", body["instructions"])
	}
	input, ok := body["input"].([]any)
	if !ok || len(input) != 3 {
		t.Fatalf("input=%#v, want all non-system turns preserved", body["input"])
	}
	oldMessage, ok := input[0].(map[string]any)
	if !ok || oldMessage["role"] != "user" || oldMessage["content"] != old {
		t.Fatalf("old input mismatch: %#v", input[0])
	}
	latestMessage, ok := input[2].(map[string]any)
	if !ok || latestMessage["role"] != "user" || latestMessage["content"] != latest {
		t.Fatalf("latest input mismatch: %#v", input[2])
	}
}

func TestOpenAIAdapterChatResponsesBridgeAcceptsLargeLatestTurnForGPT56(t *testing.T) {
	envelope := chatResponsesBridgeEnvelope()
	envelope.UpstreamModelID = "gpt-5.6-sol"
	latest := strings.Repeat("z", 2<<20)
	raw, err := json.Marshal(map[string]any{
		"model": "logical-model",
		"messages": []map[string]any{
			{"role": "user", "content": latest},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := (&OpenAIAdapter{}).TransformRequest(envelope, raw)
	if err != nil {
		t.Fatalf("large latest turn must be forwarded: %v", err)
	}
	if len(got) <= 2<<20 {
		t.Fatalf("large latest turn was truncated, got %d bytes", len(got))
	}
}

func TestOpenAIAdapterChatResponsesBridgeAcceptsSixInlineImagesForGPT56(t *testing.T) {
	envelope := chatResponsesBridgeEnvelope()
	envelope.UpstreamModelID = "gpt-5.6-sol"
	content := []map[string]any{{"type": "text", "text": "inspect all six screenshots"}}
	inlineImages := make([]string, 0, 6)
	for index := 0; index < 6; index++ {
		inlineImage := "data:image/png;base64," + strings.Repeat(string(rune('A'+index)), 256<<10)
		inlineImages = append(inlineImages, inlineImage)
		content = append(content, map[string]any{"type": "image_url", "image_url": map[string]any{"url": inlineImage}})
	}
	raw, err := json.Marshal(map[string]any{
		"model":    "logical-model",
		"messages": []map[string]any{{"role": "user", "content": content}},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := (&OpenAIAdapter{}).TransformRequest(envelope, raw)
	if err != nil {
		t.Fatalf("six inline images must be forwarded: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatal(err)
	}
	input := body["input"].([]any)
	gotContent := input[0].(map[string]any)["content"].([]any)
	if len(gotContent) != 7 {
		t.Fatalf("content count=%d, want text plus six images", len(gotContent))
	}
	for index, inlineImage := range inlineImages {
		image := gotContent[index+1].(map[string]any)
		if image["type"] != "input_image" || image["image_url"] != inlineImage {
			t.Fatalf("inline image %d was not preserved exactly", index)
		}
	}
}

func TestOpenAIAdapterChatResponsesBridgeTransformsResponse(t *testing.T) {
	adapter := &OpenAIAdapter{}
	responses := []byte(`{"id":"resp_1","object":"response","created_at":1716399600,"status":"completed","model":"vendor-model","output":[{"type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}]},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]},{"type":"function_call","id":"fc_2","name":"shell","arguments":"{\"cmd\":\"pwd\"}"}],"usage":{"input_tokens":11,"output_tokens":7,"total_tokens":18}}`)

	got, err := adapter.TransformResponseForEnvelope(chatResponsesBridgeEnvelope(), responses)
	if err != nil {
		t.Fatalf("TransformResponse failed: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("Chat response is invalid JSON: %v", err)
	}
	if body["object"] != "chat.completion" || body["model"] != "logical-model" {
		t.Fatalf("response identity mismatch: %#v", body)
	}
	choices, ok := body["choices"].([]any)
	if !ok || len(choices) != 1 {
		t.Fatalf("choices=%#v", body["choices"])
	}
	choice := choices[0].(map[string]any)
	if choice["finish_reason"] != "tool_calls" {
		t.Fatalf("finish_reason=%v", choice["finish_reason"])
	}
	message := choice["message"].(map[string]any)
	if message["role"] != "assistant" || message["content"] != "done" || message["reasoning_content"] != "thinking" {
		t.Fatalf("message=%#v", message)
	}
	toolCalls := message["tool_calls"].([]any)
	if len(toolCalls) != 1 || toolCalls[0].(map[string]any)["id"] != "fc_2" {
		t.Fatalf("tool_calls=%#v", toolCalls)
	}
	usage := body["usage"].(map[string]any)
	if usage["prompt_tokens"] != float64(11) || usage["completion_tokens"] != float64(7) || usage["total_tokens"] != float64(18) {
		t.Fatalf("usage=%#v", usage)
	}
}

func TestOpenAIAdapterChatResponsesBridgeMapsContentFilterIncompleteStatus(t *testing.T) {
	responses := []byte(`{"id":"resp_incomplete","object":"response","created_at":1716399600,"status":"incomplete","incomplete_details":{"reason":"content_filter"},"model":"vendor-model","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"partial"}]}]}`)
	got, err := (&OpenAIAdapter{}).TransformResponseForEnvelope(chatResponsesBridgeEnvelope(), responses)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatal(err)
	}
	choice := body["choices"].([]any)[0].(map[string]any)
	if choice["finish_reason"] != "content_filter" {
		t.Fatalf("finish_reason=%v, want content_filter", choice["finish_reason"])
	}
}

func TestOpenAIAdapterChatResponsesBridgeCallUsesResponsesEndpoint(t *testing.T) {
	var gotPath, gotAuthorization string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthorization = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_call","object":"response","created_at":1716399600,"status":"completed","model":"vendor-model","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello from responses"}]}],"usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7}}`)
	}))
	defer server.Close()

	envelope := chatResponsesBridgeEnvelope()
	request, err := (&OpenAIAdapter{}).TransformRequest(envelope, []byte(`{"model":"logical-model","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&OpenAIAdapter{BaseURL: server.URL, APIKey: "test-key"}).Call(context.Background(), envelope, request)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/responses" || gotAuthorization != "Bearer test-key" {
		t.Fatalf("upstream request path/auth mismatch: path=%q authorization=%q", gotPath, gotAuthorization)
	}
	if gotBody["model"] != "vendor-model" {
		t.Fatalf("upstream model=%v", gotBody["model"])
	}
	input, ok := gotBody["input"].([]any)
	if !ok || len(input) != 1 || input[0].(map[string]any)["role"] != "user" {
		t.Fatalf("upstream input=%#v", gotBody["input"])
	}
	chatResponse, err := (&OpenAIAdapter{}).TransformResponseForEnvelope(envelope, response)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(chatResponse), `"content":"hello from responses"`) {
		t.Fatalf("converted Chat response=%s", chatResponse)
	}
}

func TestOpenAIAdapterChatResponsesBridgeStreamingUsesResponsesEndpoint(t *testing.T) {
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("path=%s want=/v1/responses", r.URL.Path)
		}
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"done\"}\n\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_2\",\"status\":\"completed\",\"model\":\"vendor-model\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"done\"}]}],\"usage\":{\"input_tokens\":2,\"output_tokens\":1,\"total_tokens\":3}}}\n\n")
	}))
	defer server.Close()

	envelope := chatResponsesBridgeEnvelope()
	request, err := (&OpenAIAdapter{}).TransformRequest(envelope, []byte(`{"model":"logical-model","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&OpenAIAdapter{BaseURL: server.URL, APIKey: "test-key"}).CallStreaming(context.Background(), envelope, request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gotBody), `"stream":true`) {
		t.Fatalf("stream flag missing: %s", gotBody)
	}
	chatBody, err := (&OpenAIAdapter{}).TransformResponseForEnvelope(envelope, got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(chatBody), `"content":"done"`) {
		t.Fatalf("converted streaming response=%s", chatBody)
	}
}

func TestOpenAIAdapterChatResponsesBridgeStreamingAcceptsDoneWithLargeResponse(t *testing.T) {
	largeText := strings.Repeat("x", 70*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		event, err := json.Marshal(map[string]any{
			"type": "response.done",
			"response": map[string]any{
				"id": "resp_large", "status": "completed", "model": "vendor-model",
				"output": []any{map[string]any{
					"type": "message", "role": "assistant",
					"content": []any{map[string]any{"type": "output_text", "text": largeText}},
				}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, "data: "+string(event)+"\n\n")
	}))
	defer server.Close()

	envelope := chatResponsesBridgeEnvelope()
	request, err := (&OpenAIAdapter{}).TransformRequest(envelope, []byte(`{"model":"logical-model","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&OpenAIAdapter{BaseURL: server.URL, APIKey: "test-key"}).CallStreaming(context.Background(), envelope, request)
	if err != nil {
		t.Fatalf("large response.done stream failed: %v", err)
	}
	if !strings.Contains(string(got), largeText) {
		t.Fatalf("large terminal response was not preserved")
	}
}

func TestOpenAIAdapterChatResponsesBridgeStreamingPropagatesResponseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.error\",\"response\":{\"error\":{\"message\":\"upstream failed\"}}}\n\n")
	}))
	defer server.Close()

	envelope := chatResponsesBridgeEnvelope()
	request, err := (&OpenAIAdapter{}).TransformRequest(envelope, []byte(`{"model":"logical-model","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&OpenAIAdapter{BaseURL: server.URL, APIKey: "test-key"}).CallStreaming(context.Background(), envelope, request)
	upstreamErr := GetUpstreamHTTPError(err)
	if upstreamErr == nil || upstreamErr.StatusCode != http.StatusBadGateway || upstreamErr.Message != "upstream failed" {
		t.Fatalf("response.error was not propagated: %v", err)
	}
}

func TestOpenAIAdapterChatResponsesBridgePreservesToolStrictFlag(t *testing.T) {
	got, err := (&OpenAIAdapter{}).TransformRequest(chatResponsesBridgeEnvelope(), []byte(`{"model":"logical-model","messages":[{"role":"user","content":"hello"}],"tools":[{"type":"function","function":{"name":"lookup_status","parameters":{"type":"object"},"strict":true}}]}`))
	if err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("bridge body is invalid JSON: %v", err)
	}
	tools, ok := body["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools=%#v", body["tools"])
	}
	tool, ok := tools[0].(map[string]any)
	if !ok {
		t.Fatalf("tool=%#v", tools[0])
	}
	if tool["strict"] != true {
		t.Fatalf("Responses bridge lost tool strict flag: %#v", tool)
	}
}

func TestOpenAIAdapterChatResponsesBridgeMatchesNewAPICompatibilitySemantics(t *testing.T) {
	raw := []byte(`{
		"model":"logical-model",
		"messages":[
			{"role":"system","content":"first"},
			{"role":"developer","content":"second"},
			{"role":"user","content":"hello"},
			{"role":"assistant","content":[{"type":"text","text":"checking"}],"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":{"ok":true,"items":[1,2]}},
			{"role":"function","content":["legacy","result"]},
			{"role":"user","content":[
				{"type":"input_audio","input_audio":{"data":"abc","format":"wav"}},
				{"type":"file","file":{"file_id":"file_1"}},
				{"type":"video_url","video_url":"https://example.invalid/v.mp4"},
				{"type":"vendor_part","value":"keep"}
			]}
		],
		"tools":[
			{"type":"function","function":{"name":"lookup","description":"lookup","parameters":{"type":"object"},"strict":true}},
			{"type":"custom","name":"shell","format":{"type":"grammar","syntax":"lark","definition":"start: /.+/"}}
		],
		"max_tokens":100,
		"max_completion_tokens":200,
		"frequency_penalty":0.1,
		"presence_penalty":0.2,
		"reasoning_effort":"high",
		"user":"user-1",
		"prompt_cache_key":"cache-1",
		"enable_thinking":true,
		"thinking_budget":4096
	}`)
	got, err := (&OpenAIAdapter{}).TransformRequest(chatResponsesBridgeEnvelope(), raw)
	if err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatal(err)
	}
	if body["max_output_tokens"] != float64(200) || body["frequency_penalty"] != 0.1 || body["presence_penalty"] != 0.2 {
		t.Fatalf("generation compatibility fields mismatch: %#v", body)
	}
	if body["user"] != "user-1" || body["prompt_cache_key"] != "cache-1" || body["enable_thinking"] != true || body["thinking_budget"] != float64(4096) {
		t.Fatalf("passthrough fields mismatch: %#v", body)
	}
	if body["instructions"] != "first\n\nsecond" {
		t.Fatalf("instructions mismatch: %#v", body["instructions"])
	}
	reasoning := body["reasoning"].(map[string]any)
	if reasoning["effort"] != "high" || reasoning["summary"] != "detailed" {
		t.Fatalf("reasoning mismatch: %#v", reasoning)
	}
	input := body["input"].([]any)
	assistantMessage := input[1].(map[string]any)
	assistantContent := assistantMessage["content"].([]any)
	if assistantContent[0].(map[string]any)["type"] != "output_text" {
		t.Fatalf("assistant history must use output_text: %#v", assistantMessage)
	}
	if input[2].(map[string]any)["type"] != "function_call" {
		t.Fatalf("assistant message must precede function call: %#v", input)
	}
	functionOutput := input[3].(map[string]any)
	if functionOutput["output"] != `{"items":[1,2],"ok":true}` {
		t.Fatalf("structured tool output was not JSON encoded: %#v", functionOutput)
	}
	missingCallID := input[4].(map[string]any)
	if missingCallID["role"] != "user" || !strings.Contains(missingCallID["content"].(string), "tool_output_missing_call_id") {
		t.Fatalf("legacy function output fallback mismatch: %#v", missingCallID)
	}
	multimodal := input[5].(map[string]any)["content"].([]any)
	for index, typ := range []string{"input_audio", "input_file", "input_video", "vendor_part"} {
		if multimodal[index].(map[string]any)["type"] != typ {
			t.Fatalf("multimodal part %d=%#v want type=%s", index, multimodal[index], typ)
		}
	}
	tools := body["tools"].([]any)
	functionTool := tools[0].(map[string]any)
	if functionTool["strict"] != true {
		t.Fatalf("function strict contract was lost: %#v", functionTool)
	}
	customTool := tools[1].(map[string]any)
	if customTool["type"] != "custom" || customTool["name"] != "shell" {
		t.Fatalf("custom tool was not preserved: %#v", customTool)
	}
}

func TestOpenAIAdapterChatResponsesBridgeRejectsMultipleChoices(t *testing.T) {
	_, err := (&OpenAIAdapter{}).TransformRequest(chatResponsesBridgeEnvelope(), []byte(`{"model":"logical-model","n":2,"messages":[{"role":"user","content":"hello"}]}`))
	if err == nil || !strings.Contains(err.Error(), "n>1") {
		t.Fatalf("n>1 must be rejected, got %v", err)
	}
}

func TestOpenAIAdapterChatResponsesBridgeMapsCustomToolCall(t *testing.T) {
	responses := []byte(`{"id":"resp_custom","status":"completed","model":"vendor-model","output":[{"type":"custom_tool_call","id":"ct_1","name":"shell","input":{"command":"pwd"}}],"usage":{"input_tokens":10,"output_tokens":2,"total_tokens":0,"input_tokens_details":{"cached_tokens":4},"output_tokens_details":{"reasoning_tokens":1}}}`)
	got, err := (&OpenAIAdapter{}).TransformResponseForEnvelope(chatResponsesBridgeEnvelope(), responses)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatal(err)
	}
	choice := body["choices"].([]any)[0].(map[string]any)
	if choice["finish_reason"] != "tool_calls" {
		t.Fatalf("finish_reason=%v", choice["finish_reason"])
	}
	tool := choice["message"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)
	if tool["id"] != "ct_1" || tool["type"] != "function" {
		t.Fatalf("custom tool mapping=%#v", tool)
	}
	if tool["function"].(map[string]any)["arguments"] != `{"command":"pwd"}` {
		t.Fatalf("custom tool input mapping=%#v", tool)
	}
	usage := body["usage"].(map[string]any)
	if usage["total_tokens"] != float64(12) || usage["prompt_tokens_details"].(map[string]any)["cached_tokens"] != float64(4) || usage["completion_tokens_details"].(map[string]any)["reasoning_tokens"] != float64(1) {
		t.Fatalf("usage mapping=%#v", usage)
	}
}
