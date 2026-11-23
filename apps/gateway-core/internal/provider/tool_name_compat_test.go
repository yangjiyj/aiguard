package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

func TestOpenAIAdapterNormalizesAndRestoresCompatibleToolNames(t *testing.T) {
	t.Parallel()

	adapter := &OpenAIAdapter{}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "claude-opus-5"}
	raw := []byte(`{
		"model":"claude-opus-5",
		"messages":[
			{"role":"user","content":"search"},
			{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"Conversation Search","arguments":"{}"}}]}
		],
		"tools":[
			{"type":"function","function":{"name":"Conversation Search","description":"search","parameters":{"type":"object"}}},
			{"type":"function","function":{"name":"file_read","description":"valid","parameters":{"type":"object"}}},
			{"type":"function","function":{"name":"file-read","description":"collision","parameters":{"type":"object"}}},
			{"type":"function","function":{"name":"123.run","description":"leading digit","parameters":{"type":"object"}}}
		],
		"tool_choice":{"type":"function","function":{"name":"Conversation Search"}}
	}`)

	got, err := adapter.TransformRequest(envelope, raw)
	if err != nil {
		t.Fatalf("TransformRequest() error = %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("decode transformed body: %v", err)
	}
	tools := body["tools"].([]any)
	conversationName := chatToolName(tools[0])
	if conversationName != "Conversation_Search" {
		t.Fatalf("Conversation Search normalized to %q", conversationName)
	}
	if got := chatToolName(tools[1]); got != "file_read" {
		t.Fatalf("valid tool name changed to %q", got)
	}
	if got := chatToolName(tools[2]); got == "file_read" || !isKiroCompatibleToolName(got) {
		t.Fatalf("collision was not disambiguated: %q", got)
	}
	if got := chatToolName(tools[3]); got != "tool_123_run" {
		t.Fatalf("leading digit normalized to %q", got)
	}

	messages := body["messages"].([]any)
	historyCall := messages[1].(map[string]any)["tool_calls"].([]any)[0]
	if got := chatToolCallName(historyCall); got != conversationName {
		t.Fatalf("history tool call name = %q, want %q", got, conversationName)
	}
	choice := body["tool_choice"].(map[string]any)
	if got := choice["function"].(map[string]any)["name"]; got != conversationName {
		t.Fatalf("tool_choice name = %v, want %q", got, conversationName)
	}

	upstream := []byte(`{"id":"chatcmpl_1","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"call_2","type":"function","function":{"name":"Conversation_Search","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`)
	restored, err := adapter.TransformResponse(upstream)
	if err != nil {
		t.Fatalf("TransformResponse() error = %v", err)
	}
	var response map[string]any
	if err := json.Unmarshal(restored, &response); err != nil {
		t.Fatalf("decode restored response: %v", err)
	}
	responseCall := response["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["tool_calls"].([]any)[0]
	if got := chatToolCallName(responseCall); got != "Conversation Search" {
		t.Fatalf("restored tool name = %q", got)
	}
}

func TestOpenAIAdapterPreservesCompatibleRequestBytes(t *testing.T) {
	t.Parallel()

	adapter := &OpenAIAdapter{}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "gpt"}
	raw := []byte(`{ "model": "gpt", "messages": [{"role":"user","content":"hi"}], "tools": [{"type":"function","function":{"name":"read_file"}}] }`)
	got, err := adapter.TransformRequest(envelope, raw)
	if err != nil {
		t.Fatalf("TransformRequest() error = %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("compatible request was rewritten:\n%s", got)
	}
}

func TestCompatibleToolNameMapBoundsAndRestoresNames(t *testing.T) {
	t.Parallel()

	longName := "search." + strings.Repeat("nested-tool/", 10)
	nameMap := newCompatibleToolNameMap([]string{longName, "工具搜索"})
	for _, original := range []string{longName, "工具搜索"} {
		wireName := nameMap.compatible(original)
		if !isKiroCompatibleToolName(wireName) {
			t.Fatalf("wire name %q is not Kiro compatible", wireName)
		}
		if len(wireName) > kiroToolNameMaxBytes {
			t.Fatalf("wire name is %d bytes", len(wireName))
		}
		if got := nameMap.original(wireName); got != original {
			t.Fatalf("restored name = %q, want %q", got, original)
		}
	}
}

func TestOpenAIAdapterRestoresResponsesBridgeToolName(t *testing.T) {
	t.Parallel()

	adapter := &OpenAIAdapter{}
	envelope := chatResponsesBridgeEnvelope()
	raw := []byte(`{"model":"logical-model","messages":[{"role":"user","content":"search"}],"tools":[{"type":"function","function":{"name":"Conversation Search","parameters":{"type":"object"}}}]}`)
	providerReq, err := adapter.TransformRequest(envelope, raw)
	if err != nil {
		t.Fatalf("TransformRequest() error = %v", err)
	}
	var responsesRequest map[string]any
	if err := json.Unmarshal(providerReq, &responsesRequest); err != nil {
		t.Fatalf("decode Responses request: %v", err)
	}
	tool := responsesRequest["tools"].([]any)[0].(map[string]any)
	if got := tool["name"]; got != "Conversation_Search" {
		t.Fatalf("Responses wire tool name = %v", got)
	}

	upstream := []byte(`{"id":"resp_1","status":"completed","model":"vendor-model","output":[{"type":"function_call","id":"call_1","name":"Conversation_Search","arguments":"{}"}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
	chatBody, err := adapter.TransformResponseForEnvelope(envelope, upstream)
	if err != nil {
		t.Fatalf("TransformResponseForEnvelope() error = %v", err)
	}
	var response map[string]any
	if err := json.Unmarshal(chatBody, &response); err != nil {
		t.Fatalf("decode Chat response: %v", err)
	}
	call := response["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["tool_calls"].([]any)[0]
	if got := chatToolCallName(call); got != "Conversation Search" {
		t.Fatalf("restored Responses bridge name = %q", got)
	}
}

func TestOpenAIAdapterRestoresToolNameInLiveStream(t *testing.T) {
	t.Parallel()

	var receivedName string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode upstream request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receivedName = chatToolName(body["tools"].([]any)[0])
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl_1\",\"model\":\"claude-opus-5\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"Conversation_Search\",\"arguments\":\"{}\"}}]}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl_1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{BaseURL: server.URL, APIKey: "test-key"}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "claude-opus-5"}
	raw := []byte(`{"model":"claude-opus-5","messages":[{"role":"user","content":"search"}],"tools":[{"type":"function","function":{"name":"Conversation Search"}}]}`)
	providerReq, err := adapter.TransformRequest(envelope, raw)
	if err != nil {
		t.Fatalf("TransformRequest() error = %v", err)
	}
	reader, _, err := adapter.OpenStream(context.Background(), envelope, providerReq)
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	defer reader.Close()

	var toolName string
	for {
		event, nextErr := reader.Next(context.Background())
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			t.Fatalf("Next() error = %v", nextErr)
		}
		if event.Type == relay.EventToolCallStart && event.ToolCall != nil {
			toolName = event.ToolCall.Name
		}
	}
	if receivedName != "Conversation_Search" {
		t.Fatalf("upstream tool name = %q", receivedName)
	}
	if toolName != "Conversation Search" {
		t.Fatalf("streamed tool name = %q", toolName)
	}
}

func chatToolName(raw any) string {
	tool, _ := raw.(map[string]any)
	function, _ := tool["function"].(map[string]any)
	name, _ := function["name"].(string)
	return name
}

func chatToolCallName(raw any) string {
	return chatToolName(raw)
}
