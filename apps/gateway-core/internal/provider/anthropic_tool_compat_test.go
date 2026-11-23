package provider

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestAnthropicAdapterTransformsOpenAIToolProtocolAndRestoresNames(t *testing.T) {
	adapter := &AnthropicAdapter{}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "claude-opus-5", UpstreamModelID: "vendor-opus"}
	raw := []byte(`{
		"model":"claude-opus-5",
		"messages":[
			{"role":"system","content":"Be precise"},
			{"role":"user","content":"Find it"},
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"Conversation Search","arguments":"{\"query\":\"needle\"}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":"{\"found\":true}"}
		],
		"max_tokens":256,
		"temperature":0.2,
		"top_p":0.9,
		"stop":["END"],
		"tools":[{"type":"function","function":{"name":"Conversation Search","description":"Search conversations","parameters":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}}],
		"tool_choice":{"type":"function","function":{"name":"Conversation Search"}},
		"parallel_tool_calls":false
	}`)

	got, err := adapter.TransformRequest(envelope, raw)
	if err != nil {
		t.Fatalf("TransformRequest: %v", err)
	}
	var request map[string]any
	if err := json.Unmarshal(got, &request); err != nil {
		t.Fatalf("decode transformed request: %v", err)
	}
	if request["model"] != "vendor-opus" || anthropicSystemText(request["system"]) != "Be precise" {
		t.Fatalf("unexpected model/system: %#v", request)
	}
	// claude-opus-5 拒绝非默认采样参数（400），转换层必须把它们丢掉而不是透传。
	if _, has := request["temperature"]; has {
		t.Fatalf("temperature must be dropped for claude-opus-5: %#v", request)
	}
	if _, has := request["top_p"]; has {
		t.Fatalf("top_p must be dropped for claude-opus-5: %#v", request)
	}
	stop, _ := request["stop_sequences"].([]any)
	if len(stop) != 1 || stop[0] != "END" {
		t.Fatalf("unexpected stop_sequences: %#v", request["stop_sequences"])
	}
	tools, _ := request["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("expected one Anthropic tool, got %#v", request["tools"])
	}
	tool := tools[0].(map[string]any)
	if tool["name"] != "Conversation_Search" || tool["description"] != "Search conversations" {
		t.Fatalf("unexpected tool identity: %#v", tool)
	}
	schema, _ := tool["input_schema"].(map[string]any)
	if schema["type"] != "object" {
		t.Fatalf("OpenAI parameters were not mapped to input_schema: %#v", schema)
	}
	choice, _ := request["tool_choice"].(map[string]any)
	if choice["type"] != "tool" || choice["name"] != "Conversation_Search" || choice["disable_parallel_tool_use"] != true {
		t.Fatalf("unexpected Anthropic tool_choice: %#v", choice)
	}
	messages, _ := request["messages"].([]any)
	if len(messages) != 3 {
		t.Fatalf("expected user, assistant tool_use, user tool_result; got %#v", messages)
	}
	assistant := messages[1].(map[string]any)
	toolUse := assistant["content"].([]any)[0].(map[string]any)
	if toolUse["type"] != "tool_use" || toolUse["id"] != "call_1" || toolUse["name"] != "Conversation_Search" {
		t.Fatalf("unexpected tool_use history: %#v", toolUse)
	}
	input := toolUse["input"].(map[string]any)
	if input["query"] != "needle" {
		t.Fatalf("tool arguments were not decoded: %#v", input)
	}
	toolResult := messages[2].(map[string]any)["content"].([]any)[0].(map[string]any)
	if toolResult["type"] != "tool_result" || toolResult["tool_use_id"] != "call_1" || toolResult["content"] != "{\"found\":true}" {
		t.Fatalf("unexpected tool_result history: %#v", toolResult)
	}

	response, err := adapter.TransformResponse([]byte(`{
		"id":"msg_1","model":"vendor-opus","stop_reason":"tool_use",
		"content":[{"type":"tool_use","id":"call_2","name":"Conversation_Search","input":{"query":"next"}}],
		"usage":{"input_tokens":10,"output_tokens":4}
	}`))
	if err != nil {
		t.Fatalf("TransformResponse: %v", err)
	}
	var chat map[string]any
	if err := json.Unmarshal(response, &chat); err != nil {
		t.Fatalf("decode transformed response: %v", err)
	}
	message := chat["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)
	function := message["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)
	if function["name"] != "Conversation Search" || function["arguments"] != "{\"query\":\"next\"}" {
		t.Fatalf("unexpected restored tool call: %#v", function)
	}
}

func TestAnthropicAdapterMapsOpenAIToolChoiceModes(t *testing.T) {
	tests := []struct {
		name, choiceJSON, wantType string
		wantChoice                 bool
	}{
		{name: "auto", choiceJSON: `"auto"`, wantType: "auto", wantChoice: true},
		{name: "required", choiceJSON: `"required"`, wantType: "any", wantChoice: true},
		{name: "none", choiceJSON: `"none"`, wantType: "none", wantChoice: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &AnthropicAdapter{}
			raw := []byte(`{"model":"claude","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}],"tool_choice":` + tc.choiceJSON + `}`)
			got, err := adapter.TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "chat", Model: "claude"}, raw)
			if err != nil {
				t.Fatalf("TransformRequest: %v", err)
			}
			var request map[string]any
			if err := json.Unmarshal(got, &request); err != nil {
				t.Fatal(err)
			}
			choice, exists := request["tool_choice"].(map[string]any)
			if exists != tc.wantChoice {
				t.Fatalf("tool_choice presence=%v, want %v: %#v", exists, tc.wantChoice, request)
			}
			if tc.wantChoice && choice["type"] != tc.wantType {
				t.Fatalf("tool_choice type=%v, want %s", choice["type"], tc.wantType)
			}
		})
	}
}

func TestAnthropicAdapterTransformsCustomToolCallAndResult(t *testing.T) {
	adapter := &AnthropicAdapter{}
	raw := []byte(`{
		"model":"claude-opus-5",
		"messages":[
			{"role":"assistant","content":null,"tool_calls":[{"id":"custom_1","type":"custom","custom":{"name":"shell command","input":"pwd"}}]},
			{"role":"tool","tool_call_id":"custom_1","content":"/workspace"}
		],
		"tools":[{"type":"custom","custom":{"name":"shell command","description":"run command","input_schema":{"type":"object"}}}]
	}`)
	got, err := adapter.TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "chat", Model: "claude-opus-5"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if err := json.Unmarshal(got, &request); err != nil {
		t.Fatal(err)
	}
	tools := request["tools"].([]any)
	if tools[0].(map[string]any)["name"] != "shell_command" {
		t.Fatalf("custom tool name was not normalized: %#v", tools)
	}
	messages := request["messages"].([]any)
	use := messages[0].(map[string]any)["content"].([]any)[0].(map[string]any)
	if use["type"] != "tool_use" || use["id"] != "custom_1" || use["name"] != "shell_command" || use["input"].(map[string]any)["input"] != "pwd" {
		t.Fatalf("custom tool use=%#v", use)
	}
	result := messages[1].(map[string]any)["content"].([]any)[0].(map[string]any)
	if result["type"] != "tool_result" || result["tool_use_id"] != "custom_1" {
		t.Fatalf("custom tool result=%#v", result)
	}
}

func TestAnthropicAdapterSerializesStructuredToolResult(t *testing.T) {
	adapter := &AnthropicAdapter{}
	raw := []byte(`{
		"model":"logical-claude",
		"messages":[
			{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":{"ok":true,"items":[1,2]}}
		]
	}`)
	got, err := adapter.TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "chat", UpstreamModelID: "vendor-claude"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if err := json.Unmarshal(got, &request); err != nil {
		t.Fatal(err)
	}
	messages := request["messages"].([]any)
	toolResult := messages[1].(map[string]any)["content"].([]any)[0].(map[string]any)
	if toolResult["content"] != `{"items":[1,2],"ok":true}` {
		t.Fatalf("structured tool result was dropped or malformed: %#v", toolResult)
	}
}

func TestAnthropicAdapterMapsOpenAIReasoningControls(t *testing.T) {
	tests := []struct {
		name         string
		extra        string
		wantThinking string
		wantEffort   string
	}{
		{name: "reasoning effort", extra: `,"reasoning_effort":"high"`, wantEffort: "high"},
		{name: "nested reasoning effort", extra: `,"reasoning":{"effort":"xhigh"}`, wantEffort: "xhigh"},
		{name: "legacy budget", extra: `,"enable_thinking":true,"thinking_budget":4096`, wantThinking: "adaptive", wantEffort: "medium"},
		{name: "disable reasoning", extra: `,"reasoning_effort":"none"`, wantThinking: "disabled"},
		{name: "native adaptive thinking", extra: `,"thinking":{"type":"adaptive"}`, wantThinking: "adaptive"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &AnthropicAdapter{}
			raw := []byte(`{"model":"logical-claude","messages":[{"role":"user","content":"hi"}]` + tc.extra + `}`)
			got, err := adapter.TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "chat", UpstreamModelID: "claude-opus-5"}, raw)
			if err != nil {
				t.Fatal(err)
			}
			var request map[string]any
			if err := json.Unmarshal(got, &request); err != nil {
				t.Fatal(err)
			}
			thinking, _ := request["thinking"].(map[string]any)
			if gotType := compatStringValue(thinking["type"]); gotType != tc.wantThinking {
				t.Fatalf("thinking.type=%q, want %q: %#v", gotType, tc.wantThinking, request)
			}
			outputConfig, _ := request["output_config"].(map[string]any)
			if gotEffort := compatStringValue(outputConfig["effort"]); gotEffort != tc.wantEffort {
				t.Fatalf("output_config.effort=%q, want %q: %#v", gotEffort, tc.wantEffort, request)
			}
		})
	}
}

func TestAnthropicAdapterRejectsUnsupportedReasoningEffort(t *testing.T) {
	adapter := &AnthropicAdapter{}
	_, err := adapter.TransformRequest(
		&modelrouter.RequestEnvelope{EndpointType: "chat", UpstreamModelID: "claude-opus-5"},
		[]byte(`{"model":"logical-claude","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"extreme"}`),
	)
	if err == nil {
		t.Fatal("unsupported reasoning effort should fail before the upstream request")
	}
}
