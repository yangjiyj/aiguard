package provider

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func messagesResponsesEnvelope() *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{
		Model: "customer-coding", UpstreamModelID: "gpt-upstream",
		EndpointType: "messages", UpstreamProtocol: "responses",
		ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, ResponsesNative: true},
	}
}

func TestMessagesResponsesBridgePreservesToolsMediaReasoningAndSchema(t *testing.T) {
	input := []byte(`{
		"model":"customer-coding","max_tokens":2048,
		"thinking":{"type":"adaptive"},
		"output_config":{"effort":"high","format":{"type":"json_schema","schema":{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"],"additionalProperties":false}}},
		"system":[{"type":"text","text":"be precise"}],
		"tools":[{"name":"lookup","description":"find it","input_schema":{"type":"object","properties":{"q":{"type":"string"}}}}],
		"messages":[
			{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"lookup","input":{"q":"x"}}]},
			{"role":"user","content":[
				{"type":"tool_result","tool_use_id":"toolu_1","content":"done"},
				{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aQ=="}},
				{"type":"document","title":"note.txt","source":{"type":"text","text":"hello"}}
			]}
		]
	}`)
	got, err := (&OpenAIAdapter{}).TransformRequest(messagesResponsesEnvelope(), input)
	if err != nil {
		t.Fatalf("TransformRequest() error = %v", err)
	}
	var request map[string]any
	if err := json.Unmarshal(got, &request); err != nil {
		t.Fatalf("unmarshal transformed request: %v", err)
	}
	if request["model"] != "gpt-upstream" || request["instructions"] != "be precise" {
		t.Fatalf("request identity = %#v", request)
	}
	if request["reasoning"].(map[string]any)["effort"] != "high" {
		t.Fatalf("reasoning = %#v", request["reasoning"])
	}
	format := request["text"].(map[string]any)["format"].(map[string]any)
	if format["type"] != "json_schema" || format["name"] != "anthropic_messages_output" {
		t.Fatalf("format = %#v", format)
	}
	encoded := string(got)
	for _, wanted := range []string{"function_call", "function_call_output", "input_image", "input_file"} {
		if !strings.Contains(encoded, string('"')+wanted+string('"')) {
			t.Fatalf("transformed request missing %q: %s", wanted, encoded)
		}
	}
}

func TestMessagesResponsesBridgeRestoresAnthropicResponse(t *testing.T) {
	upstream := []byte(`{
		"id":"resp_1","status":"completed","model":"gpt-upstream",
		"output":[
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]},
			{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{\"q\":\"x\"}"}
		],
		"usage":{"input_tokens":12,"output_tokens":7,"total_tokens":19}
	}`)
	got, err := (&OpenAIAdapter{}).TransformResponseForEnvelope(messagesResponsesEnvelope(), upstream)
	if err != nil {
		t.Fatalf("TransformResponseForEnvelope() error = %v", err)
	}
	var response map[string]any
	if err := json.Unmarshal(got, &response); err != nil {
		t.Fatal(err)
	}
	if response["type"] != "message" || response["role"] != "assistant" || response["model"] != "customer-coding" {
		t.Fatalf("response identity = %#v", response)
	}
	content := response["content"].([]any)
	if len(content) != 2 || content[0].(map[string]any)["type"] != "text" || content[1].(map[string]any)["type"] != "tool_use" {
		t.Fatalf("content = %#v", content)
	}
	usage := response["usage"].(map[string]any)
	if usage["input_tokens"] != float64(12) || usage["output_tokens"] != float64(7) {
		t.Fatalf("usage = %#v", usage)
	}
}

func TestMessagesResponsesBridgeRestoresAnthropicSSE(t *testing.T) {
	envelope := messagesResponsesEnvelope()
	envelope.Streaming = true
	upstream := []byte(`{"id":"resp_1","status":"completed","model":"gpt-upstream","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]}],"usage":{"input_tokens":12,"output_tokens":7}}`)
	got, err := (&OpenAIAdapter{}).TransformResponseForEnvelope(envelope, upstream)
	if err != nil {
		t.Fatalf("TransformResponseForEnvelope() error = %v", err)
	}
	text := string(got)
	for _, wanted := range []string{"event: message_start", "event: content_block_delta", "\"text\":\"done\"", "event: message_stop"} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("SSE missing %q: %s", wanted, text)
		}
	}
}

func TestMessagesBridgeRejectsModelBoundThinkingHistory(t *testing.T) {
	input := []byte(`{"model":"customer-coding","messages":[
		{"role":"assistant","content":[{"type":"thinking","thinking":"secret","signature":"sig"}]},
		{"role":"user","content":"continue"}]}`)
	_, err := (&OpenAIAdapter{}).TransformRequest(messagesResponsesEnvelope(), input)
	if err == nil || !errors.Is(err, ErrEndpointNotSupported) {
		t.Fatalf("error = %v, want endpoint-not-supported", err)
	}
}

func TestChatToAnthropicStructuredOutputMergesEffort(t *testing.T) {
	envelope := &modelrouter.RequestEnvelope{Model: "logical", UpstreamModelID: "claude-upstream"}
	input := []byte(`{
		"model":"logical","messages":[{"role":"user","content":"answer"}],
		"reasoning_effort":"xhigh",
		"response_format":{"type":"json_schema","json_schema":{"name":"answer","strict":true,"schema":{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"]}}}
	}`)
	got, _, err := transformOpenAIChatToAnthropic(envelope, input)
	if err != nil {
		t.Fatalf("transformOpenAIChatToAnthropic() error = %v", err)
	}
	var request map[string]any
	if err := json.Unmarshal(got, &request); err != nil {
		t.Fatal(err)
	}
	output := request["output_config"].(map[string]any)
	if output["effort"] != "xhigh" {
		t.Fatalf("effort = %#v", output["effort"])
	}
	format := output["format"].(map[string]any)
	if format["type"] != "json_schema" || format["schema"] == nil {
		t.Fatalf("format = %#v", format)
	}
	if _, leaked := format["name"]; leaked {
		t.Fatalf("OpenAI-only schema name leaked to Anthropic: %#v", format)
	}
}

func TestMessagesBridgeDropsCacheControlHintsWithoutError(t *testing.T) {
	raw := []byte(`{"model":"m","max_tokens":16,
"system":[{"type":"text","text":"sys","cache_control":{"type":"ephemeral"}}],
"tools":[{"name":"t","description":"d","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral"}}],
"messages":[
 {"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]},
 {"role":"assistant","content":[{"type":"tool_use","id":"c1","name":"t","input":{},"cache_control":{"type":"ephemeral"}}]},
 {"role":"user","content":[{"type":"tool_result","tool_use_id":"c1","content":[{"type":"text","text":"ok","cache_control":{"type":"ephemeral"}}],"cache_control":{"type":"ephemeral"}}]}
]}`)
	body, err := transformAnthropicMessagesToChat(nil, raw)
	if err != nil {
		t.Fatalf("cache_control hints must not break the bridge: %v", err)
	}
	if strings.Contains(string(body), "cache_control") {
		t.Fatalf("cache_control leaked to the OpenAI upstream: %s", body)
	}
}

// 新版 Claude Code 每个请求都带 context_management（清理 thinking 的上下文编辑提示）。
// 它是 Anthropic 专有的优化提示，对 OpenAI 上游没有等价物，丢弃不改变语义；
// 之前桥接器把它当成“没有安全映射的字段”直接拒绝，导致整条路由 503。
func TestMessagesBridgeDropsContextManagementHint(t *testing.T) {
	raw := []byte(`{"model":"m","max_tokens":16,
"context_management":{"edits":[{"type":"clear_thinking_20251015","keep":"all"}]},
"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)
	body, err := transformAnthropicMessagesToChat(nil, raw)
	if err != nil {
		t.Fatalf("context_management must not break the bridge: %v", err)
	}
	if strings.Contains(string(body), "context_management") {
		t.Fatalf("context_management leaked to the OpenAI upstream: %s", body)
	}
}

// 其他没有安全映射的字段仍然必须被拒绝，不能因为放行 context_management 而放宽白名单。
func TestMessagesBridgeStillRejectsUnknownTopLevelFields(t *testing.T) {
	raw := []byte(`{"model":"m","max_tokens":16,"container":"abc","messages":[{"role":"user","content":"hi"}]}`)
	if _, err := transformAnthropicMessagesToChat(nil, raw); err == nil {
		t.Fatal("unknown top-level field must still be rejected")
	}
}

// 新版 Claude Code 把运行环境信息放在 messages 里的一条 role=system 消息中（不是顶层 system）。
// 桥接器之前只认 user/assistant，整个请求被拒，网关返回 503。这条信息必须保留给上游模型，
// 所以映射成上游的 system 消息，而不是丢弃。
func TestMessagesBridgeMapsInlineSystemMessage(t *testing.T) {
	raw := []byte(`{"model":"m","max_tokens":16,
"messages":[
 {"role":"user","content":[{"type":"text","text":"ok"}]},
 {"role":"system","content":[{"type":"text","text":"# Environment\nPlatform: win32","cache_control":{"type":"ephemeral"}}]}
]}`)
	body, err := transformAnthropicMessagesToChat(nil, raw)
	if err != nil {
		t.Fatalf("inline system message must not break the bridge: %v", err)
	}
	var request map[string]any
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	messages := request["messages"].([]any)
	if len(messages) != 2 {
		t.Fatalf("messages = %v", messages)
	}
	system := messages[1].(map[string]any)
	if system["role"] != "system" || !strings.Contains(system["content"].(string), "Platform: win32") {
		t.Fatalf("system text lost or role changed: %v", system)
	}
}

func TestMessagesBridgeInlineSystemAcceptsPlainString(t *testing.T) {
	raw := []byte(`{"model":"m","max_tokens":16,"messages":[{"role":"system","content":"plain"},{"role":"user","content":"hi"}]}`)
	body, err := transformAnthropicMessagesToChat(nil, raw)
	if err != nil || !strings.Contains(string(body), `"role":"system"`) || !strings.Contains(string(body), "plain") {
		t.Fatalf("plain-string inline system rejected or lost: %v %s", err, body)
	}
}

// system 消息里的非文本块没有安全映射，仍然必须拒绝，不能静默丢掉。
func TestMessagesBridgeInlineSystemStillRejectsNonText(t *testing.T) {
	raw := []byte(`{"model":"m","max_tokens":16,"messages":[{"role":"system","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aQ=="}}]},{"role":"user","content":"hi"}]}`)
	if _, err := transformAnthropicMessagesToChat(nil, raw); err == nil {
		t.Fatal("non-text block in an inline system message must still be rejected")
	}
}

// 其他未知角色仍然拒绝。
func TestMessagesBridgeStillRejectsUnknownRole(t *testing.T) {
	raw := []byte(`{"model":"m","max_tokens":16,"messages":[{"role":"tool","content":"x"}]}`)
	if _, err := transformAnthropicMessagesToChat(nil, raw); err == nil {
		t.Fatal("unknown role must still be rejected")
	}
}
