package provider

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func transformChatPromptCache(t *testing.T, body string) (map[string]any, []byte) {
	t.Helper()
	raw, _, err := transformOpenAIChatToAnthropic(nil, []byte(body))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	var request map[string]any
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return request, raw
}

func cacheMarkerOf(t *testing.T, value any) map[string]any {
	t.Helper()
	block, _ := value.(map[string]any)
	marker, _ := block["cache_control"].(map[string]any)
	return marker
}

const promptCacheConversation = `{
	"model":"claude-opus-4-8",
	"messages":[
		{"role":"system","content":"You are CodeBuddy."},
		{"role":"user","content":"read main.go"},
		{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"main.go\"}"}}]},
		{"role":"tool","tool_call_id":"call_1","content":"package main"},
		{"role":"assistant","content":"done"},
		{"role":"user","content":[{"type":"text","text":"now explain"}]}
	],
	"tools":[{"type":"function","function":{"name":"read_file","parameters":{"type":"object","properties":{"path":{"type":"string"}}}}}]
}`

func TestAnthropicChatPromptCacheAddsBreakpoints(t *testing.T) {
	request, _ := transformChatPromptCache(t, promptCacheConversation)

	system, ok := request["system"].([]any)
	if !ok || len(system) != 1 {
		t.Fatalf("system must become one text block with a breakpoint: %#v", request["system"])
	}
	block := system[0].(map[string]any)
	if block["text"] != "You are CodeBuddy." || cacheMarkerOf(t, block)["type"] != "ephemeral" {
		t.Fatalf("unexpected system block: %#v", block)
	}

	messages := request["messages"].([]any)
	if len(messages) != 5 {
		t.Fatalf("unexpected message count %d: %#v", len(messages), messages)
	}
	last := messages[4].(map[string]any)["content"].([]any)
	if cacheMarkerOf(t, last[len(last)-1])["type"] != "ephemeral" {
		t.Fatalf("last message must carry a breakpoint: %#v", last)
	}
	// 上一轮请求的结尾是 tool_result 那条 user 消息，必须打标记才能读到上一轮写入的缓存。
	toolTurn := messages[2].(map[string]any)["content"].([]any)
	if toolTurn[0].(map[string]any)["type"] != "tool_result" || cacheMarkerOf(t, toolTurn[0])["type"] != "ephemeral" {
		t.Fatalf("previous user turn must carry a breakpoint: %#v", toolTurn)
	}
	first := messages[0].(map[string]any)
	if first["content"] != "read main.go" {
		t.Fatalf("earlier messages must stay untouched: %#v", first)
	}
	if got := countAnthropicCacheBreakpoints(request); got != 3 {
		t.Fatalf("breakpoints=%d, want 3", got)
	}
}

func TestAnthropicChatPromptCachePrefixIsDeterministic(t *testing.T) {
	_, first := transformChatPromptCache(t, promptCacheConversation)
	_, second := transformChatPromptCache(t, promptCacheConversation)
	if !bytes.Equal(first, second) {
		t.Fatalf("same request must encode identically:\n%s\n%s", first, second)
	}
}

func TestAnthropicChatPromptCacheRespectsClientBreakpoints(t *testing.T) {
	body := `{"model":"claude","messages":[
		{"role":"system","content":[{"type":"text","text":"sys","cache_control":{"type":"ephemeral","ttl":"1h"}}]},
		{"role":"user","content":"hi"}
	]}`
	request, _ := transformChatPromptCache(t, body)
	system := request["system"].([]any)
	if cacheMarkerOf(t, system[0])["ttl"] != "1h" {
		t.Fatalf("client system breakpoint must survive flattening: %#v", system)
	}
	messages := request["messages"].([]any)
	if messages[0].(map[string]any)["content"] != "hi" {
		t.Fatalf("client-managed caching must not get extra breakpoints: %#v", messages)
	}
	if got := countAnthropicCacheBreakpoints(request); got != 1 {
		t.Fatalf("breakpoints=%d, want 1", got)
	}
}

func TestAnthropicChatPromptCacheTopLevelMarkerNeverExceedsLimit(t *testing.T) {
	body := `{"model":"claude","cache_control":{"type":"ephemeral","ttl":"1h"},"messages":[
		{"role":"system","content":"sys"},
		{"role":"user","content":[{"type":"text","text":"a","cache_control":{"type":"ephemeral"}}]},
		{"role":"assistant","content":[{"type":"text","text":"b","cache_control":{"type":"ephemeral"}}]},
		{"role":"user","content":[{"type":"text","text":"c","cache_control":{"type":"ephemeral"}}]},
		{"role":"assistant","content":"d"},
		{"role":"user","content":"e"}
	]}`
	request, raw := transformChatPromptCache(t, body)
	if _, has := request["cache_control"]; has {
		t.Fatalf("top-level cache_control must not be forwarded: %s", raw)
	}
	if got := countAnthropicCacheBreakpoints(request); got != anthropicMaxCacheBreakpoints {
		t.Fatalf("breakpoints=%d, want %d: %s", got, anthropicMaxCacheBreakpoints, raw)
	}
	system := request["system"].([]any)
	if cacheMarkerOf(t, system[0])["ttl"] != "1h" {
		t.Fatalf("top-level marker value must be reused: %#v", system)
	}
}

func TestAnthropicChatPromptCacheSkipsThinkingBlocks(t *testing.T) {
	request := map[string]any{"messages": []any{
		map[string]any{"role": "assistant", "content": []any{
			map[string]any{"type": "text", "text": "x"},
			map[string]any{"type": "thinking", "thinking": "y", "signature": "s"},
		}},
	}}
	applyAnthropicChatPromptCache(request, nil)
	blocks := request["messages"].([]any)[0].(map[string]any)["content"].([]any)
	if _, has := blocks[1].(map[string]any)["cache_control"]; has {
		t.Fatalf("thinking block must not carry cache_control: %#v", blocks)
	}
	if cacheMarkerOf(t, blocks[0])["type"] != "ephemeral" {
		t.Fatalf("text block before thinking must carry the breakpoint: %#v", blocks)
	}
}

func TestAnthropicChatPromptCacheCanBeDisabled(t *testing.T) {
	t.Setenv(anthropicChatPromptCacheEnv, "off")
	request, raw := transformChatPromptCache(t, promptCacheConversation)
	if request["system"] != "You are CodeBuddy." || strings.Contains(string(raw), "cache_control") {
		t.Fatalf("disabled switch must keep the legacy shape: %s", raw)
	}
}

func TestAnthropicChatPromptCacheKeepsToolBreakpoint(t *testing.T) {
	t.Setenv(anthropicChatPromptCacheEnv, "off")
	body := `{"model":"claude","messages":[{"role":"user","content":"hi"}],
		"tools":[{"type":"function","cache_control":{"type":"ephemeral"},"function":{"name":"t1","parameters":{"type":"object"}}}]}`
	request, _ := transformChatPromptCache(t, body)
	tools := request["tools"].([]any)
	if cacheMarkerOf(t, tools[0])["type"] != "ephemeral" {
		t.Fatalf("tool-level cache_control must be preserved: %#v", tools)
	}
}
