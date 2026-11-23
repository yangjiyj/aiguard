package provider

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func transformChatForModel(t *testing.T, upstreamModel, body string) map[string]any {
	t.Helper()
	adapter := &AnthropicAdapter{}
	got, err := adapter.TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "chat", Model: "logical-claude", UpstreamModelID: upstreamModel}, []byte(body))
	if err != nil {
		t.Fatalf("TransformRequest(%s): %v", upstreamModel, err)
	}
	var request map[string]any
	if err := json.Unmarshal(got, &request); err != nil {
		t.Fatalf("decode transformed request: %v", err)
	}
	return request
}

func TestAnthropicChatCompatClampsMaxTokensToModelCeiling(t *testing.T) {
	// WorkBuddy/Codex 不认识模型时把上下文窗口当 max_tokens 发出来，
	// Anthropic 会 400 "max_tokens: 1000000 > 128000"。
	tests := []struct {
		model string
		body  string
		want  float64
	}{
		{"claude-opus-5", `{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":1000000}`, 128000},
		{"claude-opus-5-20260514", `{"model":"x","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":1000000}`, 128000},
		{"claude-haiku-4-5-20251001", `{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":200000}`, 64000},
		{"claude-opus-4-1-20250805", `{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":200000}`, 32000},
		{"claude-opus-9-preview", `{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":1000000}`, 128000},
		{"claude-opus-5", `{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":4096}`, 4096},
		{"vendor-alias-opus", `{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":1000000}`, 128000},
		{"claude-opus-5", `{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":null}`, 4096},
	}
	for _, tc := range tests {
		t.Run(tc.model+"/"+tc.body, func(t *testing.T) {
			request := transformChatForModel(t, tc.model, tc.body)
			if got, _ := request["max_tokens"].(float64); got != tc.want {
				t.Fatalf("max_tokens=%v, want %v: %#v", request["max_tokens"], tc.want, request)
			}
		})
	}
}

func TestAnthropicChatCompatMaxTokensEnvOverride(t *testing.T) {
	t.Setenv(anthropicMaxOutputTokensEnv, "vendor-alias=65536, claude-opus-5=32000")
	anthropicMaxOutputOverridesOnce.Do(func() {})
	loadAnthropicMaxOutputOverrides()
	t.Cleanup(func() { anthropicMaxOutputOverrides = nil })

	if got := resolveAnthropicModelProfile("vendor-alias-opus").MaxOutputTokens; got != 65536 {
		t.Fatalf("unlisted alias should take the operator ceiling, got %d", got)
	}
	if got := resolveAnthropicModelProfile("claude-opus-5").MaxOutputTokens; got != 32000 {
		t.Fatalf("operator ceiling should win over the built-in table, got %d", got)
	}
	if !resolveAnthropicModelProfile("claude-opus-5").RejectsSampling {
		t.Fatal("operator ceiling must not erase the family's other constraints")
	}
}

func TestAnthropicChatCompatDropsSamplingForCurrentModels(t *testing.T) {
	body := `{"model":"x","messages":[{"role":"user","content":"hi"}],"temperature":0.7,"top_p":1}`
	for _, model := range []string{"claude-opus-5", "claude-opus-4-8", "claude-opus-4-7", "claude-sonnet-5", "claude-fable-5-1"} {
		request := transformChatForModel(t, model, body)
		if _, has := request["temperature"]; has {
			t.Fatalf("%s: temperature must be dropped: %#v", model, request)
		}
		if _, has := request["top_p"]; has {
			t.Fatalf("%s: top_p must be dropped: %#v", model, request)
		}
	}
}

func TestAnthropicChatCompatKeepsOneSamplingControlForOlderModels(t *testing.T) {
	// Claude 4 系列 temperature/top_p 只能二选一；Anthropic 的 temperature 上限是 1。
	request := transformChatForModel(t, "claude-sonnet-4-5", `{"model":"x","messages":[{"role":"user","content":"hi"}],"temperature":1.5,"top_p":0.9}`)
	if got, _ := request["temperature"].(float64); got != 1 {
		t.Fatalf("temperature should be clamped to 1, got %#v", request["temperature"])
	}
	if _, has := request["top_p"]; has {
		t.Fatalf("top_p must not be sent alongside temperature: %#v", request)
	}
	request = transformChatForModel(t, "claude-sonnet-4-5", `{"model":"x","messages":[{"role":"user","content":"hi"}],"top_p":0.9}`)
	if got, _ := request["top_p"].(float64); got != 0.9 {
		t.Fatalf("lone top_p should be preserved, got %#v", request["top_p"])
	}
}

func TestAnthropicChatCompatDropsEmptyContent(t *testing.T) {
	body := `{
		"model":"x",
		"messages":[
			{"role":"system","content":"   "},
			{"role":"system","content":"Be precise"},
			{"role":"user","content":"look"},
			{"role":"assistant","content":[{"type":"text","text":""}],"tool_calls":[{"id":"call_1","type":"function","function":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]},
			{"role":"tool","tool_call_id":"call_1","content":[{"type":"text","text":""}]},
			{"role":"assistant","content":[{"type":"text","text":"  \n"}]},
			{"role":"assistant","content":""},
			{"role":"user","content":""},
			{"role":"user","content":[{"type":"text","text":"   "},{"type":"text","text":"continue"}]}
		],
		"max_tokens":256
	}`
	request := transformChatForModel(t, "claude-opus-5", body)
	if anthropicSystemText(request["system"]) != "Be precise" {
		t.Fatalf("whitespace-only system prompt must be skipped: %#v", request["system"])
	}
	messages, _ := request["messages"].([]any)
	if len(messages) != 4 {
		t.Fatalf("expected user/assistant/tool_result/user, got %d messages: %#v", len(messages), messages)
	}
	assistant := messages[1].(map[string]any)
	blocks, _ := assistant["content"].([]any)
	if len(blocks) != 1 || blocks[0].(map[string]any)["type"] != "tool_use" {
		t.Fatalf("empty assistant text block must be dropped but tool_use kept: %#v", assistant)
	}
	toolTurn := messages[2].(map[string]any)
	toolResult := toolTurn["content"].([]any)[0].(map[string]any)
	if toolResult["content"] != "" {
		t.Fatalf("empty tool result parts must collapse to an empty string: %#v", toolResult)
	}
	last := messages[3].(map[string]any)
	lastBlocks, _ := last["content"].([]any)
	if len(lastBlocks) != 1 || lastBlocks[0].(map[string]any)["text"] != "continue" {
		t.Fatalf("whitespace text blocks must be dropped from user content: %#v", last)
	}
}

func TestAnthropicChatCompatNormalizesThinkingByModelGeneration(t *testing.T) {
	tests := []struct {
		name         string
		model        string
		extra        string
		wantThinking string
		wantBudget   float64
		wantEffort   string
	}{
		{name: "budget thinking becomes adaptive on opus 5", model: "claude-opus-5", extra: `,"thinking":{"type":"enabled","budget_tokens":10000}`, wantThinking: "adaptive", wantEffort: "high"},
		{name: "explicit effort wins over budget", model: "claude-opus-5", extra: `,"thinking":{"type":"enabled","budget_tokens":10000},"reasoning_effort":"low"`, wantThinking: "adaptive", wantEffort: "low"},
		{name: "budget thinking stays on haiku 4.5", model: "claude-haiku-4-5", extra: `,"thinking":{"type":"enabled","budget_tokens":10000}`, wantThinking: "enabled", wantBudget: 10000},
		{name: "effort becomes budget on haiku 4.5", model: "claude-haiku-4-5", extra: `,"reasoning_effort":"high"`, wantThinking: "enabled", wantBudget: 16384},
		{name: "adaptive becomes budget on sonnet 4.5", model: "claude-sonnet-4-5", extra: `,"thinking":{"type":"adaptive"}`, wantThinking: "enabled", wantBudget: 8192},
		{name: "legacy enable_thinking keeps budget on haiku 4.5", model: "claude-haiku-4-5", extra: `,"enable_thinking":true,"thinking_budget":4096`, wantThinking: "enabled", wantBudget: 4096},
		{name: "disabled thinking is omitted on fable", model: "claude-fable-5-1", extra: `,"thinking":{"type":"disabled"}`},
		{name: "effort none is omitted on fable", model: "claude-fable-5-1", extra: `,"reasoning_effort":"none"`},
		{name: "disabled thinking drops effort on opus 5", model: "claude-opus-5", extra: `,"thinking":{"type":"disabled"},"reasoning_effort":"xhigh"`, wantThinking: "disabled"},
		{name: "unknown alias keeps current behaviour", model: "vendor-alias", extra: `,"enable_thinking":true,"thinking_budget":4096`, wantThinking: "adaptive", wantEffort: "medium"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := transformChatForModel(t, tc.model, `{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":64000`+tc.extra+`}`)
			thinking, _ := request["thinking"].(map[string]any)
			if gotType := compatStringValue(thinking["type"]); gotType != tc.wantThinking {
				t.Fatalf("thinking.type=%q, want %q: %#v", gotType, tc.wantThinking, request)
			}
			if gotBudget, _ := thinking["budget_tokens"].(float64); gotBudget != tc.wantBudget {
				t.Fatalf("budget_tokens=%v, want %v: %#v", thinking["budget_tokens"], tc.wantBudget, request)
			}
			outputConfig, _ := request["output_config"].(map[string]any)
			if gotEffort := compatStringValue(outputConfig["effort"]); gotEffort != tc.wantEffort {
				t.Fatalf("output_config.effort=%q, want %q: %#v", gotEffort, tc.wantEffort, request)
			}
		})
	}
}

func TestAnthropicChatCompatFitsLegacyThinkingBudgetUnderMaxTokens(t *testing.T) {
	request := transformChatForModel(t, "claude-haiku-4-5", `{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":2000,"reasoning_effort":"high"}`)
	thinking, _ := request["thinking"].(map[string]any)
	if got, _ := thinking["budget_tokens"].(float64); got != 1999 {
		t.Fatalf("budget_tokens must stay below max_tokens, got %#v", request)
	}
	request = transformChatForModel(t, "claude-haiku-4-5", `{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":1000,"reasoning_effort":"high"}`)
	if _, has := request["thinking"]; has {
		t.Fatalf("thinking that cannot fit the 1024 minimum must be omitted: %#v", request)
	}
}
