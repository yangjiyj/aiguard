package handler

import (
	"strings"
	"testing"
)

// 准入预留的输入估算必须覆盖 assistant 历史里的 tool_calls（函数名 + 参数）。
// 编程助手的历史里常带有大段 write_file / patch 参数，漏算会让每次请求的预留系统性偏低，
// 结算时实际用量超出预留，于是产生一条 quota.admission.reservation_overrun 通知。
func TestEstimateChatPromptTokensCountsAssistantToolCalls(t *testing.T) {
	arguments := strings.Repeat("a", 30000)
	request := &ChatCompletionRequest{Messages: []Message{
		{Role: "user", Content: jsonQuote("hi")},
		{Role: "assistant", ToolCalls: []ToolCall{{ID: "call_1", Type: "function", Function: ToolCallFunc{Name: "write_file", Arguments: arguments}}}},
	}}
	got := estimateChatPromptTokens(request)
	floor := estimateTextTokens(arguments)
	if got < floor {
		t.Fatalf("tool_call 参数被漏算: estimate=%d, 仅参数文本就需要 >= %d", got, floor)
	}
	if got > floor+200 {
		t.Fatalf("tool_call 估算偏离过大: estimate=%d, 参数文本 %d", got, floor)
	}
}

func TestEstimateChatPromptTokensCountsToolCallNameAndCJKArguments(t *testing.T) {
	arguments := strings.Repeat("写", 600)
	request := &ChatCompletionRequest{Messages: []Message{
		{Role: "assistant", ToolCalls: []ToolCall{{ID: "call_1", Type: "function", Function: ToolCallFunc{Name: strings.Repeat("n", 90), Arguments: arguments}}}},
	}}
	got := estimateChatPromptTokens(request)
	floor := estimateTextTokens(arguments) + estimateTextTokens(strings.Repeat("n", 90))
	if got < floor {
		t.Fatalf("estimate=%d, want >= %d (参数 + 函数名)", got, floor)
	}
}

// 原生 Messages 的 tool_use 会同时出现在 Content（参数文本）和 ToolCalls（同一份参数）里，
// 不能因为补算 tool_calls 而把同一份参数算两遍，否则会误拒余额少的用户。
func TestEstimateChatPromptTokensDoesNotDoubleCountNativeToolUse(t *testing.T) {
	arguments := strings.Repeat("a", 3000)
	native := &ChatCompletionRequest{Messages: []Message{
		{Role: "assistant", Content: jsonQuote(arguments), ToolCalls: []ToolCall{{ID: "toolu_1", Type: "function", Function: ToolCallFunc{Name: "write_file", Arguments: arguments}}}},
	}}
	textOnly := &ChatCompletionRequest{Messages: []Message{
		{Role: "assistant", Content: jsonQuote(arguments)},
	}}
	got, base := estimateChatPromptTokens(native), estimateChatPromptTokens(textOnly)
	if got > base+promptMessageOverheadTokens+promptToolOverheadTokens {
		t.Fatalf("原生 tool_use 被重复计数: native=%d, 纯文本=%d", got, base)
	}
}

func TestEstimateChatPromptTokensKeepsTextAndToolCallsTogether(t *testing.T) {
	arguments := strings.Repeat("b", 3000)
	request := &ChatCompletionRequest{Messages: []Message{
		{Role: "assistant", Content: jsonQuote("我先改文件"), ToolCalls: []ToolCall{{ID: "call_1", Type: "function", Function: ToolCallFunc{Name: "patch", Arguments: arguments}}}},
	}}
	if got, floor := estimateChatPromptTokens(request), estimateTextTokens(arguments); got < floor {
		t.Fatalf("正文与 tool_calls 并存时参数被漏算: estimate=%d want >= %d", got, floor)
	}
}

func TestEstimatedChatAdmissionTokensIncludesToolCallHistory(t *testing.T) {
	arguments := strings.Repeat("a", 30000)
	request := &ChatCompletionRequest{
		MaxTokens: 100,
		Messages: []Message{
			{Role: "user", Content: jsonQuote("hi")},
			{Role: "assistant", ToolCalls: []ToolCall{{ID: "call_1", Type: "function", Function: ToolCallFunc{Name: "write_file", Arguments: arguments}}}},
		},
	}
	if got, floor := estimatedChatAdmissionTokens(request), estimateTextTokens(arguments)+100; got < floor {
		t.Fatalf("准入预留=%d, 应 >= %d (历史 tool_call 参数 + max_tokens)", got, floor)
	}
}
