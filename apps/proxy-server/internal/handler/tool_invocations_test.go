package handler

import (
	"strings"
	"testing"
)

// Responses 流式 SSE：custom_tool_call_input.done（Codex JS）→ ToolInvocations，
// 且 Text/SecurityText/VisibleText 与工具文本机制不变（含 [tool] 段）。
func TestToolInvocationsResponsesStreamCustomToolCall(t *testing.T) {
	js := `const r = await tools.exec_command({cmd:"pdftotext 合同.pdf -",workdir:"/w"})`
	sse := "event: response.output_item.added\n" +
		"data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"id\":\"i1\",\"type\":\"custom_tool_call\",\"call_id\":\"c1\",\"name\":\"exec\"}}\n\n" +
		"event: response.custom_tool_call_input.done\n" +
		"data: {\"type\":\"response.custom_tool_call_input.done\",\"output_index\":0,\"item_id\":\"i1\",\"input\":" + jsonQuote(js) + "}\n\n" +
		"event: response.output_item.done\n" +
		"data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"id\":\"i1\",\"type\":\"custom_tool_call\",\"call_id\":\"c1\",\"name\":\"exec\",\"input\":" + jsonQuote(js) + "}}\n\n" +
		"event: response.completed\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"status\":\"completed\",\"output\":[]}}\n\n"

	extracted := extractResponseContent([]byte(sse), "text/event-stream")
	if len(extracted.ToolInvocations) == 0 {
		t.Fatalf("no ToolInvocations extracted; text=%q", extracted.Text)
	}
	inv := extracted.ToolInvocations[0]
	if inv.Name != "exec" {
		t.Fatalf("invocation name=%q, want exec", inv.Name)
	}
	if !strings.Contains(inv.Arguments, "exec_command") || !strings.Contains(inv.Arguments, "pdftotext") {
		t.Fatalf("invocation arguments missing JS: %q", inv.Arguments)
	}
	// Text 仍走 [tool] 段机制（逐字节一致的关键：未被 ToolInvocations 改动）
	if !strings.Contains(extracted.Text, "exec_command") {
		t.Fatalf("Text lost tool payload: %q", extracted.Text)
	}
}

// 通用 SSE delta.tool_calls：name+arguments 按 token 增量聚合。
func TestToolInvocationsOpenAIDeltaStream(t *testing.T) {
	sse := "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"shell\",\"arguments\":\"{\\\"command\\\"\"}}]}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\":\\\"cat a.pdf\\\"}\"}}]}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{}}],\"finish_reason\":\"tool_calls\"}\n\n"
	extracted := extractResponseContent([]byte(sse), "text/event-stream")
	if len(extracted.ToolInvocations) != 1 {
		t.Fatalf("want 1 invocation, got %+v", extracted.ToolInvocations)
	}
	inv := extracted.ToolInvocations[0]
	if inv.Name != "shell" {
		t.Fatalf("name=%q, want shell", inv.Name)
	}
	if inv.Arguments != `{"command":"cat a.pdf"}` {
		t.Fatalf("arguments=%q", inv.Arguments)
	}
}

// Anthropic 非流式 tool_use。
func TestToolInvocationsAnthropicNonStream(t *testing.T) {
	body := `{"type":"message","model":"claude","content":[{"type":"tool_use","name":"Read","input":{"file_path":"/home/u/合同.pdf"}}]}`
	extracted := extractResponseContent([]byte(body), "application/json")
	if len(extracted.ToolInvocations) != 1 {
		t.Fatalf("want 1 invocation, got %+v (text=%q)", extracted.ToolInvocations, extracted.Text)
	}
	inv := extracted.ToolInvocations[0]
	if inv.Name != "Read" || !strings.Contains(inv.Arguments, "合同.pdf") {
		t.Fatalf("invocation=%+v", inv)
	}
	// Text 仍含 [tool_use:Read] 段
	if !strings.Contains(extracted.Text, "[tool_use:Read]") {
		t.Fatalf("Text lost tool_use part: %q", extracted.Text)
	}
}

// Anthropic 流式 tool_use（直接驱动 reassembleAnthropicMessagesStream）。
func TestToolInvocationsAnthropicStream(t *testing.T) {
	sse := "event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"name\":\"Bash\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"cat a.pdf\\\"}\"}}\n\n" +
		"event: content_block_stop\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":1}\n\n"
	extracted, ok := reassembleAnthropicMessagesStream(parseSSEDataEvents([]byte(sse)))
	if !ok {
		t.Fatal("anthropic stream not matched")
	}
	if len(extracted.ToolInvocations) != 1 {
		t.Fatalf("want 1 invocation, got %+v (text=%q)", extracted.ToolInvocations, extracted.Text)
	}
	inv := extracted.ToolInvocations[0]
	if inv.Name != "Bash" || !strings.Contains(inv.Arguments, "cat a.pdf") {
		t.Fatalf("invocation=%+v", inv)
	}
}

func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\n':
			b.WriteString("\\n")
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
