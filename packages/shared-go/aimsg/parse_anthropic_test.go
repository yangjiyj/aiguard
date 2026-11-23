package aimsg

import (
	"strings"
	"testing"
)

const anthropicFixture = `{
  "model": "claude-sonnet-4-5",
  "max_tokens": 32000,
  "system": [
    {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude.", "cache_control": {"type": "ephemeral"}},
    {"type": "text", "text": "gitStatus: Current branch: main"}
  ],
  "tools": [
    {"name": "Bash", "description": "Executes a bash command.", "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}}}
  ],
  "messages": [
    {"role": "user", "content": "GWTEST-AIMSG-01 第一条用户提问"},
    {"role": "assistant", "content": [
      {"type": "thinking", "thinking": "先查配置"},
      {"type": "text", "text": "我来搜索。"},
      {"type": "tool_use", "id": "toolu_01", "name": "Bash", "input": {"command": "grep -r DATABASE_URL ."}}
    ]},
    {"role": "user", "content": [
      {"type": "tool_result", "tool_use_id": "toolu_01", "content": [{"type": "text", "text": "prod.env:DATABASE_URL=postgres://svc:S3cretPw@10.0.0.8/app"}]},
      {"type": "text", "text": "GWTEST-AIMSG-02 继续"}
    ]}
  ]
}`

func TestParseAnthropicMessagesRequest(t *testing.T) {
	parsed, ok := ParseAnthropicMessagesRequest([]byte(anthropicFixture))
	if !ok {
		t.Fatal("anthropic 夹具应解析成功")
	}
	if parsed.Model != "claude-sonnet-4-5" {
		t.Fatalf("Model = %q", parsed.Model)
	}
	if !strings.Contains(parsed.SystemText, "You are Claude Code") || !strings.Contains(parsed.SystemText, "gitStatus") {
		t.Fatalf("SystemText 应拼接全部 system 块: %q", parsed.SystemText)
	}
	// 产物顺序：system → tool_def → 消息原序。
	if parsed.Messages[0].Source != SourceSystemPrompt || parsed.Messages[0].Role != "system" {
		t.Fatalf("首条应为 system_prompt: %+v", parsed.Messages[0])
	}
	if parsed.Messages[1].Source != SourceToolDef || !strings.Contains(parsed.Messages[1].Content, "[tool_def:Bash]") {
		t.Fatalf("第二条应为 tool_def: %+v", parsed.Messages[1])
	}
	var sources []string
	for _, m := range parsed.Messages {
		sources = append(sources, m.Source)
	}
	want := []string{SourceSystemPrompt, SourceToolDef, SourceUser, SourceAssistantHistory, SourceToolResult, SourceUser}
	if strings.Join(sources, ",") != strings.Join(want, ",") {
		t.Fatalf("source 序列 = %v, want %v", sources, want)
	}
	// assistant 历史合并 thinking/text/tool_use。
	assistant := parsed.Messages[3]
	if !strings.Contains(assistant.Content, "[reasoning] 先查配置") || !strings.Contains(assistant.Content, "[tool_use:Bash]") || !strings.Contains(assistant.Content, "grep -r DATABASE_URL") {
		t.Fatalf("assistant 历史内容不全: %q", assistant.Content)
	}
	// tool_result 独立成条且保留敏感证据。
	toolResult := parsed.Messages[4]
	if toolResult.Role != "user" || !strings.Contains(toolResult.Content, "S3cretPw") {
		t.Fatalf("tool_result 条目错误: %+v", toolResult)
	}
	// FirstUserSHA = 首条 user 消息的 sha。
	if parsed.FirstUserSHA != ContentSHA256Hex("GWTEST-AIMSG-01 第一条用户提问") {
		t.Fatalf("FirstUserSHA 错误: %q", parsed.FirstUserSHA)
	}
	// ToolsDigest（设计 1a tools_digest）：夹具只有 1 个 tool_def → 即该条内容的 sha。
	if parsed.ToolsDigest != ContentSHA256Hex(parsed.Messages[1].Content) {
		t.Fatalf("ToolsDigest 错误: %q", parsed.ToolsDigest)
	}
}

func TestParseAnthropicMessagesRequestSystemString(t *testing.T) {
	body := `{"model":"claude-haiku-4","system":"简短系统提示","messages":[{"role":"user","content":"你好"}]}`
	parsed, ok := ParseAnthropicMessagesRequest([]byte(body))
	if !ok || parsed.SystemText != "简短系统提示" {
		t.Fatalf("system 字符串形态解析失败: ok=%v parsed=%+v", ok, parsed)
	}
}

func TestParseAnthropicMessagesRequestInlineImage(t *testing.T) {
	body := `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGVsbG8="}},{"type":"text","text":"看图"}]}]}`
	parsed, ok := ParseAnthropicMessagesRequest([]byte(body))
	if !ok || len(parsed.Images) != 1 || parsed.Images[0].MediaType != "image/png" || parsed.Images[0].DataBase64 != "aGVsbG8=" {
		t.Fatalf("内嵌图片块未捕获: ok=%v images=%+v", ok, parsed.Images)
	}
}

func TestParseAnthropicMessagesRequestRejectsNonChat(t *testing.T) {
	for _, body := range []string{`{"model":"m","input":"embedding text"}`, `not json`, `{"messages":[]}`} {
		if _, ok := ParseAnthropicMessagesRequest([]byte(body)); ok {
			t.Fatalf("非 chat 形态不应匹配: %s", body)
		}
	}
}
