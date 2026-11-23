package aimsg

import (
	"strings"
	"testing"
)

const openAIFixture = `{
  "model": "gpt-5.2-codex",
  "stream": true,
  "messages": [
    {"role": "system", "content": "You are opencode, an autonomous coding agent."},
    {"role": "user", "content": "GWTEST-AIMSG-OC-01 修一下登录超时"},
    {"role": "assistant", "content": null, "tool_calls": [{"id": "call_01", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"src/auth/session.ts\"}"}}]},
    {"role": "tool", "tool_call_id": "call_01", "content": "SESSION_TTL = 30 // token: ghp_FAKE1234567890abcdef"},
    {"role": "user", "content": [{"type": "text", "text": "GWTEST-AIMSG-OC-02 TTL 提到 60"}]}
  ],
  "tools": [
    {"type": "function", "function": {"name": "read_file", "description": "Read a file.", "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}}}
  ]
}`

func TestParseOpenAIChatRequest(t *testing.T) {
	parsed, ok := ParseOpenAIChatRequest([]byte(openAIFixture))
	if !ok {
		t.Fatal("openai 夹具应解析成功")
	}
	if parsed.Model != "gpt-5.2-codex" {
		t.Fatalf("Model = %q", parsed.Model)
	}
	var sources []string
	for _, m := range parsed.Messages {
		sources = append(sources, m.Source)
	}
	// tool_def 前置，随后 messages 原序（system 消息留在原位、归 system_prompt）。
	want := []string{SourceToolDef, SourceSystemPrompt, SourceUser, SourceAssistantHistory, SourceToolResult, SourceUser}
	if strings.Join(sources, ",") != strings.Join(want, ",") {
		t.Fatalf("source 序列 = %v, want %v", sources, want)
	}
	if !strings.Contains(parsed.SystemText, "You are opencode") {
		t.Fatalf("SystemText 应取自 system 消息: %q", parsed.SystemText)
	}
	assistant := parsed.Messages[3]
	if !strings.Contains(assistant.Content, "[tool_use:read_file]") || !strings.Contains(assistant.Content, "src/auth/session.ts") {
		t.Fatalf("assistant tool_calls 参数未内联: %q", assistant.Content)
	}
	toolResult := parsed.Messages[4]
	if toolResult.Role != "tool" || !strings.Contains(toolResult.Content, "ghp_FAKE") {
		t.Fatalf("tool 消息应归 tool_result 并保留证据: %+v", toolResult)
	}
	if parsed.FirstUserSHA != ContentSHA256Hex("GWTEST-AIMSG-OC-01 修一下登录超时") {
		t.Fatalf("FirstUserSHA 错误: %q", parsed.FirstUserSHA)
	}
	if parsed.LastUserText != "GWTEST-AIMSG-OC-02 TTL 提到 60" {
		t.Fatalf("LastUserText 错误: %q", parsed.LastUserText)
	}
	if parsed.LastUserSHA != ContentSHA256Hex(parsed.LastUserText) {
		t.Fatalf("LastUserSHA 错误: %q", parsed.LastUserSHA)
	}
	// ToolsDigest（设计 1a tools_digest）：夹具只有 1 个 tool_def（前置在索引 0）。
	if parsed.ToolsDigest != ContentSHA256Hex(parsed.Messages[0].Content) {
		t.Fatalf("ToolsDigest 错误: %q", parsed.ToolsDigest)
	}
}

// TestParseOpenAIChatRequestExtractsInlineImage WorkBuddy 抓包实证：user 消息 content 是
// parts 数组含 image_url data URI(粘贴截图)。旧 openAIMessageText 只取 text、丢 image_url，
// 图片从留证消失。现应把内联图收进 out.Images（extractedFromParsedChat 转成附件）。
func TestParseOpenAIChatRequestExtractsInlineImage(t *testing.T) {
	// 1x1 PNG 的 base64（真实合法字节，供 extractedFromParsedChat base64 解码不失败）。
	png := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
	body := `{
	  "model": "auto",
	  "messages": [
	    {"role": "system", "content": "You are WorkBuddy."},
	    {"role": "user", "content": [
	      {"type": "text", "text": "看看这张图"},
	      {"type": "image_url", "image_url": {"url": "data:image/png;base64,` + png + `"}},
	      {"type": "text", "text": "<user_query>这是啥</user_query>"}
	    ]}
	  ]
	}`
	parsed, ok := ParseOpenAIChatRequest([]byte(body))
	if !ok {
		t.Fatal("应解析成功")
	}
	if len(parsed.Images) != 1 {
		t.Fatalf("应抽出 1 张内联图，实得 %d", len(parsed.Images))
	}
	img := parsed.Images[0]
	if img.MediaType != "image/png" {
		t.Fatalf("MediaType 应为 image/png，实得 %q", img.MediaType)
	}
	if img.DataBase64 != png {
		t.Fatalf("图片 base64 不匹配")
	}
	// 文本仍正常抽取（text part 保留，image_url 不污染文本）。
	if !strings.Contains(FlattenMessages(parsed.Messages), "看看这张图") {
		t.Fatal("text part 应保留")
	}
}

// TestInlineImageFromDataURL 边界：对象/裸串 url、非 data、非 base64、无逗号。
func TestInlineImageFromDataURL(t *testing.T) {
	if img, ok := inlineImageFromDataURL("data:image/jpeg;base64,AAAA"); !ok || img.MediaType != "image/jpeg" || img.DataBase64 != "AAAA" {
		t.Fatalf("data URI 应解析: ok=%v %+v", ok, img)
	}
	for _, bad := range []string{"https://x/a.png", "data:image/png,rawnotbase64", "data:", "", "not a url"} {
		if _, ok := inlineImageFromDataURL(bad); ok {
			t.Fatalf("非内联 base64 图不应匹配: %q", bad)
		}
	}
	// 裸字符串形态的 image_url。
	if got := openAIImageURLString([]byte(`"data:image/png;base64,ZZ"`)); got != "data:image/png;base64,ZZ" {
		t.Fatalf("裸字符串 image_url 未取到: %q", got)
	}
	// 对象形态。
	if got := openAIImageURLString([]byte(`{"url":"data:image/gif;base64,GG","detail":"high"}`)); got != "data:image/gif;base64,GG" {
		t.Fatalf("对象 image_url 未取到: %q", got)
	}
}

func TestParseOpenAIChatRequestUnknownRoleIsNotUser(t *testing.T) {
	parsed, ok := ParseOpenAIChatRequest([]byte(`{
	  "model":"gpt-5",
	  "messages":[
	    {"role":"custom_runtime","content":"内部标识 d212345654"},
	    {"role":"user","content":"继续"}
	  ]
	}`))
	if !ok {
		t.Fatal("未知角色应保留结构化结果")
	}
	if parsed.Messages[0].Source != SourceUnknown {
		t.Fatalf("未知角色不得伪装成 user: %+v", parsed.Messages[0])
	}
	if parsed.LastUserText != "继续" {
		t.Fatalf("真实用户消息识别失败: %+v", parsed)
	}
}

func TestParseOpenAIChatRequestRejectsNonChat(t *testing.T) {
	for _, body := range []string{`{"model":"m","input":"embedding text"}`, `not json`, `{"messages":[]}`, `[1,2,3]`} {
		if _, ok := ParseOpenAIChatRequest([]byte(body)); ok {
			t.Fatalf("非 chat 形态不应匹配: %s", body)
		}
	}
}

func TestParseChatRequestPathHint(t *testing.T) {
	// /v1/messages → anthropic 优先（system 顶层字段被解析进 SystemText）。
	anthropicBody := `{"model":"claude-sonnet-4-5","system":"SYS","messages":[{"role":"user","content":"hi"}]}`
	parsed, ok := ParseChatRequest("/v1/messages", []byte(anthropicBody))
	if !ok || parsed.SystemText != "SYS" {
		t.Fatalf("anthropic 路径提示未生效: ok=%v %+v", ok, parsed)
	}
	// chat/completions → openai 优先（system 在 messages 内）。
	openaiBody := `{"model":"gpt-4o","messages":[{"role":"system","content":"SYS2"},{"role":"user","content":"hi"}]}`
	parsed, ok = ParseChatRequest("/v1/chat/completions", []byte(openaiBody))
	if !ok || parsed.SystemText != "SYS2" {
		t.Fatalf("openai 路径提示未生效: ok=%v %+v", ok, parsed)
	}
	// 非 JSON 对象直接不匹配。
	if _, ok := ParseChatRequest("/v1/chat/completions", []byte("data: hello")); ok {
		t.Fatal("非 JSON 不应匹配")
	}
}
