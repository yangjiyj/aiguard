package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

func TestExtractedFromParsedChatDualForm(t *testing.T) {
	parsed, ok := aimsg.ParseAnthropicMessagesRequest([]byte(`{"model":"claude-sonnet-4-5","system":"SYS","messages":[{"role":"user","content":"GWTEST 双形态"},{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="}},{"type":"text","text":"看这张截图"}]}]}`))
	if !ok {
		t.Fatal("解析失败")
	}
	content, ok := extractedFromParsedChat(parsed)
	if !ok {
		t.Fatal("折算失败")
	}
	// 双形态：Messages 结构化 + Text 平铺（消息拼接生成）。
	if len(content.Messages) != 3 {
		t.Fatalf("Messages 条数 = %d, want 3: %+v", len(content.Messages), content.Messages)
	}
	if content.Text != aimsg.FlattenMessages(parsed.Messages) {
		t.Fatalf("Text 必须由消息拼接生成: %q", content.Text)
	}
	if content.SecurityTextKnown != true || content.SecurityText != "GWTEST 双形态\n看这张截图" {
		t.Fatalf("SecurityText 应只包含可归因客户消息: known=%v text=%q", content.SecurityTextKnown, content.SecurityText)
	}
	if !strings.Contains(content.Text, "SYS") || !strings.Contains(content.Text, "GWTEST 双形态") {
		t.Fatalf("平铺 Text 证据不全: %q", content.Text)
	}
	if content.Model != "claude-sonnet-4-5" {
		t.Fatalf("Model = %q", content.Model)
	}
	// 内嵌 base64 图片块 → 附件（1x1 PNG，字节留证）。
	if len(content.Attachments) != 1 || content.Attachments[0].Source != "inline_image_block" || content.Attachments[0].SHA256 == "" {
		t.Fatalf("内嵌图片附件缺失: %+v", content.Attachments)
	}
}

func TestExtractedFromParsedChatEmptyIsUnmatched(t *testing.T) {
	if _, ok := extractedFromParsedChat(aimsg.ParsedChat{}); ok {
		t.Fatal("空产物应返回不匹配，让上层走回退路径")
	}
}

func TestAnthropicMessagesRequestDecoderClaudeCodeFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/claude-code-v1-messages.req")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	decoder, ok := getWebDecoder("anthropic_messages")
	if !ok {
		t.Fatal("web decoder anthropic_messages 未注册（catalog 声明了它但注册表一直缺失——本次要修的病根）")
	}
	extracted, matched := decoder.DecodeRequest(req, body, "application/json")
	if !matched {
		t.Fatal("anthropic_messages 请求解码器未命中 Claude Code 夹具")
	}
	// 用户正文抽取。
	if !strings.Contains(extracted.Text, "GWTEST-P1C-0705-CC-02 把这个密码轮换一下") {
		t.Fatalf("用户正文缺失:\n%s", extracted.Text)
	}
	// 平铺 Text 与 legacy 兼容：system/tool 描述/tool_result 证据全在（证据不减量）。
	for _, evidence := range []string{"You are Claude Code", "[tool_def:Bash]", "S3cretPw", "[tool_use:Bash]"} {
		if !strings.Contains(extracted.Text, evidence) {
			t.Fatalf("平铺 Text 缺少证据 %q:\n%s", evidence, extracted.Text)
		}
	}
	// role/source 划分。
	bySource := map[string]int{}
	for _, m := range extracted.Messages {
		bySource[m.Source]++
	}
	if bySource["system_prompt"] != 1 || bySource["tool_def"] != 2 || bySource["tool_result"] != 1 || bySource["user"] != 2 || bySource["assistant_history"] != 1 {
		t.Fatalf("source 分布错误: %v", bySource)
	}
	if extracted.Model != "claude-sonnet-4-5" {
		t.Fatalf("Model = %q", extracted.Model)
	}
	// ConversationID 由留证前的 enrichAPIConversationKey 填，解码器阶段必须为空。
	if extracted.ConversationID != "" {
		t.Fatalf("解码器不应自填 ConversationID: %q", extracted.ConversationID)
	}
}

func TestAnthropicMessagesRequestDecoderRejectsNonChatJSON(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-5","input":"embed this"}`)
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/embeddings", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	decoder, _ := getWebDecoder("anthropic_messages")
	if _, matched := decoder.DecodeRequest(req, body, "application/json"); matched {
		t.Fatal("无 messages 数组的请求不应命中，须回退通用抽取器")
	}
}

func TestAnthropicMessagesResponseDecoderJSON(t *testing.T) {
	body, err := os.ReadFile("testdata/anthropic-v1-messages.resp.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	decoder, _ := getWebDecoder("anthropic_messages")
	extracted, matched := decoder.DecodeResponse(body, "application/json")
	if !matched {
		t.Fatal("anthropic_messages 响应解码器未命中非流式 JSON")
	}
	if !strings.Contains(extracted.Text, "GWTEST-P1C-0705-CC-RESP") || !strings.Contains(extracted.Text, "[tool_use:Read]") {
		t.Fatalf("响应正文/工具调用缺失: %q", extracted.Text)
	}
	if extracted.Model != "claude-sonnet-4-5" {
		t.Fatalf("Model = %q", extracted.Model)
	}
	if !extracted.VisibleTextKnown || extracted.VisibleText != "GWTEST-P1C-0705-CC-RESP 已生成轮换步骤。" {
		t.Fatalf("非流式 Anthropic 客户投影不得包含 thinking/tool_use: %+v", extracted)
	}
}

func TestAnthropicMessagesResponseDecoderSSE(t *testing.T) {
	body, err := os.ReadFile("testdata/anthropic-v1-messages.resp.sse")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	decoder, _ := getWebDecoder("anthropic_messages")
	extracted, matched := decoder.DecodeResponse(body, "text/event-stream")
	if !matched {
		t.Fatal("anthropic_messages 响应解码器未命中 SSE 事件流")
	}
	if !strings.Contains(extracted.Text, "[reasoning] 先确认配置文件位置") {
		t.Fatalf("thinking 增量未按 [reasoning] 标记重组: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "建议立即轮换 数据库密码并撤销旧凭据。") {
		t.Fatalf("text_delta 未按序拼接: %q", extracted.Text)
	}
	if !strings.Contains(extracted.Text, "[tool_use:Bash] {\"command\":\"vault rotate db-app\"}") {
		t.Fatalf("tool_use 输入增量未重组: %q", extracted.Text)
	}
	if extracted.Model != "claude-sonnet-4-5" {
		t.Fatalf("Model 未从 message_start 提取: %q", extracted.Model)
	}
	if !extracted.VisibleTextKnown || extracted.VisibleText != "建议立即轮换 数据库密码并撤销旧凭据。" {
		t.Fatalf("Anthropic SSE 客户投影不得包含 thinking/tool_use: %+v", extracted)
	}
	// 协议帧（message_stop/content_block_stop 等）不得进正文。
	if strings.Contains(extracted.Text, "message_stop") || strings.Contains(extracted.Text, "content_block_stop") {
		t.Fatalf("协议帧泄露进正文: %q", extracted.Text)
	}
}

func TestAnthropicSSESniffedWithoutDecoderName(t *testing.T) {
	// CheckOutput 等无解码器名的路径靠响应 sniff 链兜住 anthropic SSE。
	body, err := os.ReadFile("testdata/anthropic-v1-messages.resp.sse")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	extracted := extractResponseContent(body, "text/event-stream")
	if !strings.Contains(extracted.Text, "建议立即轮换 数据库密码并撤销旧凭据。") {
		t.Fatalf("sniff 链未重组 anthropic SSE（应加入 responseSniffWebDecoderNames）: %q", extracted.Text)
	}
	if strings.Contains(extracted.Text, "end_turn") {
		t.Fatalf("sniff 后协议字段不应进正文: %q", extracted.Text)
	}
}
