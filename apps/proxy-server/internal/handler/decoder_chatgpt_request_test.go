package handler

import (
	"strings"
	"testing"
)

// 夹具按 2026-06-22 Chrome 扩展实抓的 chatgpt.com /backend-api/f/conversation 正文结构构造。
const chatgptTextBody = `{
  "action": "next",
  "messages": [
    {
      "id": "aaa",
      "author": {"role": "user"},
      "content": {"content_type": "text", "parts": ["GPT-TEXT-7788 正向代理适配抓包测试"]},
      "metadata": {}
    }
  ],
  "model": "gpt-5"
}`

const chatgptMultimodalBody = `{
  "messages": [
    {
      "author": {"role": "user"},
      "content": {
        "content_type": "multimodal_text",
        "parts": [
          {"content_type": "image_asset_pointer", "asset_pointer": "file-service://file_00000000aa5c71f7", "size_bytes": 173, "width": 80, "height": 80},
          "GPT-IMG-7788 图片抓包测试"
        ]
      },
      "metadata": {"attachments": [{"id": "file_00000000aa5c71f7", "name": "GPT-IMG-7788.png", "mime_type": "image/png", "size": 173, "width": 80, "height": 80}]}
    }
  ]
}`

// 守卫：content_type 非 ChatGPT 取值时不得命中（防探测时误吞别站请求）。
const chatgptForeignBody = `{
  "messages": [
    {"content": {"content_type": "some_other_vendor_format", "parts": ["不该被抓"]}, "metadata": {}}
  ]
}`

func TestDecodeChatGPTConversation_Text(t *testing.T) {
	got, ok := decodeChatGPTConversationRequest([]byte(chatgptTextBody), "application/json")
	if !ok {
		t.Fatalf("expected match")
	}
	if !strings.Contains(got.Text, "GPT-TEXT-7788") {
		t.Errorf("Text 缺用户文字: %q", got.Text)
	}
}

func TestDecodeChatGPTConversation_MultimodalImage(t *testing.T) {
	got, ok := decodeChatGPTConversationRequest([]byte(chatgptMultimodalBody), "application/json")
	if !ok {
		t.Fatalf("expected match")
	}
	if !strings.Contains(got.Text, "GPT-IMG-7788") {
		t.Errorf("Text 缺文字: %q", got.Text)
	}
	var hasPart, hasAttach bool
	for _, a := range got.Attachments {
		if a.Source == "chatgpt_web_part" && a.ContentType == "image_asset_pointer" {
			hasPart = true
		}
		if a.Source == "chatgpt_web_attachment" && a.FileName == "GPT-IMG-7788.png" && a.ContentType == "image/png" {
			hasAttach = true
		}
	}
	if !hasPart {
		t.Errorf("缺 image_asset_pointer 占位附件: %+v", got.Attachments)
	}
	if !hasAttach {
		t.Errorf("缺 metadata.attachments 文件元数据: %+v", got.Attachments)
	}
}

func TestDecodeChatGPTConversation_ForeignContentTypeNotMatched(t *testing.T) {
	if _, ok := decodeChatGPTConversationRequest([]byte(chatgptForeignBody), "application/json"); ok {
		t.Errorf("非 ChatGPT content_type 不应命中（防误吞别站）")
	}
}

func TestDecodeChatGPTConversation_NonJSON(t *testing.T) {
	if _, ok := decodeChatGPTConversationRequest([]byte("not json"), "text/plain"); ok {
		t.Errorf("非 JSON 不应命中")
	}
}
