package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestYuanbaoWebResponseDecodesConversationDetail 用真实抓取的元宝 conversation/v1/detail
// 报文（testdata/yuanbao-conversation-detail.resp.json）验证：结构化解出 human/ai 轮次、
// 剥掉 markdown 标注噪音、按时间线排序（用户在前、模型在后）。
func TestYuanbaoWebResponseDecodesConversationDetail(t *testing.T) {
	body, err := os.ReadFile("testdata/yuanbao-conversation-detail.resp.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	got, ok := decodeYuanbaoWebResponse(body, "application/json")
	if !ok {
		t.Fatal("yuanbao_web 应命中 conversation/v1/detail 响应")
	}
	if len(got.Messages) != 2 {
		t.Fatalf("期望 2 条消息(human+ai)，实得 %d: %+v", len(got.Messages), got.Messages)
	}
	// 时间线：用户"好啊"在前，模型回复在后。
	if got.Messages[0].Role != "user" || got.Messages[0].Content != "好啊" {
		t.Fatalf("首条应为用户 好啊，实得 role=%s content=%q", got.Messages[0].Role, got.Messages[0].Content)
	}
	if got.Messages[1].Role != "assistant" {
		t.Fatalf("次条应为 assistant，实得 %s", got.Messages[1].Role)
	}
	if !strings.Contains(got.Messages[1].Content, "开启聊天模式的暗号") {
		t.Fatalf("模型回复正文缺失: %q", got.Messages[1].Content)
	}
	// markdown 标注噪音已剥离。
	if strings.Contains(got.Text, "@mark_underline") {
		t.Fatalf("平铺 Text 仍含 markdown 标注噪音: %q", got.Text)
	}
	if got.ConversationID == "" {
		t.Fatal("应带 conversation_id 供 turn 归组")
	}
	// 每条消息带 sha 供检测/会话键。
	for _, m := range got.Messages {
		if m.ContentSHA256 == "" {
			t.Fatalf("消息缺 ContentSHA256: %+v", m)
		}
	}
}

// TestYuanbaoWebResponseRejectsNonDetail 非 detail 结构（无 convs）不命中，走回退。
func TestYuanbaoWebResponseRejectsNonDetail(t *testing.T) {
	if _, ok := decodeYuanbaoWebResponse([]byte(`{"code":0,"data":{"items":[]}}`), "application/json"); ok {
		t.Fatal("无 convs 的响应不应命中 yuanbao_web")
	}
	if _, ok := decodeYuanbaoWebResponse([]byte(`not json`), "application/json"); ok {
		t.Fatal("非 JSON 不应命中")
	}
}

// TestYuanbaoWebRequestExtractsChatPrompt /api/chat 请求抽出用户 prompt。
func TestYuanbaoWebRequestExtractsChatPrompt(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://yuanbao.tencent.com/api/chat/0OXoMc79xg0", nil)
	got, ok := decodeYuanbaoWebRequest(req, []byte(`{"prompt":"卧槽？","sessionId":"x"}`), "application/json")
	if !ok {
		t.Fatal("/api/chat 请求应命中")
	}
	if got.Text != "卧槽？" || len(got.Messages) != 1 || got.Messages[0].Content != "卧槽？" {
		t.Fatalf("应抽出用户提问 卧槽？，实得 text=%q msgs=%+v", got.Text, got.Messages)
	}
}

// TestYuanbaoWebRequestSuppressesMetadata 轮询/元数据接口返回空匹配抑制，不产噪音留证。
func TestYuanbaoWebRequestSuppressesMetadata(t *testing.T) {
	for _, path := range []string{
		"/api/user/agent/conversation/promptSug",
		"/api/user/agent/conversation/list",
		"/api/user/agent/conversation/v1/detail",
		"/api/user/agent/conversation/updateModel",
	} {
		req := httptest.NewRequest(http.MethodPost, "https://yuanbao.tencent.com"+path, nil)
		got, ok := decodeYuanbaoWebRequest(req, []byte(`{"prompt":"好","sessionId":"x"}`), "application/json")
		if !ok {
			t.Fatalf("%s 应命中（空匹配抑制）", path)
		}
		if strings.TrimSpace(got.Text) != "" {
			t.Fatalf("%s 应抑制为空内容，实得 %q", path, got.Text)
		}
	}
}
