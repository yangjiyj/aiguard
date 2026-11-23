package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/aiconvo"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

func TestEnrichAPIConversationKeyStableAndContractAligned(t *testing.T) {
	parsed, ok := aimsg.ParseAnthropicMessagesRequest([]byte(`{"model":"claude-sonnet-4-5","system":"SYS","messages":[{"role":"user","content":"首条提问"}]}`))
	if !ok {
		t.Fatal("解析失败")
	}
	content, _ := extractedFromParsedChat(parsed)
	enrichAPIConversationKey("tenant_default", "claude-code", &content)
	if content.ConversationID == "" {
		t.Fatal("ConversationID 未填")
	}
	// 与共享契约的 aiconvo.ConversationKey 逐字一致（keyID 恒空：正代无网关 key）。
	want := aiconvo.ConversationKey("tenant_default", "", "claude-code", aiconvo.SystemDigest("SYS"), aimsg.ContentSHA256Hex("首条提问"))
	if content.ConversationID != want {
		t.Fatalf("ConversationID = %q, want %q", content.ConversationID, want)
	}
	if len(content.ConversationID) > 128 {
		t.Fatalf("conversation_id 超出 access_content_logs.conversation_id VARCHAR(128): %d", len(content.ConversationID))
	}
	// 幂等：重复调用不改值。
	again := content
	enrichAPIConversationKey("tenant_default", "claude-code", &again)
	if again.ConversationID != content.ConversationID {
		t.Fatal("重复富化改变了 ConversationID")
	}
}

func TestEnrichAPIConversationKeyDoesNotOverrideDecoderKey(t *testing.T) {
	content := ExtractedContent{ConversationID: "chat-session-from-web", Messages: []ConvMessage{{Role: "user", Source: aimsg.SourceUser, Content: "x", ContentSHA256: aimsg.ContentSHA256Hex("x")}}}
	enrichAPIConversationKey("tenant_default", "", &content)
	if content.ConversationID != "chat-session-from-web" {
		t.Fatal("网页解码器自带会话键不得被覆盖")
	}
}

func TestEnrichAPIConversationKeySkipsWhenNoAnchors(t *testing.T) {
	// 无 system 且无 user 首条（只有 tool_def）→ 不填，防止无关请求被归为一组。
	content := ExtractedContent{Messages: []ConvMessage{{Role: "tool", Source: aimsg.SourceToolDef, Content: "[tool_def:x] y", ContentSHA256: aimsg.ContentSHA256Hex("[tool_def:x] y")}}}
	enrichAPIConversationKey("tenant_default", "", &content)
	if content.ConversationID != "" {
		t.Fatalf("锚点缺失时不应填 ConversationID: %q", content.ConversationID)
	}
	// 无 Messages（普通网页流量/回退平铺）→ 不动。
	flat := ExtractedContent{Text: "plain"}
	enrichAPIConversationKey("tenant_default", "", &flat)
	if flat.ConversationID != "" {
		t.Fatal("无结构化消息不应填 ConversationID")
	}
}

func TestNativeCodexThreadOverridesChangingFingerprint(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/responses", nil)
	req.Header.Set("Thread-Id", "thread-a")
	first := ExtractedContent{ConversationID: "ck_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	enrichAPIConversationKey("tenant", "openai-codex", &first, req)
	second := ExtractedContent{ConversationID: "ck_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	enrichAPIConversationKey("tenant", "openai-codex", &second, req)
	if first.ConversationID == "" || first.ConversationID != second.ConversationID {
		t.Fatal("native thread split")
	}
	req.Header.Set("Thread-Id", "thread-b")
	third := ExtractedContent{ConversationID: "ck_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	enrichAPIConversationKey("tenant", "openai-codex", &third, req)
	if third.ConversationID == first.ConversationID {
		t.Fatal("different thread merged")
	}
}

func TestFingerprintConversationSeparatesCallers(t *testing.T) {
	key := func(ip string) string {
		req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		req.RemoteAddr = ip + ":1234"
		content := ExtractedContent{Messages: []ConvMessage{{Role: "user", Source: aimsg.SourceUser, Content: "你好", ContentSHA256: aimsg.ContentSHA256Hex("你好")}}}
		enrichAPIConversationKey("tenant", "cline", &content, req)
		return content.ConversationID
	}
	if key("192.0.2.1") == key("192.0.2.2") {
		t.Fatal("different callers with identical prompts merged")
	}
}

func TestClineDynamicContextKeepsConversation(t *testing.T) {
	key := func(context string) string {
		text := "<task>检查项目</task>\n\n# task_progress RECOMMENDED\n<environment_details>\n" + context + "\n</environment_details>"
		content := ExtractedContent{Messages: []ConvMessage{{Role: "user", Source: aimsg.SourceUser, Content: text, ContentSHA256: aimsg.ContentSHA256Hex(text)}}}
		enrichAPIConversationKey("tenant", "cline", &content)
		return content.ConversationID
	}
	if key("ACT MODE") != key("PLAN MODE") {
		t.Fatal("Cline environment changes split one task")
	}
}
