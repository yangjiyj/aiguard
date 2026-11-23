package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestOpenAICompatibleRequestDecoderOpencodeFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/opencode-chat-completions.req")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	decoder, ok := getWebDecoder("openai_compatible")
	if !ok {
		t.Fatal("web decoder openai_compatible 未注册")
	}
	extracted, matched := decoder.DecodeRequest(req, body, "application/json")
	if !matched {
		t.Fatal("openai_compatible 对 api.openai.com 必须命中（旧错绑 decodeWorkBuddyInvokeRequest 的 host 写死 ride-3，此断言在换绑前必失败）")
	}
	if !strings.Contains(extracted.Text, "GWTEST-P1C-0705-OC-01") || !strings.Contains(extracted.Text, "GWTEST-P1C-0705-OC-02") {
		t.Fatalf("用户正文缺失:\n%s", extracted.Text)
	}
	for _, evidence := range []string{"You are opencode", "[tool_def:read_file]", "[tool_use:read_file]", "ghp_FAKE1234567890abcdef"} {
		if !strings.Contains(extracted.Text, evidence) {
			t.Fatalf("平铺 Text 缺少证据 %q:\n%s", evidence, extracted.Text)
		}
	}
	bySource := map[string]int{}
	for _, m := range extracted.Messages {
		bySource[m.Source]++
	}
	if bySource["system_prompt"] != 1 || bySource["tool_def"] != 1 || bySource["tool_result"] != 1 || bySource["user"] != 2 || bySource["assistant_history"] != 1 {
		t.Fatalf("source 分布错误: %v", bySource)
	}
	if extracted.Model != "gpt-5.2-codex" {
		t.Fatalf("Model = %q", extracted.Model)
	}
}

func TestOpenAICompatibleRequestDecoderRejectsNonChat(t *testing.T) {
	decoder, _ := getWebDecoder("openai_compatible")
	for name, body := range map[string]string{
		"embeddings": `{"model":"text-embedding-3-small","input":"embed this"}`,
		"files":      `{"purpose":"assistants"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/embeddings", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if _, matched := decoder.DecodeRequest(req, []byte(body), "application/json"); matched {
			t.Fatalf("%s 形态不应命中，须回退通用抽取器", name)
		}
	}
}

func TestWorkBuddyEntriesUntouchedByOpenAICompatibleRebind(t *testing.T) {
	// 契约红线：workbuddy_web / workbuddy_invoke 条目不受影响。
	requestDecoder, responseDecoder := detectLLMDecoders("ride-3-live-webapp.azurewebsites.net", "/api/invoke")
	if requestDecoder != "workbuddy_invoke" || responseDecoder != "workbuddy_invoke" {
		t.Fatalf("workbuddy_invoke 路由被破坏: %q/%q", requestDecoder, responseDecoder)
	}
	if _, ok := getWebDecoder("workbuddy_web"); !ok {
		t.Fatal("workbuddy_web 条目丢失")
	}
}
