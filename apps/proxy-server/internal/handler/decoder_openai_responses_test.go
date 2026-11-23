package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAICompatibleRequestDecoderResponsesKeepsUserTextAndLabelsInstructions(t *testing.T) {
	body := []byte(`{"model":"gpt-5.5","instructions":"You are Codex. Runtime instructions.","input":[{"role":"developer","content":[{"type":"input_text","text":"developer runtime"}]},{"role":"user","content":[{"type":"input_text","text":"只保留这句真实用户问题"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "https://api.example-gateway.com/v1/responses", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	decoder, _ := getWebDecoder("openai_compatible")
	extracted, matched := decoder.DecodeRequest(req, body, "application/json")
	if !matched {
		t.Fatal("Responses API 请求必须走结构化解码，不能回退到整包 JSON")
	}
	retained := messagesToRetentionText(extracted.Messages)
	if !strings.HasPrefix(retained, "只保留这句真实用户问题") {
		t.Fatalf("真实用户输入未置顶: %q", retained)
	}
	if !strings.Contains(retained, "【系统】You are Codex") {
		t.Fatalf("top-level instructions 未标记为系统段: %q", retained)
	}
}
