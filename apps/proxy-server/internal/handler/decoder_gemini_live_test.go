package handler

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// 现网核对：2026-06-22 用 Chrome 扩展实抓 gemini.google.com 当前发送请求，确认仍是
// POST .../BardFrontendService/StreamGenerate，form-urlencoded 的 f.req = [null, "<inner json string>"]，
// 用户文字在 inner[0][0]。本测试按实抓骨架重建 f.req，跑现有 decodeGeminiWebRequest，
// 验证老解码器对现网格式仍能抽出用户文字（formData 形态不变）。
func TestDecodeGeminiWebRequest_LiveStreamGenerateShape(t *testing.T) {
	// inner 骨架对齐实抓：inner[0]=[TEXT,number,null,null,null,null,number], inner[1]=[str], inner[2]=[str,str,str,...]
	inner := `[["GEMINI-TEXT-7788 正向代理适配抓包测试，回复一个字即可",0,null,null,null,null,0],["zh-CN"],["conv-id","resp-id","rcid"]]`
	freq, err := json.Marshal([]interface{}{nil, inner})
	if err != nil {
		t.Fatal(err)
	}
	body := "f.req=" + url.QueryEscape(string(freq))
	req := httptest.NewRequest(
		"POST",
		"https://gemini.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate",
		strings.NewReader(body),
	)
	got, ok := decodeGeminiWebRequest(req, []byte(body), "application/x-www-form-urlencoded")
	if !ok {
		t.Fatalf("现网 Gemini StreamGenerate f.req 形态未被老解码器命中")
	}
	if !strings.Contains(got.Text, "GEMINI-TEXT-7788") {
		t.Errorf("老解码器未能从现网 f.req 抽出用户文字: %q", got.Text)
	}
}
