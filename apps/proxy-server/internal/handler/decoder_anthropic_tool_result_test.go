package handler

import (
	"encoding/base64"
	"testing"
)

// §3.8 / 任务 8.4：anthropic 请求里 tool_result 嵌套的 PDF 出现在 Attachments（走文件 DLP 通道）。
func TestDecodeAnthropicToolResultPDFAttachment(t *testing.T) {
	pdfB64 := base64.StdEncoding.EncodeToString([]byte("fake-pdf-bytes"))
	body := `{
		"model": "claude-3",
		"messages": [
			{"role": "user", "content": "read the contract"},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "t1", "content": [
					{"type": "document", "title": "合同.pdf", "source": {"type": "base64", "media_type": "application/pdf", "data": "` + pdfB64 + `"}},
					{"type": "text", "text": "file content follows"}
				]}
			]}
		]
	}`

	extracted, ok := decodeAnthropicMessagesRequest(nil, []byte(body), "application/json")
	if !ok {
		t.Fatal("decodeAnthropicMessagesRequest returned false")
	}

	found := false
	for _, att := range extracted.Attachments {
		if att.ContentType == "application/pdf" {
			found = true
		}
	}
	if !found {
		t.Fatalf("tool_result PDF not in Attachments: %+v", extracted.Attachments)
	}
}
