package handler

import (
	"encoding/json"
	"testing"
)

// §3.8 / 任务 8.3：role=tool 消息内容为块数组且含 document 时，extractAttachments 能抽到。
// （Messages 原生路径转 chat 后，tool 消息的 content 仍可能是 Anthropic 块数组。）
func TestExtractAttachmentsToolMessageDocument(t *testing.T) {
	content := json.RawMessage(`[
		{"type": "text", "text": "file content"},
		{"type": "document", "title": "合同.pdf", "source": {"type": "base64", "media_type": "application/pdf", "data": "cGRmLWJ5dGVz"}}
	]`)

	attachments := extractAttachments(content)
	if len(attachments) == 0 {
		t.Fatal("want document attachment extracted from tool message blocks")
	}
	found := false
	for _, att := range attachments {
		if ct, _ := att["content_type"].(string); ct == "application/pdf" {
			found = true
			if data, _ := att["data_base64"].(string); data != "cGRmLWJ5dGVz" {
				t.Fatalf("data_base64=%q", data)
			}
		}
	}
	if !found {
		t.Fatalf("application/pdf not found in %+v", attachments)
	}
}
