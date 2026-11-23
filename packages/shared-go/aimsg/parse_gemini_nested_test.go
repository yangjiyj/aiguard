package aimsg

import (
	"encoding/base64"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

// §3.8 / 任务 8.2：functionResponse 同一 parts 数组里的 inlineData(application/pdf 等文档)
// 要抽成 Artifacts；inlineData 为图片仍进 Images。
func TestParseGeminiFunctionResponseInlineData(t *testing.T) {
	pdfB64 := base64.StdEncoding.EncodeToString([]byte("fake-pdf"))
	pngB64 := base64.StdEncoding.EncodeToString([]byte("fake-png"))

	body := `{
		"contents": [
			{"role": "user", "parts": [
				{"functionResponse": {"name": "read_file", "response": {"result": "ok"}}},
				{"inlineData": {"mimeType": "application/pdf", "data": "` + pdfB64 + `"}},
				{"inlineData": {"mimeType": "image/png", "data": "` + pngB64 + `"}}
			]}
		]
	}`

	chat, ok := ParseGeminiGenerateContentRequest([]byte(body))
	if !ok {
		t.Fatal("ParseGeminiGenerateContentRequest returned false")
	}

	// pdf inlineData → Artifacts（KindFile）
	var docArtifact *retentionartifact.Candidate
	for i := range chat.Artifacts {
		if chat.Artifacts[i].Kind == retentionartifact.KindFile {
			docArtifact = &chat.Artifacts[i]
			break
		}
	}
	if docArtifact == nil {
		t.Fatalf("want a file artifact from pdf inlineData, got %+v", chat.Artifacts)
	}

	// png inlineData → Images（图片行为不变）
	if len(chat.Images) != 1 || chat.Images[0].MediaType != "image/png" {
		t.Fatalf("image handling changed: %+v", chat.Images)
	}
}
