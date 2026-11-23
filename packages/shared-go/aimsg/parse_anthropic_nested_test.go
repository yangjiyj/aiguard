package aimsg

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

// §3.8 / 任务 8.1：tool_result.content 里嵌套的 image/document 块要抽成附件。
func TestParseAnthropicNestedToolResultAttachments(t *testing.T) {
	pngB64 := base64.StdEncoding.EncodeToString([]byte("fake-png-bytes"))
	pdfB64 := base64.StdEncoding.EncodeToString([]byte("fake-pdf-bytes"))

	body := `{
		"model": "claude-3",
		"messages": [
			{"role": "user", "content": "read the contract"},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "t1", "content": [
					{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "` + pngB64 + `"}},
					{"type": "document", "title": "合同.pdf", "source": {"type": "base64", "media_type": "application/pdf", "data": "` + pdfB64 + `"}},
					{"type": "text", "text": "file content follows"}
				]}
			]}
		]
	}`

	chat, ok := ParseAnthropicMessagesRequest([]byte(body))
	if !ok {
		t.Fatal("ParseAnthropicMessages returned false")
	}

	// 嵌套 image → out.Images
	if len(chat.Images) != 1 {
		t.Fatalf("want 1 image, got %d", len(chat.Images))
	}
	if chat.Images[0].MediaType != "image/png" {
		t.Fatalf("image media=%q", chat.Images[0].MediaType)
	}

	// 嵌套 document → out.Artifacts（KindFile，名字取 title）
	var docArtifact *retentionartifact.Candidate
	for i := range chat.Artifacts {
		if chat.Artifacts[i].Kind == retentionartifact.KindFile {
			docArtifact = &chat.Artifacts[i]
			break
		}
	}
	if docArtifact == nil {
		t.Fatalf("want a file artifact, got %+v", chat.Artifacts)
	}
	if docArtifact.DisplayName != "合同.pdf" {
		t.Fatalf("artifact name=%q", docArtifact.DisplayName)
	}

	// tool_result 消息 Content 仍只有 text（嵌套块不进文本）
	var toolResultMsg *ConvMessage
	for i := range chat.Messages {
		if chat.Messages[i].Source == SourceToolResult {
			toolResultMsg = &chat.Messages[i]
			break
		}
	}
	if toolResultMsg == nil {
		t.Fatal("no tool_result message")
	}
	if !strings.Contains(toolResultMsg.Content, "file content follows") {
		t.Fatalf("tool_result content=%q", toolResultMsg.Content)
	}
	if strings.Contains(toolResultMsg.Content, "image") || strings.Contains(toolResultMsg.Content, pngB64) {
		t.Fatalf("tool_result content should be text-only, got %q", toolResultMsg.Content)
	}
}

// 顶层 document 行为不变（回归）。
func TestParseAnthropicTopLevelDocumentUnchanged(t *testing.T) {
	pdfB64 := base64.StdEncoding.EncodeToString([]byte("pdf"))
	body := `{
		"model": "claude-3",
		"messages": [
			{"role": "user", "content": [
				{"type": "document", "title": "report.pdf", "source": {"type": "base64", "media_type": "application/pdf", "data": "` + pdfB64 + `"}}
			]}
		]
	}`
	chat, ok := ParseAnthropicMessagesRequest([]byte(body))
	if !ok {
		t.Fatal("parse failed")
	}
	found := false
	for _, a := range chat.Artifacts {
		if a.Kind == retentionartifact.KindFile && a.DisplayName == "report.pdf" {
			found = true
		}
	}
	if !found {
		t.Fatalf("top-level document lost: %+v", chat.Artifacts)
	}
}
