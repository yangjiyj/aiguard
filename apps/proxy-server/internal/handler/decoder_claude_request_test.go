package handler

import (
	"strings"
	"testing"
)

// 夹具按 2026-06-22 Chrome 扩展实抓的 claude.ai completion 请求体结构构造。
const claudeCompletionTextDocBody = `{
  "prompt": "正向代理适配测试 CLAUDE-TEXT-7788 请回复收到",
  "parent_message_uuid": "00000000-0000-4000-8000-000000000000",
  "model": "claude-opus-4-8",
  "rendering_mode": "messages",
  "attachments": [
    {
      "file_name": "CLAUDE-FILE-7788.txt",
      "file_type": "text/plain",
      "file_size": 115,
      "extracted_content": "CLAUDE-FILE-7788 这是文件外发抓包测试。敏感占位: 病案号 BR20260622",
      "origin": "upload",
      "kind": "document",
      "path": ""
    }
  ],
  "files": ["img-uuid-7788"]
}`

const claudeCompletionImageOnlyBody = `{
  "prompt": "CLAUDE-IMG-7788 这是图片抓包测试",
  "attachments": [],
  "files": ["img-uuid-aaaa", "img-uuid-bbbb"]
}`

func TestDecodeClaudeWebRequest_TextAndDocument(t *testing.T) {
	got, ok := decodeClaudeWebRequest(nil, []byte(claudeCompletionTextDocBody), "application/json")
	if !ok {
		t.Fatalf("expected match, got ok=false")
	}
	// 用户文字进入正文
	if !strings.Contains(got.Text, "CLAUDE-TEXT-7788") {
		t.Errorf("Text 缺少用户文字: %q", got.Text)
	}
	// 文档 extracted_content 并入正文，供 DLP 检测（含敏感占位）
	if !strings.Contains(got.Text, "病案号 BR20260622") {
		t.Errorf("Text 缺少文档提取文本: %q", got.Text)
	}
	// 文档附件元数据
	var doc *ExtractedAttachment
	var imgRef *ExtractedAttachment
	for i := range got.Attachments {
		switch got.Attachments[i].Source {
		case "claude_web_attachment":
			doc = &got.Attachments[i]
		case "claude_web_file":
			imgRef = &got.Attachments[i]
		}
	}
	if doc == nil {
		t.Fatalf("缺少文档附件")
	}
	if doc.FileName != "CLAUDE-FILE-7788.txt" || doc.ContentType != "text/plain" || doc.Size != 115 {
		t.Errorf("文档附件元数据不对: %+v", *doc)
	}
	if doc.TextPreview == "" {
		t.Errorf("文档附件应带截断预览")
	}
	// 图片以 file_uuid 引用
	if imgRef == nil || imgRef.ReferenceID != "img-uuid-7788" {
		t.Errorf("图片 file_uuid 引用不对: %+v", imgRef)
	}
}

func TestDecodeClaudeWebRequest_ImageOnly(t *testing.T) {
	got, ok := decodeClaudeWebRequest(nil, []byte(claudeCompletionImageOnlyBody), "application/json")
	if !ok {
		t.Fatalf("expected match")
	}
	if !strings.Contains(got.Text, "CLAUDE-IMG-7788") {
		t.Errorf("Text 缺少文字: %q", got.Text)
	}
	refs := 0
	for _, a := range got.Attachments {
		if a.Source == "claude_web_file" {
			refs++
		}
	}
	if refs != 2 {
		t.Errorf("应有 2 个图片 file_uuid 引用, got %d", refs)
	}
}

func TestDecodeClaudeWebRequest_MultipartUploadPassthrough(t *testing.T) {
	// wiggle/upload-file 是 multipart 字节，本增量不处理，应返回 false 不误吞。
	if _, ok := decodeClaudeWebRequest(nil, []byte("\x89PNG\r\n\x1a\nrawbytes"), "multipart/form-data; boundary=x"); ok {
		t.Errorf("multipart 上传不应命中 JSON 解码器")
	}
}

func TestDecodeClaudeWebRequest_NoFields(t *testing.T) {
	if _, ok := decodeClaudeWebRequest(nil, []byte(`{"timezone":"Asia/Shanghai","model":"x"}`), "application/json"); ok {
		t.Errorf("无 prompt/attachments/files 不应命中")
	}
}
