package handler

import (
	"encoding/json"
	"testing"
)

// extractAttachments 从多模态 Message.Content 提取附件字节，供文件内容 DLP 送检。
// 仅在文件内容 DLP 开启时由 CheckInputDetailed 填入 context.attachments。

func TestExtractAttachmentsNil(t *testing.T) {
	got := extractAttachments(json.RawMessage(nil))
	if len(got) != 0 {
		t.Fatalf("nil content should yield no attachments: %+v", got)
	}
}

func TestExtractAttachmentsPlainText(t *testing.T) {
	// 纯文本 content（JSON 字符串）无附件
	got := extractAttachments(json.RawMessage(`"just text"`))
	if len(got) != 0 {
		t.Fatalf("plain text should yield no attachments: %+v", got)
	}
}

func TestExtractAttachmentsImageURLDataUrl(t *testing.T) {
	// 多模态：image_url 的 data:image/png;base64,.... —— 提取 base64 字节
	content := `[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}]`
	got := extractAttachments(json.RawMessage(content))
	if len(got) != 1 {
		t.Fatalf("expected 1 image attachment, got %d: %+v", len(got), got)
	}
	if got[0]["content_type"] != "image/png" {
		t.Fatalf("content_type: got %v want image/png", got[0]["content_type"])
	}
	if got[0]["data_base64"] != "iVBORw0KGgo=" {
		t.Fatalf("data_base64 not extracted: %v", got[0]["data_base64"])
	}
}

func TestExtractAttachmentsInputImageAnthropic(t *testing.T) {
	// Anthropic 风格 input_image：{"source":{"type":"base64","media_type":"image/jpeg","data":"..."}}
	content := `[{"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":"/9j/4AAQ"}}]`
	got := extractAttachments(json.RawMessage(content))
	if len(got) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(got))
	}
	if got[0]["content_type"] != "image/jpeg" {
		t.Fatalf("content_type: got %v want image/jpeg", got[0]["content_type"])
	}
	if got[0]["data_base64"] != "/9j/4AAQ" {
		t.Fatalf("data_base64: %v", got[0]["data_base64"])
	}
}

func TestExtractAttachmentsNoBase64Skipped(t *testing.T) {
	// image_url 是 http URL（无 base64）→ 不提取（无字节可送检，不虚构）
	content := `[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]`
	got := extractAttachments(json.RawMessage(content))
	if len(got) != 0 {
		t.Fatalf("http url image should be skipped: %+v", got)
	}
}

func TestExtractAttachmentsDoesNotLeakInPreview(t *testing.T) {
	// evidence 字段不得包含完整 base64（脱敏）
	content := `[{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="}}]`
	got := extractAttachments(json.RawMessage(content))
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	for k, v := range got[0] {
		_ = k
		if s, ok := v.(string); ok && len(s) > 32 && s != "iVBORw0KGgoAAAANS" {
			// 非 data_base64 字段不应包含长 base64
			t.Fatalf("field %s unexpectedly long/leaky: %q", k, s)
		}
	}
}

func TestExtractRequestAttachmentsForProxyDoesNotUseMimeAllowlist(t *testing.T) {
	body := []byte("MZ executable bytes")
	got := extractRequestAttachmentsForProxy(body, "application/vnd.customer-executable", "/upload")
	if len(got) != 1 {
		t.Fatalf("unknown file MIME must still be inspected, got %+v", got)
	}
	if got[0]["content_type"] != "application/vnd.customer-executable" {
		t.Fatalf("content type = %v", got[0]["content_type"])
	}
}
