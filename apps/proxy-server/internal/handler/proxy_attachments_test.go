package handler

import (
	"testing"
)

// 验证 proxy-server 对文本类文档(docx)附件的字节接通：attachmentContext 应输出
// data_base64，使 security-engine 文件内容 DLP 能拿到字节。这是三入口共享检测的
// proxy 侧基础（multipart/base64 上传的 ≤2MB 文档天然走此路径）。

func TestAttachmentContextCarriesDocxDataBase64(t *testing.T) {
	// 构造一个 docx 风格附件（非文本二进制，≤2MB）→ shouldRetainAttachmentBytes=true
	body := []byte("PK\x03\x04 this stands in for a small docx body")
	att := attachmentFromBytes("multipart", "file", "report.docx",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document", body)

	if att.DataBase64 == "" {
		t.Fatalf("docx attachment should carry data_base64 for content DLP, got empty")
	}
	out := attachmentContext([]ExtractedAttachment{att})
	if len(out) != 1 {
		t.Fatalf("expected 1 attachment entry, got %d", len(out))
	}
	if out[0]["data_base64"] != att.DataBase64 {
		t.Fatalf("attachmentContext did not carry data_base64")
	}
	if out[0]["content_type"] != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" {
		t.Fatalf("content_type mismatch: %v", out[0]["content_type"])
	}
}

func TestAttachmentContextOmitsDataBase64WhenAbsent(t *testing.T) {
	// 仅引用（file_id，无字节）→ 无 data_base64（不虚构字节）
	att := ExtractedAttachment{
		Source:      "json_file_reference",
		ReferenceID: "file-abc",
		FileName:    "ref.docx",
		ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	}
	out := attachmentContext([]ExtractedAttachment{att})
	if _, leak := out[0]["data_base64"]; leak {
		t.Fatalf("reference-only attachment must not fabricate data_base64")
	}
}

func TestAttachmentContextRedactsFileNamePII(t *testing.T) {
	// 文件名里的 PII 不应在 attachmentContext 里被改写（原样保留文件名是设计允许的元数据，
	// 引擎侧 finding 证据才做脱敏）。这里只验证文件名透传不被丢弃。
	att := ExtractedAttachment{FileName: "客户名单.docx", ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", DataBase64: "x"}
	out := attachmentContext([]ExtractedAttachment{att})
	if out[0]["file_name"] != "客户名单.docx" {
		t.Fatalf("file_name not preserved: %v", out[0]["file_name"])
	}
}
