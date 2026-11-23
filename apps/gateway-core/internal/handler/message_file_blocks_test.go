package handler

import (
	"encoding/json"
	"testing"
)

// 文件块（input_file/file/file_data/data/data URL/file_id）提取测试。

func TestExtractFileBlockInputFileBase64(t *testing.T) {
	// OpenAI Responses input_file: file_data.base64
	content := `[{"type":"input_file","file_data":{"base64":"aGVsbG8=","mime_type":"text/plain"},"filename":"a.txt"}]`
	atts := extractAttachments(json.RawMessage(content))
	if len(atts) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(atts), atts)
	}
	if atts[0]["data_base64"] != "aGVsbG8=" {
		t.Fatalf("data_base64: %v", atts[0]["data_base64"])
	}
	if atts[0]["content_type"] != "text/plain" {
		t.Fatalf("content_type: %v", atts[0]["content_type"])
	}
	if atts[0]["file_name"] != "a.txt" {
		t.Fatalf("file_name: %v", atts[0]["file_name"])
	}
}

func TestExtractFileBlockFileDataURL(t *testing.T) {
	content := `[{"type":"file","file_data":"data:text/plain;base64,aGVsbG8=","filename":"b.txt"}]`
	atts := extractAttachments(json.RawMessage(content))
	if len(atts) != 1 || atts[0]["data_base64"] != "aGVsbG8=" {
		t.Fatalf("data url not extracted: %+v", atts)
	}
	if atts[0]["content_type"] != "text/plain" {
		t.Fatalf("content_type: %v", atts[0]["content_type"])
	}
}

func TestExtractFileBlockDataField(t *testing.T) {
	// {"type":"file","data":"<b64>"} + filename 推 mime
	content := `[{"type":"file","data":"aGVsbG8gd29ybGQ=","filename":"report.docx"}]`
	atts := extractAttachments(json.RawMessage(content))
	if len(atts) != 1 {
		t.Fatalf("expected 1: %+v", atts)
	}
	if atts[0]["content_type"] != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" {
		t.Fatalf("docx mime not inferred from filename: %v", atts[0]["content_type"])
	}
}

func TestExtractFileBlockReferenceID(t *testing.T) {
	// 无字节，只有 file_id → reference_id（交引擎两阶段协议查）
	content := `[{"type":"file","file_id":"file-abc123","filename":"c.pdf"}]`
	atts := extractAttachments(json.RawMessage(content))
	if len(atts) != 1 {
		t.Fatalf("expected 1: %+v", atts)
	}
	if atts[0]["reference_id"] != "file-abc123" {
		t.Fatalf("reference_id: %v", atts[0]["reference_id"])
	}
	if _, hasB64 := atts[0]["data_base64"]; hasB64 {
		t.Fatalf("reference block must not fabricate data_base64")
	}
	if atts[0]["object_id_unavailable"] != "reference_unverified" {
		t.Fatalf("unverified file reference must fail closed: %+v", atts[0])
	}
}

func TestResponsesStructuredInputFileIsPreservedForDLP(t *testing.T) {
	h := &ResponsesHandler{}
	req := &ResponsesRequest{
		Model: "m",
		Input: []interface{}{map[string]interface{}{
			"role": "user",
			"content": []interface{}{map[string]interface{}{
				"type": "input_file",
				"file_data": map[string]interface{}{
					"base64":    "aGVsbG8=",
					"mime_type": "text/plain",
				},
				"filename": "secret.txt",
			}},
		}},
	}

	chat, err := h.convertToChatRequest(req)
	if err != nil {
		t.Fatalf("structured responses input must convert: %v", err)
	}
	atts := extractAttachments(chat.Messages[0].Content)
	if len(atts) != 1 || atts[0]["data_base64"] != "aGVsbG8=" {
		t.Fatalf("Responses input_file was dropped before DLP: %+v", atts)
	}
}

func TestExtractFileBlockExtMimeInference(t *testing.T) {
	cases := map[string]string{
		"r.xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"p.pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"d.pdf":  "application/pdf",
		"n.csv":  "text/csv",
		"j.json": "application/json",
		"m.md":   "text/markdown",
		"x.xml":  "application/xml",
	}
	for fn, want := range cases {
		content := `[{"type":"file","data":"aGVsbG8gd29ybGQxMjM0NTY=","filename":"` + fn + `"}]`
		atts := extractAttachments(json.RawMessage(content))
		if len(atts) != 1 || atts[0]["content_type"] != want {
			t.Fatalf("%s mime: got %v want %s", fn, atts[0]["content_type"], want)
		}
	}
}

func TestExtractFileBlockFilenameOnlyPreservedAsMetadata(t *testing.T) {
	// 客户端先解析文件时可能只留下可信 file 块中的 filename；保留声明元数据，
	// 但不虚构 data_base64 / reference_id。
	content := `[{"type":"file","filename":"report.pdf"}]`
	atts := extractAttachments(json.RawMessage(content))
	if len(atts) != 1 {
		t.Fatalf("filename-only file metadata was dropped: %+v", atts)
	}
	if atts[0]["file_name"] != "report.pdf" || atts[0]["content_type"] != "application/pdf" {
		t.Fatalf("filename-only metadata mismatch: %+v", atts[0])
	}
	if atts[0]["source"] != "json_file_metadata" {
		t.Fatalf("filename-only metadata source mismatch: %+v", atts[0])
	}
	if _, hasB64 := atts[0]["data_base64"]; hasB64 {
		t.Fatalf("filename-only metadata must not fabricate bytes: %+v", atts[0])
	}
	if _, hasRef := atts[0]["reference_id"]; hasRef {
		t.Fatalf("filename-only metadata must not fabricate a reference: %+v", atts[0])
	}
}

func TestPlainTextMentioningPDFIsNotAttachmentEvidence(t *testing.T) {
	content := `[{"type":"text","text":"请说明 report.pdf 怎么打开","filename":"report.pdf"}]`
	if atts := extractAttachments(json.RawMessage(content)); atts != nil {
		t.Fatalf("plain text must not be reclassified as attachment metadata: %+v", atts)
	}
}

func TestExtractFileBlockHTTPUrlPreservedAsUnverifiedReference(t *testing.T) {
	// http url 无字节 → 保留为未物化引用，交安全层 fail-closed。
	content := `[{"type":"file","file_data":{"url":"https://example.com/a.docx"},"filename":"a.docx"}]`
	atts := extractAttachments(json.RawMessage(content))
	if len(atts) != 1 {
		t.Fatalf("http url reference should be preserved: %+v", atts)
	}
	if atts[0]["reference_id"] != "https://example.com/a.docx" {
		t.Fatalf("reference_id: %+v", atts[0])
	}
	if atts[0]["object_id_unavailable"] != "reference_unverified" {
		t.Fatalf("http url must remain unverified until materialized: %+v", atts[0])
	}
}
