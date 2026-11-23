package handler

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestBuildAccessContentLogRedactsSecretsAndKeepsAttachmentMetadata(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_llm",
		TenantID:        "tenant_default",
		Provider:        "deepseek",
		Product:         "deepseek_api",
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	req := ExtractedContent{
		Text:        "请分析 key=" + testOpenAIProjectKey() + " 和 " + testAWSAccessKeyID(),
		ContentType: "json",
		Attachments: []ExtractedAttachment{
			{Source: "multipart", FileName: "secret.env", ContentType: "text/plain", Size: 64, SHA256: "abc123", TextPreview: "API_KEY=" + testOpenAIProjectKey()},
		},
	}
	resp := ExtractedContent{Text: "模型输出正常", ContentType: "json"}

	payload, ok := buildAccessContentLogPayload(record, req, resp)

	if !ok {
		t.Fatal("LLM content-retained record should build a payload")
	}
	combined := payload.RequestContentRedacted + payload.ResponseContentRedacted + payload.FileMetadataJSON
	for _, leaked := range []string{testOpenAIProjectKey(), testAWSAccessKeyID()} {
		if strings.Contains(combined, leaked) {
			t.Fatalf("retention payload leaked secret %q: %s", leaked, combined)
		}
	}
	for _, want := range []string{"secret.env", "abc123", "模型输出正常"} {
		if !strings.Contains(combined, want) {
			t.Fatalf("retention payload missing %q: %+v", want, payload)
		}
	}
}

func TestBuildAccessContentLogExternalizesReturnedImagePreviewData(t *testing.T) {
	store := &fakeRetentionStore{}
	retentionUntil := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	record := ProxyAuditRecord{
		RequestID:       "req_image_response",
		TenantID:        "tenant_default",
		Provider:        "doubao",
		Product:         "doubao",
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	resp := ExtractedContent{
		Text:        "已生成图片",
		ContentType: "json",
		Attachments: []ExtractedAttachment{
			{Source: "json_data_url", FieldName: "content.image", ContentType: "image/png", Size: 5, SHA256: "imgsha", DataBase64: "aGVsbG8="},
		},
	}

	payload, ok := buildAccessContentLogPayloadWithRetentionStore(context.Background(), store, retentionUntil, record, ExtractedContent{}, resp)

	if !ok {
		t.Fatal("image response should build a retained content payload")
	}
	for _, want := range []string{`"stage":"response"`, `"content_type":"image/png"`, `"object_key":"tenant_default/req_image_response/response/content.image/object-1"`, `"storage_backend":"local"`, `"retention_status":"externalized"`} {
		if !strings.Contains(payload.FileMetadataJSON, want) {
			t.Fatalf("image metadata missing %s: %s", want, payload.FileMetadataJSON)
		}
	}
	if strings.Contains(payload.FileMetadataJSON, "data_base64") || strings.Contains(payload.FileMetadataJSON, "aGVsbG8=") {
		t.Fatalf("image metadata should not keep raw base64: %s", payload.FileMetadataJSON)
	}
}

func TestBuildAccessContentLogScrubsUploadedBinaryDataWhenStoreUnavailable(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_pdf_upload",
		TenantID:        "tenant_default",
		Provider:        "deepseek",
		Product:         "deepseek_chat",
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	req := ExtractedContent{
		Text:        "[file:report.pdf type=application/pdf size=7 sha256=pdfsha]",
		ContentType: "multipart/form-data",
		Attachments: []ExtractedAttachment{
			{Source: "multipart", FieldName: "file", FileName: "report.pdf", ContentType: "application/pdf", Size: 7, SHA256: "pdfsha", DataBase64: "JVBERi0x"},
		},
	}

	payload, ok := buildAccessContentLogPayload(record, req, ExtractedContent{})

	if !ok {
		t.Fatal("uploaded binary should build a retained content payload")
	}
	for _, want := range []string{`"stage":"request"`, `"file_name":"report.pdf"`, `"content_type":"application/pdf"`, `"retention_status":"externalize_unavailable"`} {
		if !strings.Contains(payload.FileMetadataJSON, want) {
			t.Fatalf("binary upload metadata missing %s: %s", want, payload.FileMetadataJSON)
		}
	}
	if strings.Contains(payload.FileMetadataJSON, "data_base64") || strings.Contains(payload.FileMetadataJSON, "JVBERi0x") {
		t.Fatalf("binary upload metadata should not keep raw base64: %s", payload.FileMetadataJSON)
	}
}

func TestBuildAccessContentLogRemovesPostgresNULBytes(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_nul_bytes",
		TenantID:        "tenant_default",
		Provider:        "deepseek",
		Product:         "deepseek_chat",
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	req := ExtractedContent{
		Text: "你\x00好",
		Attachments: []ExtractedAttachment{
			{Source: "json", FileName: "bad\x00.png", TextPreview: "pre\x00view", DataBase64: "abc\x00def"},
		},
	}
	resp := ExtractedContent{Text: "答\x00案"}

	payload, ok := buildAccessContentLogPayload(record, req, resp)

	if !ok {
		t.Fatal("NUL-containing content should still build a retained payload")
	}
	combined := payload.RequestContentRedacted + payload.ResponseContentRedacted + payload.FileMetadataJSON
	if strings.Contains(combined, "\x00") {
		t.Fatalf("retained payload contains raw NUL byte: %#v", combined)
	}
	for _, want := range []string{"你好", "答案", "bad.png", "preview"} {
		if !strings.Contains(combined, want) {
			t.Fatalf("retained payload missing sanitized content %q: %s", want, combined)
		}
	}
	if strings.Contains(combined, "data_base64") || strings.Contains(combined, "abcdef") {
		t.Fatalf("retained payload should not keep raw base64: %s", combined)
	}
}

func TestBuildAccessContentLogSkipsRegularPublicSummary(t *testing.T) {
	record := ProxyAuditRecord{RequestID: "req_regular", TenantID: "tenant_default", AccessType: "normal_public", RetentionLevel: "summary", ContentRetained: false}
	payload, ok := buildAccessContentLogPayload(record, ExtractedContent{Text: "query secret"}, ExtractedContent{})
	if ok || payload.RequestID != "" {
		t.Fatalf("regular public summary should not retain content: ok=%v payload=%+v", ok, payload)
	}
}

func TestBuildAccessContentLogSkipsEmptyLLMContent(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_empty_llm",
		TenantID:        "tenant_default",
		Provider:        "deepseek",
		Product:         "deepseek_chat",
		RetentionLevel:  "content",
		ContentRetained: true,
	}

	payload, ok := buildAccessContentLogPayload(record, ExtractedContent{}, ExtractedContent{})

	if ok || payload.RequestID != "" {
		t.Fatalf("empty LLM extraction should not create retained content log: ok=%v payload=%+v", ok, payload)
	}
}

func TestExtractRetainableResponseContentSkipsStaticJavaScript(t *testing.T) {
	body := []byte(`function boot(){return "doubao app shell, not a model reply"}`)

	extracted := extractRetainableResponseContent(body, "application/javascript; charset=utf-8")

	if strings.TrimSpace(extracted.Text) != "" {
		t.Fatalf("static JavaScript should not be retained as model answer: %q", extracted.Text)
	}
	if len(extracted.Attachments) != 0 {
		t.Fatalf("static JavaScript should not create retained attachments: %+v", extracted.Attachments)
	}
}

func TestRawDumpPathOfInterestIncludesWorkBuddyInvoke(t *testing.T) {
	for _, path := range []string{"/api/invoke", "//api/invoke", "/api/stream", "/v1/responses", "/v1/responses/"} {
		if !rawDumpPathOfInterest(path) {
			t.Fatalf("WorkBuddy path %q should be eligible for temporary raw-dump diagnostics", path)
		}
	}
	if rawDumpPathOfInterest("/v2/activity/growth/buddy/info") {
		t.Fatal("WorkBuddy growth/telemetry ping should not consume raw-dump samples")
	}
	if !rawDumpPathOfInterest("/api/v0/chat/completion") {
		t.Fatal("deepseek chat completion path should be of interest for raw dump")
	}
}

func TestRawDumpPathOfInterestIncludesCopilotAttachmentUpload(t *testing.T) {
	// GitHub Copilot 聊天图片上传(uploads.github.com/copilot/chat/attachments)承载用户真实图片
	// 字节与上传响应里的 attachment id——定位「对话引用↔上传字节」关联所必需,故应可临时诊断落盘。
	for _, path := range []string{"/copilot/chat/attachments", "/copilot/chat/attachments/"} {
		if !rawDumpPathOfInterest(path) {
			t.Fatalf("Copilot attachment upload path %q should be eligible for temporary raw-dump diagnostics", path)
		}
	}
}
