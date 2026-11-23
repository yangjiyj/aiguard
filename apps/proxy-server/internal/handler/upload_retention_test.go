package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestKimiUploadMultipartRequestCapturesBytesAndExternalizesForChatReference(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "diagram.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(testPNGBytes(t, 48, 32)); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("file_id", "file_kimi_upload_abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://www.kimi.com/apiv2-files/file/upload", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", writer.FormDataContentType())

	upload := extractRequestContentWithDecoder(req, body.Bytes(), "kimi_web")
	if len(upload.Attachments) != 1 {
		t.Fatalf("Kimi multipart upload should produce one byte attachment, got %+v", upload.Attachments)
	}
	uploaded := upload.Attachments[0]
	if uploaded.DataBase64 == "" || uploaded.SHA256 == "" || uploaded.Size <= 0 {
		t.Fatalf("Kimi upload attachment missing retained bytes metadata: %+v", uploaded)
	}
	if uploaded.ReferenceID != "file_kimi_upload_abcdef" {
		t.Fatalf("Kimi upload should carry reference_id from multipart fields, got %+v", uploaded)
	}

	chat := ExtractedContent{Attachments: []ExtractedAttachment{{
		Source:      "json_file_reference",
		FieldName:   "message.blocks.file.id",
		ReferenceID: "file_kimi_upload_abcdef",
		ContentType: "reference/file-id",
	}}}
	upload, _ = resolveRetainedContents("tenant-kimi", "moonshot", upload, ExtractedContent{})
	chat, _ = resolveRetainedContents("tenant-kimi", "moonshot", chat, ExtractedContent{})

	store := &fakeRetentionStore{}
	uploadRecord := ProxyAuditRecord{
		RequestID:       "req_kimi_upload",
		TenantID:        "tenant-kimi",
		Provider:        "moonshot",
		Product:         "kimi",
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	if _, ok := buildAccessContentLogPayloadWithRetentionStore(context.Background(), store, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), uploadRecord, upload, ExtractedContent{}); !ok {
		t.Fatal("upload request should build retained content payload")
	}

	chatRecord := uploadRecord
	chatRecord.RequestID = "req_kimi_chat"
	payload, ok := buildAccessContentLogPayloadWithRetentionStore(context.Background(), store, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), chatRecord, chat, ExtractedContent{})
	if !ok {
		t.Fatal("chat reference should build retained content payload")
	}

	var metadata []retainedAttachmentMetadata
	if err := json.Unmarshal([]byte(payload.FileMetadataJSON), &metadata); err != nil {
		t.Fatalf("decode metadata: %v\n%s", err, payload.FileMetadataJSON)
	}
	if len(metadata) != 1 {
		t.Fatalf("chat metadata should merge reference with retained upload bytes, got %+v", metadata)
	}
	item := metadata[0]
	if item.ReferenceID != "file_kimi_upload_abcdef" || item.ObjectKey == "" || item.RetentionStatus != "externalized" {
		t.Fatalf("chat reference was not linked to externalized upload bytes: %+v", item)
	}
	if item.FileName != "diagram.png" || item.ContentType != "image/png" || item.Size <= 0 {
		t.Fatalf("linked metadata lost upload file details: %+v", item)
	}
	if store.putCalls != 1 || store.body == "" {
		t.Fatalf("upload bytes should be stored once and later referenced, calls=%d body=%q", store.putCalls, store.body)
	}
	if strings.Contains(payload.FileMetadataJSON, "data_base64") {
		t.Fatalf("metadata must not keep raw data_base64 after externalization: %s", payload.FileMetadataJSON)
	}
}

func TestReferenceOnlyDownloadURLIsMarkedReferenceOnly(t *testing.T) {
	record := ProxyAuditRecord{
		RequestID:       "req_url_only",
		TenantID:        "tenant-default",
		Provider:        "alibaba",
		Product:         "qwen",
		RetentionLevel:  "content",
		ContentRetained: true,
	}
	reqContent := ExtractedContent{Attachments: []ExtractedAttachment{{
		Source:      "json_image_url",
		FieldName:   "attachments.0.url",
		FileName:    "qwen-image.png",
		ReferenceID: "oss-qwen-image",
		ContentType: "image/png",
		DownloadURL: "https://dashscope-result.oss-cn-hangzhou.aliyuncs.com/qwen-image.png?signature=redacted",
	}}}

	payload, ok := buildAccessContentLogPayload(record, reqContent, ExtractedContent{})
	if !ok {
		t.Fatal("url-only attachment should still build retained content metadata")
	}
	if !strings.Contains(payload.FileMetadataJSON, `"retention_status":"reference_only"`) {
		t.Fatalf("reference-only attachment should be explicitly marked, got %s", payload.FileMetadataJSON)
	}
	if strings.Contains(payload.FileMetadataJSON, `"object_key"`) || strings.Contains(payload.FileMetadataJSON, `"data_base64"`) {
		t.Fatalf("reference-only metadata should not pretend to have retained bytes: %s", payload.FileMetadataJSON)
	}
}

func TestExternalizeRetainedImagePreservesOriginalBytes(t *testing.T) {
	store := &fakeRetentionStore{}
	raw := testPNGBytes(t, 1200, 900)
	items := []retainedAttachmentMetadata{{
		Source:      "multipart",
		Stage:       "request",
		FieldName:   "file",
		FileName:    "large.png",
		ContentType: "image/png",
		Size:        int64(len(raw)),
		DataBase64:  base64.StdEncoding.EncodeToString(raw),
	}}

	got := externalizeRetainedAttachmentData(context.Background(), store, ProxyAuditRecord{TenantID: "tenant-img", RequestID: "req_img_upload"}, time.Now().UTC(), items)

	if store.putCalls != 1 {
		t.Fatalf("PutObject calls = %d, want 1", store.putCalls)
	}
	if store.input.ContentType != "image/png" || store.input.FileName != "large.png" {
		t.Fatalf("stored original metadata changed: %+v", store.input)
	}
	if !bytes.Equal([]byte(store.body), raw) {
		t.Fatal("stored image bytes must equal the uploaded PNG")
	}
	if got[0].ContentType != "image/png" || got[0].FileName != "large.png" || got[0].RetentionStatus != "externalized" {
		t.Fatalf("externalized metadata should describe original object: %+v", got[0])
	}
}

func testPNGBytes(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 5), G: uint8(y * 7), B: 180, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	if _, err := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
