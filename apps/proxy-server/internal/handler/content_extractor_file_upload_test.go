package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractRequestContent_RawFileBodiesBecomeAttachments(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		fileName    string
		body        []byte
	}{
		{name: "pdf", contentType: "application/pdf", fileName: "report.pdf", body: []byte("%PDF-1.4\nsecret")},
		{name: "docx", contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", fileName: "report.docx", body: []byte("PK\x03\x04docx")},
		{name: "xlsx", contentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", fileName: "report.xlsx", body: []byte("PK\x03\x04xlsx")},
		{name: "pptx", contentType: "application/vnd.openxmlformats-officedocument.presentationml.presentation", fileName: "report.pptx", body: []byte("PK\x03\x04pptx")},
		{name: "zip", contentType: "application/zip", fileName: "archive.zip", body: []byte("PK\x03\x04zip")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://upload.example.test/upload/"+tt.fileName, bytes.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)

			got := extractRequestContent(req, tt.body)
			if len(got.Attachments) != 1 {
				t.Fatalf("raw %s body attachments=%d, want 1: %+v", tt.name, len(got.Attachments), got)
			}
			if got.Attachments[0].DataBase64 == "" {
				t.Fatalf("raw %s body has no data_base64: %+v", tt.name, got.Attachments[0])
			}
			if got.Attachments[0].FileName != "" && got.Attachments[0].FileName != tt.fileName {
				t.Fatalf("file name=%q, want %q", got.Attachments[0].FileName, tt.fileName)
			}
		})
	}
}

func TestExtractRequestContent_UnknownJSONFileBlockBecomesAttachment(t *testing.T) {
	body := []byte(`{"payload":{"type":"document","title":"report.pdf","source":{"type":"base64","media_type":"application/pdf","data":"JVBERi0xLjQ="}}}`)
	req := httptest.NewRequest(http.MethodPost, "https://files.example.test/opaque", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	got := extractRequestContent(req, body)
	if len(got.Attachments) != 1 {
		t.Fatalf("unknown JSON file block attachments=%d, want 1: %+v", len(got.Attachments), got)
	}
	attachment := got.Attachments[0]
	if attachment.ContentType != "application/pdf" || attachment.FileName != "report.pdf" || attachment.DataBase64 != "JVBERi0xLjQ=" {
		t.Fatalf("unexpected unknown JSON attachment: %+v", attachment)
	}
}

func TestExtractRequestContent_NestedFileDataObjectBecomesAttachment(t *testing.T) {
	body := []byte(`{"payload":{"type":"file","filename":"report.pdf","file_data":{"base64":"JVBERi0xLjQ="}}}`)
	req := httptest.NewRequest(http.MethodPost, "https://files.example.test/opaque", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	got := extractRequestContent(req, body)
	if len(got.Attachments) != 1 {
		t.Fatalf("nested file_data object attachments=%d, want 1: %+v", len(got.Attachments), got)
	}
	attachment := got.Attachments[0]
	if attachment.ContentType != "application/pdf" || attachment.FileName != "report.pdf" || attachment.DataBase64 != "JVBERi0xLjQ=" {
		t.Fatalf("unexpected nested file_data attachment: %+v", attachment)
	}
}
