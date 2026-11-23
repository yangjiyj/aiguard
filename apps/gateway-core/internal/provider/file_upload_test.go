package provider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIAdapterSupportsExplicitFilesEndpoint(t *testing.T) {
	if !(&OpenAIAdapter{}).SupportsEndpoint("files") {
		t.Fatal("OpenAI-compatible adapter must expose the explicit files endpoint")
	}
}

func TestOpenAIAdapterUploadFileUsesConfiguredEndpointAndMultipart(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/files" {
			t.Fatalf("path = %s, want /v1/files", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer provider-secret" {
			t.Fatalf("authorization = %q", got)
		}
		if err := r.ParseMultipartForm(2 << 20); err != nil {
			t.Fatalf("parse multipart form: %v", err)
		}
		if got := r.FormValue("purpose"); got != "assistants" {
			t.Fatalf("purpose = %q", got)
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			t.Fatalf("uploaded form file: %v", err)
		}
		defer file.Close()
		if header.Filename != "customer-report.pdf" {
			t.Fatalf("filename = %q", header.Filename)
		}
		body, err := io.ReadAll(file)
		if err != nil {
			t.Fatalf("read file: %v", err)
		}
		if string(body) != "%PDF-safe-sample" {
			t.Fatalf("file body = %q", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"file_upstream_1","object":"file"}`))
	}))
	defer upstream.Close()

	adapter := &OpenAIAdapter{BaseURL: upstream.URL + "/v1", APIKey: "provider-secret"}
	got, err := adapter.UploadFile(context.Background(), FileUploadRequest{
		FileName:    "customer-report.pdf",
		ContentType: "application/pdf",
		Purpose:     "assistants",
		Content:     []byte("%PDF-safe-sample"),
	})
	if err != nil {
		t.Fatalf("upload file: %v", err)
	}
	if string(got) != `{"id":"file_upstream_1","object":"file"}` {
		t.Fatalf("response = %s", got)
	}
}

func TestOpenAIAdapterUploadFileRejectsMissingBaseURL(t *testing.T) {
	_, err := (&OpenAIAdapter{APIKey: "provider-secret"}).UploadFile(context.Background(), FileUploadRequest{
		FileName: "customer-report.pdf",
		Content:  []byte("%PDF-safe-sample"),
	})
	if err == nil || !strings.Contains(err.Error(), "base URL") {
		t.Fatalf("missing base URL error = %v", err)
	}
}
