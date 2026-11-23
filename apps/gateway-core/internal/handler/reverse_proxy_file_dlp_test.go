package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReverseProxyStructuredFileAttachmentReachesSecurityEngine(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")

	var received map[string]interface{}
	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode security request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"action\":\"block\",\"findings\":[{\"type\":\"file\",\"category\":\"phone_cn\",\"action\":\"block\"}]}")
	}))
	defer securityServer.Close()

	body := "{\"model\":\"claude\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"请审查附件\"},{\"type\":\"document\",\"source\":{\"type\":\"base64\",\"media_type\":\"application/pdf\",\"data\":\"JVBERi0xLjQ=\"},\"title\":\"report.pdf\"}]}]}"
	req := httptest.NewRequest(http.MethodPost, "https://api.example.test/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h := &ReverseProxyHandler{
		tenantID:    "tenant_default",
		securityURL: securityServer.URL,
		client:      securityServer.Client(),
	}

	decision, err := h.checkRequestSecurityStructured(
		req.Context(), "reverse-file-test", req, []byte(body),
		"application/json", "api.example.test:443", "/v1/messages",
	)
	if err != nil {
		t.Fatalf("checkRequestSecurityStructured: %v", err)
	}
	if decision.Allowed || decision.Action != "block" {
		t.Fatalf("file finding should block, got allowed=%v action=%q", decision.Allowed, decision.Action)
	}

	context, ok := received["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("security context missing: %#v", received)
	}
	attachments, ok := context["attachments"].([]interface{})
	if !ok || len(attachments) != 1 {
		t.Fatalf("file attachment missing from reverse-proxy security context: %#v", context["attachments"])
	}
	attachment, ok := attachments[0].(map[string]interface{})
	if !ok || attachment["content_type"] != "application/pdf" || attachment["data_base64"] != "JVBERi0xLjQ=" {
		t.Fatalf("unexpected reverse-proxy attachment: %#v", attachments[0])
	}
}

func TestReverseProxyStructuredFileOnlyRequestStillReachesSecurityEngine(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")

	calls := 0
	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"action\":\"block\",\"findings\":[{\"type\":\"file\",\"action\":\"block\"}]}")
	}))
	defer securityServer.Close()

	body := "{\"model\":\"claude\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"document\",\"source\":{\"type\":\"base64\",\"media_type\":\"application/pdf\",\"data\":\"JVBERi0xLjQ=\"},\"title\":\"report.pdf\"}]}]}"
	req := httptest.NewRequest(http.MethodPost, "https://api.example.test/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h := &ReverseProxyHandler{
		tenantID:    "tenant_default",
		securityURL: securityServer.URL,
		client:      securityServer.Client(),
	}

	decision, err := h.checkRequestSecurityStructured(
		req.Context(), "reverse-file-only-test", req, []byte(body),
		"application/json", "api.example.test:443", "/v1/messages",
	)
	if err != nil {
		t.Fatalf("checkRequestSecurityStructured: %v", err)
	}
	if calls != 1 || decision.Allowed || decision.Action != "block" {
		t.Fatalf("pure file request was not blocked: calls=%d allowed=%v action=%q", calls, decision.Allowed, decision.Action)
	}
}

func TestReverseProxyRawFileBodyReachesSecurityEngine(t *testing.T) {
	var received map[string]interface{}
	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode security request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"action\":\"block\",\"findings\":[{\"type\":\"file\",\"action\":\"block\"}]}")
	}))
	defer securityServer.Close()

	body := []byte("%PDF-1.7\ncustomer phone 13812345678\n")
	h := &ReverseProxyHandler{
		tenantID:    "tenant_default",
		securityURL: securityServer.URL,
		client:      securityServer.Client(),
	}

	decision, err := h.checkRequestSecurity(
		context.Background(), "reverse-raw-file-test", body,
		"application/pdf", "files.example.test:443", "/upload/report.pdf",
	)
	if err != nil {
		t.Fatalf("checkRequestSecurity: %v", err)
	}
	if decision.Allowed || decision.Action != "block" {
		t.Fatalf("raw file finding should block, got allowed=%v action=%q", decision.Allowed, decision.Action)
	}

	contextValue, ok := received["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("security context missing: %#v", received)
	}
	attachments, ok := contextValue["attachments"].([]interface{})
	if !ok || len(attachments) != 1 {
		t.Fatalf("raw file attachment missing from reverse-proxy security context: %#v", contextValue["attachments"])
	}
	attachment, ok := attachments[0].(map[string]interface{})
	if !ok || attachment["content_type"] != "application/pdf" || attachment["data_base64"] == "" {
		t.Fatalf("unexpected raw reverse-proxy attachment: %#v", attachments[0])
	}
}

func TestReverseProxyMultipartFileBodyReachesSecurityEngine(t *testing.T) {
	var received map[string]interface{}
	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode security request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"block","findings":[{"type":"file","action":"block"}]}`)
	}))
	defer securityServer.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "report.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("%PDF-1.7\ncustomer phone 13812345678\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	h := &ReverseProxyHandler{
		tenantID:    "tenant_default",
		securityURL: securityServer.URL,
		client:      securityServer.Client(),
	}
	decision, err := h.checkRequestSecurity(
		context.Background(), "reverse-multipart-file-test", body.Bytes(),
		writer.FormDataContentType(), "files.example.test:443", "/upload",
	)
	if err != nil {
		t.Fatalf("checkRequestSecurity: %v", err)
	}
	if decision.Allowed || decision.Action != "block" {
		t.Fatalf("multipart file finding should block, got allowed=%v action=%q", decision.Allowed, decision.Action)
	}

	contextValue, ok := received["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("security context missing: %#v", received)
	}
	attachments, ok := contextValue["attachments"].([]interface{})
	if !ok || len(attachments) != 1 {
		t.Fatalf("multipart attachment missing from reverse-proxy security context: %#v", contextValue["attachments"])
	}
	attachment, ok := attachments[0].(map[string]interface{})
	if !ok || attachment["content_type"] != "application/pdf" || attachment["file_name"] != "report.pdf" || attachment["data_base64"] == "" {
		t.Fatalf("unexpected multipart reverse-proxy attachment: %#v", attachments[0])
	}
}

func TestReverseProxyRawFileMaskIsForwardedWithAlert(t *testing.T) {
	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"mask","findings":[{"type":"file","action":"mask"}]}`)
	}))
	defer securityServer.Close()

	h := &ReverseProxyHandler{
		tenantID:    "tenant_default",
		securityURL: securityServer.URL,
		client:      securityServer.Client(),
	}
	decision, err := h.checkRequestSecurity(
		context.Background(), "reverse-raw-file-mask-test", []byte("%PDF-1.7\nsecret"),
		"application/pdf", "files.example.test:443", "/upload/report.pdf",
	)
	if err != nil {
		t.Fatalf("checkRequestSecurity: %v", err)
	}
	// A raw file cannot be masked; the configured action is "mask", not
	// "block": forward the original and record the gap as an alert.
	if !decision.Allowed || decision.Action != "audit" || !decision.MaskUnavailable {
		t.Fatalf("unmaskable raw file must be forwarded with an alert, got allowed=%v action=%q", decision.Allowed, decision.Action)
	}
}

func TestReverseProxyStructuredFileMaskIsForwardedWithAlert(t *testing.T) {
	t.Setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
	securityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"mask","findings":[{"type":"file","action":"mask"}]}`)
	}))
	defer securityServer.Close()

	body := []byte(`{"model":"claude","messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBERi0xLjQ="},"title":"report.pdf"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "https://api.example.test/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h := &ReverseProxyHandler{
		tenantID:    "tenant_default",
		securityURL: securityServer.URL,
		client:      securityServer.Client(),
	}

	decision, err := h.checkRequestSecurityStructured(
		context.Background(), "reverse-structured-file-mask-test", req, body,
		"application/json", "api.example.test:443", "/v1/messages",
	)
	if err != nil {
		t.Fatalf("checkRequestSecurityStructured: %v", err)
	}
	if !decision.Allowed || decision.Action != "audit" || !decision.MaskUnavailable {
		t.Fatalf("unmaskable structured file must be forwarded with an alert, got allowed=%v action=%q", decision.Allowed, decision.Action)
	}
}
