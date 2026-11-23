package handler

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

const legacyRequestBodyLimitBytes int64 = 10 << 20

func assertPayloadAboveLegacyLimitPasses(t *testing.T, handler http.Handler, path string) {
	t.Helper()

	req := httptest.NewRequest(
		http.MethodPost,
		path,
		bytes.NewReader(bytes.Repeat([]byte("a"), int(legacyRequestBodyLimitBytes)+1)),
	)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-123", "project-123", "user-123", "key-123", ""))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400 after payload passes the API body limit", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "invalid_request") {
		t.Fatalf("body=%s, want invalid_request from JSON parsing", recorder.Body.String())
	}
}

func TestMessagesAllowsPayloadAboveLegacyLimit(t *testing.T) {
	audit := &MockAuditWriter{}
	handler := NewMessagesHandler(
		&config.Config{},
		&MockModelResolver{},
		&MockRateLimitChecker{},
		&MockSecurityChecker{},
		audit,
		&MockProviderAdapterFactory{},
		nil,
		nil,
	)

	assertPayloadAboveLegacyLimitPasses(t, handler.Handler(), "/v1/messages")
}

func TestResponsesAllowsPayloadAboveLegacyLimit(t *testing.T) {
	audit := &MockAuditWriter{}
	handler := NewResponsesHandler(
		&config.Config{},
		&MockModelResolver{},
		&MockRateLimitChecker{},
		&MockSecurityChecker{},
		audit,
		&MockProviderAdapterFactory{},
		nil,
		nil,
	)

	assertPayloadAboveLegacyLimitPasses(t, handler.Handler(), "/v1/responses")
}

func TestEmbeddingsAllowsPayloadAboveLegacyLimit(t *testing.T) {
	audit := &MockAuditWriter{}
	handler := NewEmbeddingsHandler(
		&config.Config{},
		&MockModelResolver{},
		&MockRateLimitChecker{},
		&MockSecurityChecker{},
		audit,
		&MockProviderAdapterFactory{},
	)

	assertPayloadAboveLegacyLimitPasses(t, handler.Handler(), "/v1/embeddings")
}

func TestAPIHandlersHonorConfiguredBodyLimit(t *testing.T) {
	const configuredLimit int64 = 1024
	tests := []struct {
		name    string
		path    string
		handler func(*config.Config, *MockAuditWriter) http.Handler
	}{
		{
			name: "chat",
			path: "/v1/chat/completions",
			handler: func(cfg *config.Config, audit *MockAuditWriter) http.Handler {
				return NewChatCompletionsHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, &MockProviderAdapterFactory{}, nil, nil).Handler()
			},
		},
		{
			name: "messages",
			path: "/v1/messages",
			handler: func(cfg *config.Config, audit *MockAuditWriter) http.Handler {
				return NewMessagesHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, &MockProviderAdapterFactory{}, nil, nil).Handler()
			},
		},
		{
			name: "responses",
			path: "/v1/responses",
			handler: func(cfg *config.Config, audit *MockAuditWriter) http.Handler {
				return NewResponsesHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, &MockProviderAdapterFactory{}, nil, nil).Handler()
			},
		},
		{
			name: "embeddings",
			path: "/v1/embeddings",
			handler: func(cfg *config.Config, audit *MockAuditWriter) http.Handler {
				return NewEmbeddingsHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, &MockProviderAdapterFactory{}).Handler()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{APIRequestBodyLimitBytes: configuredLimit}
			audit := &MockAuditWriter{}
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader(bytes.Repeat([]byte("a"), int(configuredLimit)+1)))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(setAuthInfo(req.Context(), "tenant-123", "project-123", "user-123", "key-123", ""))

			recorder := httptest.NewRecorder()
			tt.handler(cfg, audit).ServeHTTP(recorder, req)

			if recorder.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status=%d body=%s, want 413", recorder.Code, recorder.Body.String())
			}
			wantCode := "request_too_large"
			if tt.name == "messages" {
				wantCode = "invalid_request_error"
			}
			if !strings.Contains(recorder.Body.String(), wantCode) {
				t.Fatalf("body=%s, want %s", recorder.Body.String(), wantCode)
			}
		})
	}
}

func TestLogRequestBodyTooLargeRecordsOnlySafeMetadata(t *testing.T) {
	var output bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previousWriter) })

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	req.ContentLength = 12_345_678
	req.Header.Set("Authorization", "Bearer must-not-leak")

	logRequestBodyTooLarge(req, "req-safe-log", maxAPIRequestBodyBytes)

	got := output.String()
	for _, want := range []string{"request=req-safe-log", "path=/v1/responses", "content_length=12345678", "limit_bytes=209715200"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log=%q, want %q", got, want)
		}
	}
	if strings.Contains(got, "must-not-leak") {
		t.Fatalf("authorization leaked in log: %q", got)
	}
}
