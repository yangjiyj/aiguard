package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// ---- fakes for proxy auth (承接任务 1.7 / 阶段二 2.5) ----

type fakeProxyKeyVerifier struct {
	info *ProxyKeyInfo
	err  error
}

func (f *fakeProxyKeyVerifier) VerifyProxyKey(ctx context.Context, rawKey, modelID string) (*ProxyKeyInfo, error) {
	return f.info, f.err
}

type recordedUsage struct {
	ModelID string
	In      int
	Out     int
}

type fakeProxyUsageRecorder struct {
	calls []recordedUsage
}

func (f *fakeProxyUsageRecorder) RecordProxyUsage(ctx context.Context, modelID string, inputTokens, outputTokens int) error {
	f.calls = append(f.calls, recordedUsage{ModelID: modelID, In: inputTokens, Out: outputTokens})
	return nil
}

func newProxyEnabledResolver() *MockModelResolver {
	return &MockModelResolver{
		ModelRecord: &modelrouter.ModelRecord{
			ID:              "model-123",
			ProviderID:      "provider-123",
			ModelName:       "gpt-4",
			ProviderType:    "openai",
			ProviderBaseURL: "https://api.openai.com",
			Status:          "active",
			ProxyConfig:     `{"enabled":true}`,
		},
	}
}

func newProxyHandler(mockResolver *MockModelResolver, mockAudit *MockAuditWriter, verifier ProxyKeyVerifier, recorder ProxyUsageRecorder) *ChatCompletionsHandler {
	cfg := &config.Config{}
	mockProviderFactory := &MockProviderAdapterFactory{}
	h := NewChatCompletionsHandler(cfg, mockResolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, mockAudit, mockProviderFactory, nil, nil)
	h.SetProxyAuth(verifier, recorder)
	return h
}

func proxyChatRequest(proxyKey string) *http.Request {
	reqBody := ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}}}
	body, _ := json.Marshal(reqBody)
	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	if proxyKey != "" {
		httpReq.Header.Set("X-Proxy-Key", proxyKey)
	}
	ctx := setAuthInfo(httpReq.Context(), "tenant-123", "project-123", "user-123", "key-123", "")
	ctx = context.WithValue(ctx, auth.ProxyRequestKey, true)
	ctx = context.WithValue(ctx, auth.ClientIPKey, "1.2.3.4")
	return httpReq.WithContext(ctx)
}

// 无效 proxy key 被拒
func TestProxyInvalidKeyRejected(t *testing.T) {
	mockResolver := newProxyEnabledResolver()
	mockAudit := &MockAuditWriter{}
	verifier := &fakeProxyKeyVerifier{err: errors.New("proxy key not found")}
	recorder := &fakeProxyUsageRecorder{}
	handler := newProxyHandler(mockResolver, mockAudit, verifier, recorder)

	httpReq := proxyChatRequest("bad-key")
	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Expected status 401 for invalid proxy key, got %d: %s", w.Code, w.Body.String())
	}
	if len(recorder.calls) != 0 {
		t.Errorf("Expected no usage recorded on rejected request, got %d", len(recorder.calls))
	}
}

// 用量落表
func TestProxyUsageRecordedOnSuccess(t *testing.T) {
	mockResolver := newProxyEnabledResolver()
	mockAudit := &MockAuditWriter{}
	verifier := &fakeProxyKeyVerifier{info: &ProxyKeyInfo{KeyID: "pk-1"}}
	recorder := &fakeProxyUsageRecorder{}
	handler := newProxyHandler(mockResolver, mockAudit, verifier, recorder)

	httpReq := proxyChatRequest("good-key")
	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for valid proxy key, got %d: %s", w.Code, w.Body.String())
	}
	if len(recorder.calls) != 1 {
		t.Fatalf("Expected exactly 1 usage record, got %d", len(recorder.calls))
	}
	got := recorder.calls[0]
	if got.ModelID != "model-123" || got.In != 10 || got.Out != 20 {
		t.Errorf("Expected usage (model-123, 10, 20), got (%s, %d, %d)", got.ModelID, got.In, got.Out)
	}
}
