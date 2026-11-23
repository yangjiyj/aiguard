package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/packages/shared-go/aicontentlabel"
)

// 经真实 chat handler 走一遍：门户请求的回复带标识，留存正文和计费收尾看到的是不带标识的版本。
func runLabeledChatRequest(t *testing.T, agentType string, stream bool) (*httptest.ResponseRecorder, *MockAuditWriter) {
	t.Helper()
	upstream := []byte(`{"id":"chatcmpl-up","object":"chat.completion","created":1,"model":"gpt-4","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"门户回答"}}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`)
	caller := &MockProviderCaller{CallResponse: upstream}
	audit := &MockAuditWriter{}
	client := labelTestClient(t, labelOnSettings())
	h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit,
		&MockProviderAdapterFactory{MockProviderCaller: caller}, client, nil)

	body, _ := json.Marshal(map[string]any{
		"model":    "gpt-4",
		"messages": []map[string]string{{"role": "user", "content": "你好"}},
		"stream":   stream,
	})
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(req.Context(), "tenant-1", "project-1", "user-1", "key-1", "")
	ctx = context.WithValue(ctx, auth.AgentTypeKey, agentType)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, req.WithContext(ctx))
	return w, audit
}

func chatContentFromResponse(t *testing.T, w *httptest.ResponseRecorder, stream bool) string {
	t.Helper()
	if !stream {
		m := decodeJSONMap(t, w.Body.Bytes())
		return m["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["content"].(string)
	}
	var b strings.Builder
	for _, f := range sseFrames(t, w.Body.Bytes()) {
		for _, raw := range asSlice(f["choices"]) {
			if delta, _ := raw.(map[string]any)["delta"].(map[string]any); delta != nil {
				if s, ok := delta["content"].(string); ok {
					b.WriteString(s)
				}
			}
		}
	}
	return b.String()
}

func TestChatHandlerLabelsPortalReplyButNotRetainedContent(t *testing.T) {
	for _, stream := range []bool{false, true} {
		w, audit := runLabeledChatRequest(t, aicontentlabel.PortalAgentType, stream)
		if w.Code != 200 {
			t.Fatalf("stream=%v status=%d body=%s", stream, w.Code, w.Body.String())
		}
		content := chatContentFromResponse(t, w, stream)
		frames := aicontentlabel.Find(content)
		if len(frames) != 1 {
			t.Fatalf("stream=%v: want one watermark, got %d in %q", stream, len(frames), content)
		}
		requestID, ok := aicontentlabel.Verify(frames[0], aicontentlabel.DeriveKey(labelTestSecret))
		if !ok || requestID == "" {
			t.Fatalf("stream=%v: watermark does not verify", stream)
		}
		if aicontentlabel.Strip(content) != "门户回答\n\n（以上内容由 AI 生成）" {
			t.Fatalf("stream=%v: content = %q", stream, aicontentlabel.Strip(content))
		}
		for _, entry := range audit.ContentLogWrites {
			if strings.Contains(entry.Content, "以上内容由 AI 生成") || len(aicontentlabel.Find(entry.Content)) != 0 {
				t.Fatalf("stream=%v: retained content carries the label: %q", stream, entry.Content)
			}
		}
		if len(audit.RequestLogFinalizes) != 1 || strings.Contains(string(audit.RequestLogFinalizes[0].RespBody), "以上内容由 AI 生成") {
			t.Fatalf("stream=%v: finalize saw labeled body", stream)
		}
	}
}

func TestChatHandlerDoesNotLabelCodingAssistant(t *testing.T) {
	for _, stream := range []bool{false, true} {
		w, _ := runLabeledChatRequest(t, "claude-code", stream)
		if content := chatContentFromResponse(t, w, stream); content != "门户回答" {
			t.Fatalf("stream=%v: coding assistant reply was changed: %q", stream, content)
		}
	}
}
