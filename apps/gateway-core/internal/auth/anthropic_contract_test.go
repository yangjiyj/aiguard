package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
)

type anthropicAuthErrorEnvelope struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
	RequestID string `json:"request_id"`
}

func assertAnthropicAuthError(t *testing.T, recorder *httptest.ResponseRecorder, status int, errorType string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status=%d want=%d body=%s", recorder.Code, status, recorder.Body.String())
	}
	var body anthropicAuthErrorEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode Anthropic auth error: %v body=%s", err, recorder.Body.String())
	}
	if body.Type != "error" || body.Error.Type != errorType || body.Error.Message == "" || body.RequestID == "" {
		t.Fatalf("invalid Anthropic auth error: %#v", body)
	}
	if got := recorder.Header().Get("X-Request-Id"); got != body.RequestID {
		t.Fatalf("X-Request-Id=%q body.request_id=%q", got, body.RequestID)
	}
}

func TestMessagesMissingAuthorizationUsesAnthropicContract(t *testing.T) {
	a := NewAuthMiddleware(nil, nil, nil)
	handler := a.Middleware(&config.Config{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthenticated request reached downstream")
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/messages", nil))

	assertAnthropicAuthError(t, recorder, http.StatusUnauthorized, "authentication_error")
}

func TestMessagesHeaderConflictUsesAnthropicContract(t *testing.T) {
	auditServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer auditServer.Close()
	a := NewAuthMiddleware(nil, nil, headeraudit.NewClient(auditServer.URL, "test-secret"))
	handler := a.Middleware(&config.Config{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("conflicting request reached downstream")
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("X-JJDGuard-Session-Id", "new-session")
	req.Header.Set("X-NewAPI-Session-Id", "old-session")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	assertAnthropicAuthError(t, recorder, http.StatusBadRequest, "invalid_request_error")
	if strings.Contains(recorder.Body.String(), "new-session") || strings.Contains(recorder.Body.String(), "old-session") {
		t.Fatalf("conflicting values leaked: %s", recorder.Body.String())
	}
}

func TestGenerateRequestIDIsUniqueWithinOneSecond(t *testing.T) {
	seen := make(map[string]struct{}, 256)
	for i := 0; i < 256; i++ {
		requestID := generateRequestID()
		if !strings.HasPrefix(requestID, "req_") {
			t.Fatalf("request id %q lacks req_ prefix", requestID)
		}
		if _, exists := seen[requestID]; exists {
			t.Fatalf("duplicate request id generated in one burst: %s", requestID)
		}
		seen[requestID] = struct{}{}
	}
}

func TestMessagesAuthErrorStatusMapping(t *testing.T) {
	cases := []struct {
		name      string
		code      string
		status    int
		errorType string
	}{
		{name: "invalid key", code: "unauthorized", status: http.StatusUnauthorized, errorType: "authentication_error"},
		{name: "revoked key", code: "key_revoked", status: http.StatusUnauthorized, errorType: "authentication_error"},
		{name: "expired key", code: "key_expired", status: http.StatusUnauthorized, errorType: "authentication_error"},
		{name: "insufficient scope", code: "insufficient_scope", status: http.StatusForbidden, errorType: "permission_error"},
		{name: "paused key", code: "key_paused", status: http.StatusForbidden, errorType: "permission_error"},
		{name: "key lookup failure", code: "internal_error", status: http.StatusInternalServerError, errorType: "api_error"},
		{name: "auth wiring failure", code: "auth_misconfigured", status: http.StatusInternalServerError, errorType: "api_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
			recorder := httptest.NewRecorder()
			writeAuthError(recorder, req, tc.code, "safe message", "req_mapping")
			assertAnthropicAuthError(t, recorder, tc.status, tc.errorType)
		})
	}
}

func TestNonMessagesAuthErrorContractRemainsUnchanged(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	recorder := httptest.NewRecorder()
	writeAuthError(recorder, req, "internal_error", "key validation failed", "req_openai")

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("non-Messages status=%d want existing 401", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"code":"internal_error"`) ||
		!strings.Contains(recorder.Body.String(), `"request_id":"req_openai"`) {
		t.Fatalf("non-Messages envelope changed: %s", recorder.Body.String())
	}
}
