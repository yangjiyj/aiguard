package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

// failClosedClient is a ToolRiskClient holding a signed snapshot with the
// given execution mode and fail-closed option.
func failClosedClient(t *testing.T, auditOnly, failClosed bool) *ToolRiskClient {
	t.Helper()
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	client := NewToolRiskClient("http://control-plane.invalid", gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision: "00000000000000000000000000000000", Enabled: true, InputEnabled: true, AgentEnabled: true,
		SecurityAuditOnly: auditOnly, SecurityExecutionModeManaged: true, GuardrailFailClosedEnabled: failClosed,
	})
	return client
}

func engineDownChat(client *ToolRiskClient) *ChatCompletionsHandler {
	return &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client,
		securityClient: &MockSecurityChecker{InputError: errors.New("engine down"), OutputError: errors.New("engine down")},
		auditWriter:    &MockAuditWriter{}}
}

func gapChatResponse(t *testing.T) []byte {
	return mustMarshalChatResponse(t, ChatCompletionResponse{ID: "chatcmpl-gap", Object: "chat.completion", Model: "glm-5",
		Choices: []Choice{{Index: 0, Message: ChoiceMessage{Role: "assistant", Content: "text"}}}})
}

func TestFailClosedExitMatrix(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		auditOnly, failClosed bool
		wantReject            bool
	}{
		{"protect off (P0-3 behaviour)", false, false, false},
		{"record off", true, false, false},
		{"record on (invariant R)", true, true, false},
		{"protect on", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := failClosedClient(t, tc.auditOnly, tc.failClosed)
			h := engineDownChat(client)
			req := &ChatCompletionRequest{Model: "glm-5", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
			_, inErr := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), req)
			_, audit, outErr := h.applyOutputSecurity(context.Background(), newFailModeEnvelope(), nil, gapChatResponse(t))
			tool := ToolCall{ID: "call_1", Type: "function", Function: ToolCallFunc{Name: "f", Arguments: `{"a":1}`}}
			_, toolErr := h.secureOutputToolArguments(context.Background(), newFailModeEnvelope(), tool, 0, &AuditResult{})
			emb := &EmbeddingsHandler{cfg: &config.Config{}, toolRiskClient: client, securityClient: &MockSecurityChecker{InputError: errors.New("down")}, auditWriter: &MockAuditWriter{}}
			embErr := emb.applyInputSecurity(context.Background(), newFailModeEnvelope(), &EmbeddingsRequest{Model: "e", Input: "x"})
			img := &ImagesHandler{cfg: &config.Config{}, toolRiskClient: client, securityClient: &MockSecurityChecker{InputError: errors.New("down")}, auditWriter: &MockAuditWriter{}}
			_, imgErr := img.applyInputSecurity(context.Background(), newFailModeEnvelope(), &ImagesRequest{Prompt: "p"}, nil, []byte(`{"prompt":"p"}`))
			for exit, err := range map[string]error{"chat input": inErr, "chat output": outErr, "tool arguments": toolErr, "embeddings": embErr, "images": imgErr} {
				if tc.wantReject != isGuardrailDetectionUnavailable(err) || (!tc.wantReject && err != nil) {
					t.Fatalf("%s: err=%v wantReject=%v", exit, err, tc.wantReject)
				}
			}
			if !tc.wantReject && (audit == nil || audit.OutputAction != "audit") {
				t.Fatalf("detection failure must stay an audited gap, got %+v", audit)
			}
			wantMode := "open"
			if tc.wantReject {
				wantMode = "close"
			}
			if got := h.guardrailFailureMode(context.Background()); got != wantMode {
				t.Fatalf("resolved failure mode=%q want %q", got, wantMode)
			}
		})
	}
}

func TestFailClosedDoesNotTouchRuleVerdictsOrCapacity(t *testing.T) {
	// A rule verdict in protect mode keeps its 403 block path; the option only
	// ever maps DetectionFailure. Capacity is covered in securityexit.
	client := failClosedClient(t, false, true)
	h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client, securityClient: &MockSecurityChecker{InputAction: "block"}, auditWriter: &MockAuditWriter{}}
	req := &ChatCompletionRequest{Model: "glm-5", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
	_, err := h.applyInputSecurity(context.Background(), newFailModeEnvelope(), req)
	if err == nil || isGuardrailDetectionUnavailable(err) {
		t.Fatalf("rule block must stay a security block, got %v", err)
	}
}

func serveEmbeddings(t *testing.T, client *ToolRiskClient) (*httptest.ResponseRecorder, *MockAuditWriter) {
	t.Helper()
	audit := &MockAuditWriter{}
	handler := NewEmbeddingsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{InputError: errors.New("engine down")}, audit, &MockProviderAdapterFactory{})
	handler.SetRuntimeConfigClient(client)
	body, _ := json.Marshal(EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello world"})
	req := httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-123", "project-123", "user-123", "key-123", ""))
	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, req)
	return w, audit
}

func TestFailClosedHTTPProtectOnReturns503(t *testing.T) {
	w, audit := serveEmbeddings(t, failClosedClient(t, false, true))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Error.Code != guardrailDetectionUnavailableCode {
		t.Fatalf("body=%s err=%v", w.Body.String(), err)
	}
	last := audit.RequestLogFinalizes[len(audit.RequestLogFinalizes)-1]
	if last.Status != "security_blocked" {
		t.Fatalf("request log status=%q", last.Status)
	}
	if !hasSecurityEvent(audit, "security_check_failed") {
		t.Fatalf("gap event missing: %#v", audit.SecurityEventWrites)
	}
}

func TestFailClosedHTTPRecordOnStillReturns2xx(t *testing.T) {
	w, audit := serveEmbeddings(t, failClosedClient(t, true, true))
	if w.Code < 200 || w.Code > 299 {
		t.Fatalf("record mode must forward on detection failure, status=%d body=%s", w.Code, w.Body.String())
	}
	if !hasSecurityEvent(audit, "security_check_failed") {
		t.Fatalf("gap event missing: %#v", audit.SecurityEventWrites)
	}
}

func TestFailClosedChatInputMapsTo503(t *testing.T) {
	h := engineDownChat(failClosedClient(t, false, true))
	req := &ChatCompletionRequest{Model: "glm-5", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
	result := h.applyChatInputSecurity(context.Background(), newFailModeEnvelope(), req)
	if result.errorCode != guardrailDetectionUnavailableCode || result.httpStatus != http.StatusServiceUnavailable || result.auditStatus != "security_blocked" {
		t.Fatalf("chat input fail-closed mapping=%+v", result)
	}
	if getStatusCode(guardrailDetectionUnavailableCode) != http.StatusServiceUnavailable {
		t.Fatal("error code must map to 503")
	}
}
