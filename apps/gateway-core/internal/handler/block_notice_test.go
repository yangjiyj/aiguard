package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// The field report (acme, 2026-09-23): an agent was blocked, showed only
// "自定义模型 … 错误 10000", and the console had no record naming the rule.
// These tests pin the contract: the agent-facing notice names the rule, the
// redacted detail, and a block number that is the security event's id.

var passwordRuleFinding = SecurityFinding{
	Type: "custom", Severity: "critical", Category: "plain_password",
	RuleID: "rule_525f3078", RuleName: "密码明文检测", Action: "block",
	MatchedTextPreview: "pass****i996", MatchedLocation: "input",
}

func blockedEventID(t *testing.T, audit *MockAuditWriter) string {
	t.Helper()
	for _, event := range audit.SecurityEventWrites {
		if isBlockingSecurityAction(event.ActionTaken) {
			if event.Block == nil || event.Block.BlockID != event.EventID {
				t.Fatalf("block event lacks attribution: %+v", event)
			}
			return event.EventID
		}
	}
	t.Fatalf("no block event persisted: %+v", audit.SecurityEventWrites)
	return ""
}

func serveBlockedChat(t *testing.T, security *MockSecurityChecker, mode string, stream bool) (*httptest.ResponseRecorder, *MockAuditWriter) {
	t.Helper()
	audit := &MockAuditWriter{}
	handler, _ := createTestHandlers(&MockModelResolver{}, &MockRateLimitChecker{}, security, audit)
	if mode != "" {
		client := NewToolRiskClient("http://127.0.0.1:1", "secret")
		client.runtimeCache.setSecurityAuditOnly(false)
		client.setBlockNoticeSettings(blockNoticeSettings{Mode: mode, Template: DefaultBlockNoticeTemplate})
		handler.toolRiskClient = client
	}
	body, _ := json.Marshal(ChatCompletionRequest{Model: "gpt-4", Stream: stream, Messages: []Message{{Role: "user", Content: jsonQuote("my password is pass1996")}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-123", "project-123", "user-123", "key-123", ""))
	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, req)
	return w, audit
}

func assertNoticeNamesRule(t *testing.T, text, blockID string) {
	t.Helper()
	for _, want := range []string{"密码明文检测", "rule_525f3078", "pass****i996", "阻断编号：" + blockID, "输入内容命中安全规则"} {
		if !strings.Contains(text, want) {
			t.Fatalf("notice missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "pass1996") {
		t.Fatalf("notice leaked the raw secret:\n%s", text)
	}
}

func TestChatInputBlockErrorModeNamesRuleDetailAndBlockID(t *testing.T) {
	w, audit := serveBlockedChat(t, &MockSecurityChecker{InputAction: "block", InputFindings: []SecurityFinding{passwordRuleFinding}}, "", false)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	blockID := blockedEventID(t, audit)
	assertNoticeNamesRule(t, response.Error.Message, blockID)
	if response.Error.Code != "security_blocked" || w.Header().Get("X-JJDGuard-Block-ID") != blockID {
		t.Fatalf("code=%q header=%q block=%q", response.Error.Code, w.Header().Get("X-JJDGuard-Block-ID"), blockID)
	}
}

func TestChatInputBlockMessageModeRepliesAsAssistant(t *testing.T) {
	w, audit := serveBlockedChat(t, &MockSecurityChecker{InputAction: "block", InputFindings: []SecurityFinding{passwordRuleFinding}}, blockResponseModeMessage, false)
	if w.Code != http.StatusOK {
		t.Fatalf("message mode must answer 200, got %d body=%s", w.Code, w.Body.String())
	}
	var response ChatCompletionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Choices) != 1 || response.Choices[0].Message.Role != "assistant" || response.Choices[0].FinishReason != "stop" {
		t.Fatalf("not an assistant reply: %s", w.Body.String())
	}
	blockID := blockedEventID(t, audit)
	assertNoticeNamesRule(t, response.Choices[0].Message.Content, blockID)
	last := audit.RequestLogFinalizes[len(audit.RequestLogFinalizes)-1]
	if last.Status != "security_blocked" {
		t.Fatalf("request must still be logged as blocked, got %q", last.Status)
	}
}

func TestChatStreamInputBlockMessageModeStreamsNotice(t *testing.T) {
	w, audit := serveBlockedChat(t, &MockSecurityChecker{InputAction: "block", InputFindings: []SecurityFinding{passwordRuleFinding}}, blockResponseModeMessage, true)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "chat.completion.chunk") || !strings.Contains(body, "data: [DONE]") {
		t.Fatalf("stream notice missing: status=%d body=%s", w.Code, body)
	}
	if strings.Contains(body, `"error"`) {
		t.Fatalf("message mode must not emit an SSE error: %s", body)
	}
	if !strings.Contains(body, blockedEventID(t, audit)) {
		t.Fatalf("stream notice lacks block number: %s", body)
	}
}

func TestChatOutputBlockNoticeNamesOutputRule(t *testing.T) {
	finding := passwordRuleFinding
	finding.MatchedLocation = "output"
	w, audit := serveBlockedChat(t, &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{finding}}, blockResponseModeMessage, false)
	var response ChatCompletionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response.Choices) != 1 {
		t.Fatalf("status=%d body=%s err=%v", w.Code, w.Body.String(), err)
	}
	text := response.Choices[0].Message.Content
	if !strings.Contains(text, "模型输出命中安全规则") || !strings.Contains(text, blockedEventID(t, audit)) {
		t.Fatalf("output notice: %s", text)
	}
}

func TestRenderBlockNoticeDropsLinesWithoutValues(t *testing.T) {
	text := renderBlockNotice(DefaultBlockNoticeTemplate, blockAttribution{BlockID: "evt_1", Reason: "输入内容命中安全规则"})
	if strings.Contains(text, "命中规则") || strings.Contains(text, "命中内容") || strings.Contains(text, "操作编号") {
		t.Fatalf("empty lines must be dropped:\n%s", text)
	}
	if !strings.Contains(text, "阻断编号：evt_1") || !strings.Contains(text, "输入内容命中安全规则") {
		t.Fatalf("notice:\n%s", text)
	}
	custom := renderBlockNotice("请联系安全组，编号 {block_id}（{rule}）", blockAttribution{BlockID: "evt_2", RuleName: "密码明文检测"})
	if custom != "请联系安全组，编号 evt_2（密码明文检测）" {
		t.Fatalf("custom template = %q", custom)
	}
}

func TestValidateBlockNoticeTemplate(t *testing.T) {
	if err := ValidateBlockNoticeTemplate("编号 {block_id} 规则 {rule} 请求 {request_id}"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBlockNoticeTemplate("{password}"); err == nil {
		t.Fatal("unknown placeholder must be rejected")
	}
	if err := ValidateBlockNoticeTemplate(strings.Repeat("长", maxBlockNoticeTemplateRunes+1)); err == nil {
		t.Fatal("over-long template must be rejected")
	}
	if got := renderBlockNotice("{password}", blockAttribution{BlockID: "evt_3"}); !strings.Contains(got, "evt_3") {
		t.Fatalf("an invalid stored template must fall back to the default, got %q", got)
	}
}

func TestBlockEventIsNeverFoldedOrDropped(t *testing.T) {
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{auditWriter: audit}
	ctx := withBlockLedger(context.Background())
	nonFinding := false
	h.writeSecurityEvent(withFingerprintOccurrence(ctx, "evt_first", "ctx-key"), &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t"},
		[]SecurityFinding{{Type: "engine_runtime", Action: "block", CountsAsSecurityFinding: &nonFinding}}, "security_blocked", "blocked")
	if len(audit.SecurityEventWrites) != 1 || audit.SecurityEventWrites[0].Block == nil {
		t.Fatalf("a block must be written as its own event: %+v", audit.SecurityEventWrites)
	}
	if !blockRecorded(ctx) {
		t.Fatal("ledger must note the block")
	}
}
