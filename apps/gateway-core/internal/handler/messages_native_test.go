package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

func nativeMessagesTestHandler(caller *MockProviderCaller, security SecurityChecker, audit *MockAuditWriter) *MessagesHandler {
	if security == nil {
		security = &MockSecurityChecker{}
	}
	if audit == nil {
		audit = &MockAuditWriter{}
	}
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID:              "model-native",
		ModelName:       "claude-opus-5",
		ProviderID:      "provider-native",
		ProviderType:    "openai",
		ProviderBaseURL: "https://boflow.example",
		UpstreamModelID: "kiro-opus",
		Status:          "active",
	}}
	factory := &MockProviderAdapterFactory{MockProviderCaller: caller}
	return NewMessagesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, security, audit, factory, nil, nil)
}

func serveNativeMessages(t *testing.T, h *MessagesHandler, target string, body []byte, headers http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", "session-a"))
	recorder := httptest.NewRecorder()
	h.Handler().ServeHTTP(recorder, req)
	return recorder
}

func TestNativeMessagesPreservesRequestAndJSONResponse(t *testing.T) {
	requestBody := []byte(`{
  "model":"claude-opus-5",
  "max_tokens":8192,
  "stream":false,
  "system":[{"type":"text","text":"system","cache_control":{"type":"ephemeral"}}],
  "messages":[
    {"role":"assistant","content":[{"type":"thinking","thinking":"reason","signature":"sig"},{"type":"tool_use","id":"toolu_1","name":"Read","input":{"path":"/tmp/a"}}]},
    {"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"text","text":"done"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AQID"}}]}]}
  ],
  "thinking":{"type":"enabled","budget_tokens":4096},
  "context_management":{"edits":[{"type":"clear_tool_uses_20250919"}]},
  "metadata":{"user_id":"u-1"},
  "unknown":{"large":9007199254740993123456789}
}`)
	responseBody := []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"kiro-opus","content":[{"type":"text","text":"ok","citations":[{"x":1}]}],"stop_reason":"end_turn","usage":{"input_tokens":123,"output_tokens":2,"cache_read_input_tokens":99},"unknown":{"keep":true}}`)
	caller := &MockProviderCaller{CallResponse: responseBody}
	h := nativeMessagesTestHandler(caller, nil, nil)

	recorder := serveNativeMessages(t, h, "/v1/messages?beta=one&beta=two", requestBody, http.Header{
		"Anthropic-Version":         {"2023-06-01"},
		"Anthropic-Beta":            {"feature-a", "feature-b"},
		"X-Claude-Code-Session-Id":  {"claude-session"},
		"Authorization":             {"Bearer inbound-secret"},
		"X-Api-Key":                 {"inbound-api-key"},
		"Cookie":                    {"private=cookie"},
		"X-JJDGuard-Internal-Token": {"internal-secret"},
	})

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(caller.TransformRequestCalls) != 1 {
		t.Fatalf("transform calls=%d want 1", len(caller.TransformRequestCalls))
	}
	if !bytes.Equal(caller.TransformRequestCalls[0].RawBody, requestBody) {
		t.Fatalf("native request changed before provider: %s", caller.TransformRequestCalls[0].RawBody)
	}
	if got := caller.CallEnvelopes[0].EndpointType; got != "messages" {
		t.Fatalf("endpoint=%q want messages", got)
	}
	if !bytes.Equal(recorder.Body.Bytes(), responseBody) {
		t.Fatalf("native response changed:\n got=%s\nwant=%s", recorder.Body.Bytes(), responseBody)
	}
}

func TestNativeMessagesPreservesSSEBytes(t *testing.T) {
	sse := []byte("event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_sse\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"kiro-opus\",\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}}\n\n" +
		"event: ping\ndata: {\"type\":\"ping\",\"unknown\":true}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	caller := &MockProviderCaller{CallResponse: sse}
	h := nativeMessagesTestHandler(caller, nil, nil)
	body := []byte(`{"model":"claude-opus-5","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"hello"}]}`)

	recorder := serveNativeMessages(t, h, "/v1/messages", body, nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("content-type=%q", got)
	}
	if !bytes.Equal(recorder.Body.Bytes(), sse) {
		t.Fatalf("SSE bytes changed:\n got=%q\nwant=%q", recorder.Body.Bytes(), sse)
	}
}

func TestNativeMessagesStreamSecurityReplyUsesAnthropicSSE(t *testing.T) {
	security := &MockSecurityChecker{
		InputAction: "reply", InputMasked: "request denied",
		InputFindings: []SecurityFinding{{Type: "policy", Severity: "high"}},
	}
	caller := &MockProviderCaller{}
	h := nativeMessagesTestHandler(caller, security, nil)
	body := []byte(`{"model":"claude-opus-5","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"blocked"}]}`)

	recorder := serveNativeMessages(t, h, "/v1/messages", body, nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("content-type=%q", got)
	}
	for _, expected := range []string{"event: message_start", "event: content_block_delta", "request denied", "event: message_stop"} {
		if !strings.Contains(recorder.Body.String(), expected) {
			t.Fatalf("security reply SSE missing %q: %s", expected, recorder.Body.String())
		}
	}
	if len(caller.CallCalls) != 0 {
		t.Fatal("security reply reached upstream")
	}
}

type maskFirstInputSecurity struct {
	MockSecurityChecker
	calls int
	seen  []string
}

func (m *maskFirstInputSecurity) CheckInput(_ context.Context, _ *modelrouter.RequestEnvelope, content string, _ int, _ string, _ string) (string, string, []SecurityFinding, error) {
	m.calls++
	m.seen = append(m.seen, content)
	if m.calls == 1 {
		return "mask", "[MASKED]", []SecurityFinding{{Type: "secret", Severity: "high"}}, nil
	}
	return "allow", "", nil, nil
}

func (m *maskFirstInputSecurity) CheckInputDetailed(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (*InputCheckOutcome, error) {
	action, masked, findings, err := m.CheckInput(ctx, envelope, content, messageIndex, messageRole, contentSource)
	if err != nil {
		return nil, err
	}
	return &InputCheckOutcome{Action: action, MaskedContent: masked, Findings: findings}, nil
}

func TestNativeMessagesMasksExactInputTextPointer(t *testing.T) {
	requestBody := []byte(`{"model":"claude-opus-5","max_tokens":32,"system":[{"type":"text","text":"secret","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":[{"type":"text","text":"keep"}]}],"unknown":{"large":9007199254740993123456789}}`)
	responseBody := []byte(`{"id":"msg_mask","type":"message","role":"assistant","model":"kiro-opus","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	security := &maskFirstInputSecurity{}
	caller := &MockProviderCaller{CallResponse: responseBody}
	h := nativeMessagesTestHandler(caller, security, nil)
	h.toolRiskClient = allInspectionTestClient()

	recorder := serveNativeMessages(t, h, "/v1/messages", requestBody, nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var got map[string]any
	decoder := json.NewDecoder(bytes.NewReader(caller.TransformRequestCalls[0].RawBody))
	decoder.UseNumber()
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	systemBlocks, ok := got["system"].([]any)
	if !ok || len(systemBlocks) == 0 {
		t.Fatalf("native system blocks were lost: %#v", got)
	}
	system, ok := systemBlocks[0].(map[string]any)
	if !ok {
		t.Fatalf("native system block shape changed: %#v", systemBlocks[0])
	}
	if system["text"] != "[MASKED]" || system["cache_control"].(map[string]any)["type"] != "ephemeral" {
		t.Fatalf("system pointer was not masked precisely: %#v", system)
	}
	if got["unknown"].(map[string]any)["large"].(json.Number).String() != "9007199254740993123456789" {
		t.Fatalf("large integer changed: %#v", got["unknown"])
	}
}

// Signed thinking cannot be rewritten. The configured action is "mask", not
// "block": the original is forwarded and the gap is alerted.
func TestNativeMessagesForwardsUnmaskableSignedThinkingWithAlert(t *testing.T) {
	requestBody := []byte(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"private reasoning","signature":"signed-value"}]}]}`)
	security := &maskFirstInputSecurity{}
	caller := &MockProviderCaller{CallResponse: []byte(`{"id":"msg_never","type":"message","role":"assistant","model":"kiro-opus","content":[],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":0}}`)}
	h := nativeMessagesTestHandler(caller, security, nil)
	h.toolRiskClient = allInspectionTestClient()
	audit := h.auditWriter.(*MockAuditWriter)

	recorder := serveNativeMessages(t, h, "/v1/messages", requestBody, nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unmaskable input must be forwarded, status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(security.seen) == 0 || security.seen[0] != "private reasoning" {
		t.Fatalf("signed thinking was not inspected: %+v", security.seen)
	}
	alerted := false
	for _, event := range audit.SecurityEventWrites {
		if event.ActionTaken == "security_audit" && event.MaskUnavailable {
			alerted = true
		}
	}
	if !alerted {
		t.Fatalf("mask-unavailable alert missing: %+v", audit.SecurityEventWrites)
	}
}

type maskSelectedOutputSecurity struct {
	MockSecurityChecker
	choice int
}

func (m *maskSelectedOutputSecurity) CheckOutput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, choiceIndex int) (string, string, []SecurityFinding, error) {
	m.OutputCheckCalls = append(m.OutputCheckCalls, struct {
		Content     string
		ChoiceIndex int
	}{content, choiceIndex})
	if choiceIndex == m.choice {
		return "mask", "[REDACTED]", []SecurityFinding{{Type: "secret", Severity: "high"}}, nil
	}
	return "allow", content, nil, nil
}

func TestNativeMessagesMasksJSONOutputTextOnly(t *testing.T) {
	responseBody := []byte(`{"id":"msg_output_mask","type":"message","role":"assistant","model":"kiro-opus","content":[{"type":"text","text":"sensitive","citations":[{"url":"https://example.invalid"}]},{"type":"thinking","thinking":"private reasoning","signature":"sig"}],"stop_reason":"end_turn","usage":{"input_tokens":2,"output_tokens":3},"unknown":{"keep":true}}`)
	security := &maskSelectedOutputSecurity{choice: 0}
	caller := &MockProviderCaller{CallResponse: responseBody}
	h := nativeMessagesTestHandler(caller, security, nil)
	body := []byte(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`)

	recorder := serveNativeMessages(t, h, "/v1/messages", body, nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	content := got["content"].([]any)
	text := content[0].(map[string]any)
	if text["text"] != "[REDACTED]" || text["citations"].([]any)[0].(map[string]any)["url"] != "https://example.invalid" {
		t.Fatalf("text mask changed sibling fields: %#v", text)
	}
	thinking := content[1].(map[string]any)
	if thinking["thinking"] != "private reasoning" || thinking["signature"] != "sig" {
		t.Fatalf("unmasked signed thinking changed: %#v", thinking)
	}
	if got["unknown"].(map[string]any)["keep"] != true {
		t.Fatalf("unknown response field changed: %#v", got)
	}
}

func TestNativeMessagesBlocksMaskedSignedThinkingJSONOutput(t *testing.T) {
	responseBody := []byte(`{"id":"msg_signed","type":"message","role":"assistant","model":"kiro-opus","content":[{"type":"thinking","thinking":"private reasoning","signature":"signed-value"}],"stop_reason":"end_turn","usage":{"input_tokens":2,"output_tokens":3}}`)
	security := &maskSelectedOutputSecurity{choice: 0}
	h := nativeMessagesTestHandler(&MockProviderCaller{CallResponse: responseBody}, security, nil)
	body := []byte(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`)

	recorder := serveNativeMessages(t, h, "/v1/messages", body, nil)

	assertAnthropicMessagesError(t, recorder, http.StatusForbidden, "permission_error")
	if len(security.OutputCheckCalls) != 1 || security.OutputCheckCalls[0].Content != "private reasoning" {
		t.Fatalf("signed thinking was not inspected: %+v", security.OutputCheckCalls)
	}
	if strings.Contains(recorder.Body.String(), "private reasoning") || strings.Contains(recorder.Body.String(), "signed-value") {
		t.Fatalf("blocked signed thinking leaked: %s", recorder.Body.String())
	}
}

func TestNativeMessagesBlocksMaskedSignedThinkingSSEOutput(t *testing.T) {
	responseBody := []byte("event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_signed_sse\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"kiro-opus\",\"usage\":{\"input_tokens\":2,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"private reasoning\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"signed-value\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	security := &maskSelectedOutputSecurity{choice: 0}
	h := nativeMessagesTestHandler(&MockProviderCaller{CallResponse: responseBody}, security, nil)
	body := []byte(`{"model":"claude-opus-5","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"hello"}]}`)

	recorder := serveNativeMessages(t, h, "/v1/messages", body, nil)

	assertAnthropicMessagesError(t, recorder, http.StatusForbidden, "permission_error")
	if len(security.OutputCheckCalls) != 1 || security.OutputCheckCalls[0].Content != "private reasoning" {
		t.Fatalf("SSE signed thinking was not inspected: %+v", security.OutputCheckCalls)
	}
	if strings.Contains(recorder.Body.String(), "private reasoning") || strings.Contains(recorder.Body.String(), "signed-value") {
		t.Fatalf("blocked SSE signed thinking leaked: %s", recorder.Body.String())
	}
}

func TestNativeMessagesPreservesUpstream400AndSafeHeaders(t *testing.T) {
	errorBody := []byte(`{"type":"error","error":{"type":"invalid_request_error","message":"bad compact payload"},"request_id":"kiro-400"}`)
	caller := &MockProviderCaller{CallError: &provider.UpstreamHTTPError{
		StatusCode: http.StatusBadRequest,
		Body:       errorBody,
		Headers: http.Header{
			"Content-Type":         {"application/json; charset=utf-8"},
			"Retry-After":          {"9"},
			"Anthropic-Request-Id": {"kiro-400"},
			"Set-Cookie":           {"must-not-pass=1"},
			"Server":               {"private-upstream"},
		},
	}}
	h := nativeMessagesTestHandler(caller, nil, nil)
	body := []byte(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`)

	recorder := serveNativeMessages(t, h, "/v1/messages", body, nil)

	// 4xx：上游 message 透传（替换通用文案），状态码与上游头部白名单行为不变。
	if recorder.Code != http.StatusBadRequest || strings.Contains(recorder.Body.String(), "upstream Messages request failed") || !bytes.Contains(recorder.Body.Bytes(), []byte("bad compact payload")) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Retry-After") != "9" || recorder.Header().Get("Anthropic-Request-Id") != "kiro-400" {
		t.Fatalf("safe upstream headers lost: %#v", recorder.Header())
	}
	if recorder.Header().Get("Set-Cookie") != "" || recorder.Header().Get("Server") != "" {
		t.Fatalf("unsafe upstream headers leaked: %#v", recorder.Header())
	}
}

func TestNativeMessagesRejectsCredentialQueryWithAnthropicError(t *testing.T) {
	caller := &MockProviderCaller{CallResponse: []byte(`{"id":"msg_never","type":"message","role":"assistant","model":"kiro-opus","content":[{"type":"text","text":"no"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)}
	h := nativeMessagesTestHandler(caller, nil, nil)
	body := []byte(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`)

	recorder := serveNativeMessages(t, h, "/v1/messages?beta=one&token=must-not-pass", body, nil)

	assertAnthropicMessagesError(t, recorder, http.StatusBadRequest, "invalid_request_error")
	if len(caller.CallCalls) != 0 {
		t.Fatal("credential query reached upstream")
	}
	if strings.Contains(recorder.Body.String(), "must-not-pass") {
		t.Fatalf("credential query leaked in response: %s", recorder.Body.String())
	}
}

func TestNativeMessagesRequestTooLargeUsesAnthropicError(t *testing.T) {
	h := nativeMessagesTestHandler(&MockProviderCaller{}, nil, nil)
	h.cfg = &config.Config{APIRequestBodyLimitBytes: 64}
	body := []byte(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"` + strings.Repeat("x", 128) + `"}]}`)

	recorder := serveNativeMessages(t, h, "/v1/messages", body, nil)

	assertAnthropicMessagesError(t, recorder, http.StatusRequestEntityTooLarge, "invalid_request_error")
}

func TestNativeMessagesEightMiBRequestReachesProvider(t *testing.T) {
	largeText := strings.Repeat("x", 8<<20)
	body, err := json.Marshal(map[string]any{
		"model": "claude-opus-5", "max_tokens": 32,
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":          "text",
						"text":          largeText,
						"cache_control": map[string]any{"type": "ephemeral"},
					},
				},
			},
		},
		"unknown": map[string]any{"keep": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	responseBody := []byte(`{"id":"msg_large","type":"message","role":"assistant","model":"kiro-opus","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":999000,"output_tokens":1}}`)
	caller := &MockProviderCaller{CallResponse: responseBody}
	h := nativeMessagesTestHandler(caller, nil, nil)

	recorder := serveNativeMessages(t, h, "/v1/messages", body, nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(caller.TransformRequestCalls) != 1 {
		t.Fatalf("transform calls=%d want 1", len(caller.TransformRequestCalls))
	}
	if !bytes.Equal(caller.TransformRequestCalls[0].RawBody, body) {
		t.Fatalf("8 MiB request was transformed or truncated: got=%d want=%d", len(caller.TransformRequestCalls[0].RawBody), len(body))
	}
}

func TestNativeMessagesReusesAuthRequestID(t *testing.T) {
	caller := &MockProviderCaller{CallResponse: []byte(`{"id":"msg_request_id","type":"message","role":"assistant","model":"kiro-opus","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)}
	h := nativeMessagesTestHandler(caller, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Content-Type", "application/json")
	ctx := setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", "session-a")
	ctx = context.WithValue(ctx, auth.RequestIDKey, "req_from_auth")
	req = req.WithContext(ctx)
	recorder := httptest.NewRecorder()

	h.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("X-Request-Id"); got != "req_from_auth" {
		t.Fatalf("X-Request-Id=%q want auth request id", got)
	}
	if len(caller.CallEnvelopes) != 1 || caller.CallEnvelopes[0].RequestID != "req_from_auth" {
		t.Fatalf("upstream envelope request id was regenerated: %+v", caller.CallEnvelopes)
	}
}

func TestNativeMessagesSSERejectsInvalidEventOrder(t *testing.T) {
	messageStart := `data: {"type":"message_start","message":{"id":"msg_state","type":"message","role":"assistant","content":[],"model":"kiro-opus","usage":{"input_tokens":1,"output_tokens":0}}}` + "\n\n"
	blockStart := `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n"
	blockDelta := `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"x"}}` + "\n\n"
	blockStop := `data: {"type":"content_block_stop","index":0}` + "\n\n"
	messageDelta := `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}` + "\n\n"
	messageStop := `data: {"type":"message_stop"}` + "\n\n"
	cases := []struct {
		name string
		raw  string
	}{
		{name: "delta before block start", raw: messageStart + blockDelta + messageStop},
		{name: "duplicate block index", raw: messageStart + blockStart + blockStart + blockStop + messageStop},
		{name: "content block after message delta", raw: messageStart + messageDelta + blockStart + blockStop + messageStop},
		{name: "duplicate message delta", raw: messageStart + messageDelta + messageDelta + messageStop},
		{name: "message stop before message delta", raw: messageStart + messageStop},
		{name: "event after message stop", raw: messageStart + messageStop + messageDelta},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildNativeMessagesSSEProjection([]byte(tc.raw)); err == nil {
				t.Fatalf("invalid SSE order was accepted: %s", tc.name)
			}
		})
	}
}

func TestNativeMessagesJSONRejectsDuplicateToolUseIDAcrossBlocks(t *testing.T) {
	raw := []byte(`{"id":"msg_dup","type":"message","role":"assistant","model":"kiro-opus","content":[{"type":"tool_use","id":"toolu_duplicate","name":"Read","input":{"path":"/tmp/a"}},{"type":"tool_use","id":"toolu_duplicate","name":"Write","input":{"path":"/tmp/b"}}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`)
	if _, err := buildNativeMessagesJSONProjection(raw); err == nil {
		t.Fatal("duplicate JSON tool_use.id was accepted")
	}
}

func TestNativeMessagesSSERejectsDuplicateToolUseIDAcrossBlocks(t *testing.T) {
	raw := []byte("data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_dup_sse\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"kiro-opus\",\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n" +
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_duplicate\",\"name\":\"Read\",\"input\":{}}}\n\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_duplicate\",\"name\":\"Write\",\"input\":{}}}\n\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":1}\n\n" +
		"data: {\"type\":\"message_stop\"}\n\n")
	if _, err := buildNativeMessagesSSEProjection(raw); err == nil {
		t.Fatal("duplicate SSE tool_use.id was accepted")
	}
}

func BenchmarkParseNativeMessagesTwoTwelveMiBImages(b *testing.B) {
	image := strings.Repeat("A", 12<<20)
	body := []byte(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + image + `"}},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + image + `"}}]}]}`)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		document, err := parseNativeMessagesDocument(body)
		if err != nil {
			b.Fatal(err)
		}
		if len(document.request.Messages) != 2 {
			b.Fatalf("image messages=%d want=2", len(document.request.Messages))
		}
	}
}

func assertAnthropicMessagesError(t *testing.T, recorder *httptest.ResponseRecorder, status int, errorType string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status=%d body=%s want=%d", recorder.Code, recorder.Body.String(), status)
	}
	var body struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode Anthropic error: %v body=%s", err, recorder.Body.String())
	}
	if body.Type != "error" || body.Error.Type != errorType || body.Error.Message == "" || body.RequestID == "" {
		t.Fatalf("invalid Anthropic error envelope: %#v", body)
	}
	if got := recorder.Header().Get("X-Request-Id"); got != body.RequestID {
		t.Fatalf("X-Request-Id=%q body.request_id=%q", got, body.RequestID)
	}
}
