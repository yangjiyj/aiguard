package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func newDestructiveChatTestHandler(t *testing.T, mode, action string) (*ChatCompletionsHandler, *atomic.Int32) {
	t.Helper()
	return newDestructiveChatTestHandlerWithProtections(t, mode, action, "{}")
}

// newDestructiveChatTestHandlerWithProtections 同 newDestructiveChatTestHandler，另下发防护项配置（JSON 对象）。
func newDestructiveChatTestHandlerWithProtections(t *testing.T, mode, action, protections string) (*ChatCompletionsHandler, *atomic.Int32) {
	t.Helper()
	var confirmations atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"data":{"id":"policy-destructive","name":"destructive","policy_version":"v1","mode":%q,"default_action":"allow","fail_policy":"fail_closed","confirm_channel_enabled":true,"rules":[],"exceptions":[],"config_source":"tenant_policy","destructive":{"mode":%q,"action":%q,"scope_type":"tenant","scope_ref":""},"protections":%s}}`, mode, mode, action, protections)
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			w.WriteHeader(http.StatusCreated)
		case "/admin/v1/internal/agentguard/confirmations":
			confirmations.Add(1)
			w.WriteHeader(http.StatusCreated)
		case "/admin/v1/internal/agentguard/confirmations/consume":
			_, _ = w.Write([]byte(`{"data":{"consumed":false}}`))
		default:
			t.Errorf("unexpected control-plane path: %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	t.Cleanup(controlPlane.Close)

	client := NewToolRiskClient(controlPlane.URL, "internal-secret")
	setToolGuardTestPosture(t, client, false, false)
	return &ChatCompletionsHandler{
		cfg:            &config.Config{SecurityAuditOnly: false},
		securityClient: &MockSecurityChecker{},
		auditWriter:    &MockAuditWriter{},
		toolRiskClient: client,
	}, &confirmations
}

func destructiveChatResponse(t *testing.T, content string, calls ...ToolCall) []byte {
	t.Helper()
	return mustMarshalChatResponse(t, ChatCompletionResponse{
		ID: "chatcmpl-destructive", Object: "chat.completion", Created: 7, Model: "test-model",
		Choices: []Choice{{
			Index: 0, Message: ChoiceMessage{Role: "assistant", Content: content, ToolCalls: calls},
			FinishReason: "tool_calls",
		}},
	})
}

func TestDestructiveChatBlockReturnsCompatibleSafetyMessageWithoutToolCall(t *testing.T) {
	h, confirmations := newDestructiveChatTestHandler(t, "light", "block")
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-chat-block", TenantID: "tenant-1", UserID: "user-1", SessionID: "session-1"}
	call := ToolCall{ID: "call-delete", Type: "function", Function: ToolCallFunc{
		Name: "shell_command", Arguments: `{"command":"rm -rf /srv/sandbox-target"}`,
	}}
	secured, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, destructiveChatResponse(t, "", call))
	if err != nil {
		t.Fatalf("block must return a protocol-compatible response: %v", err)
	}
	var response ChatCompletionResponse
	if err := json.Unmarshal(secured, &response); err != nil {
		t.Fatal(err)
	}
	choice := response.Choices[0]
	if len(choice.Message.ToolCalls) != 0 || choice.FinishReason != "stop" ||
		!strings.Contains(choice.Message.Content, "网关检测到模型准备调用删除或破坏性工具。调用已被网关阻断。操作编号：") {
		t.Fatalf("incompatible safety choice: %+v", choice)
	}
	if auditResult == nil || auditResult.OutputAction != "block" || confirmations.Load() != 0 {
		t.Fatalf("audit=%+v confirmations=%d", auditResult, confirmations.Load())
	}
}

func TestDestructiveChatAlertAllowPreservesStructuredToolCallFieldsAndOrder(t *testing.T) {
	h, confirmations := newDestructiveChatTestHandler(t, "light", "alert_allow")
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-chat-alert", TenantID: "tenant-1", UserID: "user-1", SessionID: "session-1"}
	original := []ToolCall{
		{ID: "call-delete", Type: "function", Function: ToolCallFunc{Name: "shell_command", Arguments: `{ "command": "rm -rf ./dist" }`}},
		{ID: "call-read", Type: "function", Function: ToolCallFunc{Name: "read_file", Arguments: `{"path":"README.md"}`}},
	}
	secured, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, destructiveChatResponse(t, "", original...))
	if err != nil {
		t.Fatalf("alert_allow must pass through: %v", err)
	}
	var response ChatCompletionResponse
	if err := json.Unmarshal(secured, &response); err != nil {
		t.Fatal(err)
	}
	got := response.Choices[0].Message.ToolCalls
	if len(got) != len(original) {
		t.Fatalf("tool_calls=%+v", got)
	}
	for i := range original {
		if got[i].ID != original[i].ID || got[i].Type != original[i].Type ||
			got[i].Function.Name != original[i].Function.Name ||
			got[i].Function.Arguments != original[i].Function.Arguments {
			t.Fatalf("tool call %d changed: got=%+v want=%+v", i, got[i], original[i])
		}
	}
	if auditResult == nil || auditResult.OutputAction != "audit" || confirmations.Load() != 0 {
		t.Fatalf("audit=%+v confirmations=%d", auditResult, confirmations.Load())
	}
}

func TestDestructiveChatOrdinaryTextNeverEntersExecutionGate(t *testing.T) {
	h, confirmations := newDestructiveChatTestHandler(t, "strict", "block")
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-chat-text", TenantID: "tenant-1", UserID: "user-1", SessionID: "session-1"}
	content := "I will run shell only as documentation:\n" + "```sh\nrm -rf /srv/example\n```"
	secured, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, destructiveChatResponse(t, content))
	if err != nil {
		t.Fatalf("ordinary text entered execution gate: %v", err)
	}
	var response ChatCompletionResponse
	if err := json.Unmarshal(secured, &response); err != nil {
		t.Fatal(err)
	}
	if response.Choices[0].Message.Content != content || auditResult.OutputAction != "allow" || confirmations.Load() != 0 {
		t.Fatalf("response=%+v audit=%+v confirmations=%d", response, auditResult, confirmations.Load())
	}
}

func TestDestructiveChatParseRejectedRecordPolicyAllowsCall(t *testing.T) {
	h, confirmations := newDestructiveChatTestHandler(t, "audit", "record")
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-chat-parse", TenantID: "tenant-1", UserID: "user-1", SessionID: "session-1"}
	call := ToolCall{ID: "call-malformed", Type: "function", Function: ToolCallFunc{
		Name: "shell_command", Arguments: `{"command":"rm -rf $("}`,
	}}
	secured, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, destructiveChatResponse(t, "", call))
	if err != nil {
		t.Fatalf("parse rejection must use a compatible safety result: %v", err)
	}
	var response ChatCompletionResponse
	if err := json.Unmarshal(secured, &response); err != nil {
		t.Fatal(err)
	}
	gotCalls := response.Choices[0].Message.ToolCalls
	if len(gotCalls) != 1 || gotCalls[0].ID != call.ID ||
		gotCalls[0].Function.Name != call.Function.Name || gotCalls[0].Function.Arguments != call.Function.Arguments ||
		auditResult.OutputAction != "audit" || confirmations.Load() != 0 {
		t.Fatalf("response=%+v audit=%+v confirmations=%d", response, auditResult, confirmations.Load())
	}
}
func TestDestructiveChatStructuredArgumentsParseRejectedRecordPolicyAllowsCall(t *testing.T) {
	for _, raw := range []string{`{"command":`, `["rm -rf /srv/isolated-fixture"]`, `"rm -rf /srv/isolated-fixture"`} {
		t.Run(raw, func(t *testing.T) {
			h, confirmations := newDestructiveChatTestHandler(t, "audit", "record")
			envelope := &modelrouter.RequestEnvelope{RequestID: "req-chat-json-reject", TenantID: "tenant-1", UserID: "user-1"}
			call := ToolCall{ID: "call-malformed-json", Type: "function", Function: ToolCallFunc{Name: "shell_command", Arguments: raw}}

			secured, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, destructiveChatResponse(t, "", call))
			if err != nil {
				t.Fatalf("parse rejection must return compatible safety response: %v", err)
			}
			var response ChatCompletionResponse
			if err := json.Unmarshal(secured, &response); err != nil {
				t.Fatal(err)
			}
			gotCalls := response.Choices[0].Message.ToolCalls
			if len(gotCalls) != 1 || gotCalls[0].ID != call.ID || gotCalls[0].Function.Arguments != raw ||
				auditResult.OutputAction != "audit" || confirmations.Load() != 0 {
				t.Fatalf("raw=%q response=%+v audit=%+v confirmations=%d", raw, response, auditResult, confirmations.Load())
			}
		})
	}
}

func TestNativeResponsesStructuredArgumentsParseRejectedRecordPolicyAllowsCall(t *testing.T) {
	for _, raw := range []string{`{"command":`, `["rm -rf /srv/isolated-fixture"]`, `"rm -rf /srv/isolated-fixture"`} {
		t.Run(raw, func(t *testing.T) {
			h, _ := newDestructiveChatTestHandler(t, "audit", "record")
			final, err := json.Marshal(map[string]interface{}{
				"id": "resp-parse-rejected", "object": "response", "status": "completed", "model": "test",
				"output": []interface{}{map[string]interface{}{
					"id": "item-malformed", "type": "function_call", "status": "completed",
					"call_id": "call-malformed", "name": "shell_command", "arguments": raw,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			view, err := nativeResponsesSecurityView(final)
			if err != nil {
				t.Fatal(err)
			}
			envelope := &modelrouter.RequestEnvelope{RequestID: "req-native-json-reject", TenantID: "tenant-1", UserID: "user-1"}
			securedView, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, view)
			if err != nil {
				t.Fatalf("native parse rejection security: %v", err)
			}
			var response ChatCompletionResponse
			if err := json.Unmarshal(securedView, &response); err != nil {
				t.Fatal(err)
			}
			gotCalls := response.Choices[0].Message.ToolCalls
			if len(gotCalls) != 1 || gotCalls[0].ID != "call-malformed" || gotCalls[0].Function.Arguments != raw ||
				auditResult.OutputAction != "audit" {
				t.Fatalf("raw=%q secured_view=%s audit=%+v", raw, securedView, auditResult)
			}
			securedFinal, err := secureNativeResponsesOutput(final, securedView)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(securedFinal, final) {
				t.Fatalf("record policy should preserve native response: raw=%q final=%s secured=%s", raw, final, securedFinal)
			}
		})
	}
}

// 2.9.22 批次 2B：删除与破坏选“确认”不再限定 MCP。原用例名 TestDestructiveChatConfirmWithoutExtensionBlocksWithoutTicket，
// 锁的是“chat 协议没有确认扩展，确认一律改成阻断、不建确认单”；现在策略开了确认通道（这里的有效
// 策略 confirm_channel_enabled=true），chat 走普通确认票据：调用照样扣下，但建一张确认单。
func TestDestructiveChatConfirmUsesConfirmationTicket(t *testing.T) {
	h, confirmations := newDestructiveChatTestHandler(t, "light", "confirm")
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-chat-confirm", TenantID: "tenant-1", UserID: "user-1", SessionID: "session-1"}
	call := ToolCall{ID: "call-confirm", Type: "function", Function: ToolCallFunc{
		Name: "shell_command", Arguments: `{"command":"rm -rf /srv/sandbox-target"}`,
	}}
	secured, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, destructiveChatResponse(t, "", call))
	if err != nil {
		t.Fatalf("unsupported confirmation must return a compatible safety result: %v", err)
	}
	var response ChatCompletionResponse
	if err := json.Unmarshal(secured, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Choices[0].Message.ToolCalls) != 0 ||
		len(response.Choices[0].Message.Content) == 0 ||
		auditResult.OutputAction != "block" || confirmations.Load() != 1 {
		t.Fatalf("response=%+v audit=%+v confirmations=%d", response, auditResult, confirmations.Load())
	}
}

func TestNativeResponsesDestructiveBlockReplacesCallWithCompatibleSafetyResult(t *testing.T) {
	var confirmations atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"id":"policy-responses","name":"destructive","policy_version":"v1","mode":"light","default_action":"allow","fail_policy":"fail_closed","confirm_channel_enabled":true,"rules":[],"exceptions":[],"config_source":"tenant_policy","destructive":{"mode":"light","action":"block","scope_type":"tenant","scope_ref":""}}}`))
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			w.WriteHeader(http.StatusCreated)
		case "/admin/v1/internal/agentguard/confirmations":
			confirmations.Add(1)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected control-plane path: %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer controlPlane.Close()

	client := NewToolRiskClient(controlPlane.URL, "internal-secret")
	setToolGuardTestPosture(t, client, false, false)
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-native", ProviderID: "provider-native", ModelName: "gpt-5.6-sol",
		UpstreamModelID: "gpt-5.6", ProviderType: "openai",
		ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true,
	}}
	upstream := []byte(`{"id":"resp_native","object":"response","status":"completed","model":"gpt-5.6","output":[{"id":"item_1","type":"function_call","status":"completed","call_id":"call_delete","name":"shell_command","arguments":"{\"command\":\"rm -rf /srv/sandbox-target\"}"}],"usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7}}`)
	handler := NewResponsesHandler(
		&config.Config{SecurityAuditOnly: false}, resolver, &MockRateLimitChecker{},
		&MockSecurityChecker{}, &MockAuditWriter{},
		&MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallResponse: upstream}},
		client, nil,
	)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response ResponsesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ID != "resp_native" || response.Model != "gpt-5.6" || response.Status != "completed" ||
		response.Usage == nil || response.Usage.TotalTokens != 7 {
		t.Fatalf("incompatible response envelope: %+v", response)
	}
	for _, item := range response.Output {
		if strings.Contains(item.Type, "call") || item.CallID == "call_delete" ||
			strings.Contains(item.Arguments, "rm -rf") {
			t.Fatalf("blocked call leaked: %+v", item)
		}
	}
	// The replacement is the block notice: reason, rule, block and operation
	// numbers that the console's 阻断记录 can look up.
	if len(response.Output) != 1 || response.Output[0].Type != "message" ||
		!strings.Contains(response.Output[0].Content[0].Text, "模型准备调用删除或破坏性工具") ||
		!strings.Contains(response.Output[0].Content[0].Text, "阻断编号：evt_") ||
		!strings.Contains(response.Output[0].Content[0].Text, "操作编号：op_") {
		t.Fatalf("missing compatible safety output: %+v", response.Output)
	}
	if confirmations.Load() != 0 {
		t.Fatalf("block created %d confirmation tickets", confirmations.Load())
	}
}

func TestNativeResponsesDestructiveAlertAllowPreservesBodyBytesWhenAuditFails(t *testing.T) {
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"id":"policy-responses-alert","name":"destructive","policy_version":"v1","mode":"light","default_action":"allow","fail_policy":"fail_closed","confirm_channel_enabled":true,"rules":[],"exceptions":[],"config_source":"tenant_policy","destructive":{"mode":"light","action":"alert_allow","scope_type":"tenant","scope_ref":""}}}`))
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			http.Error(w, "injected lifecycle transaction failure", http.StatusServiceUnavailable)
		default:
			t.Errorf("unexpected control-plane path: %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer controlPlane.Close()

	client := NewToolRiskClient(controlPlane.URL, "internal-secret")
	setToolGuardTestPosture(t, client, false, false)
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-native", ProviderID: "provider-native", ModelName: "gpt-5.6-sol",
		UpstreamModelID: "gpt-5.6", ProviderType: "openai",
		ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true,
	}}
	upstream := []byte(`{"id":"resp_alert","object":"response","status":"completed","model":"gpt-5.6","output":[{"id":"item_1","type":"function_call","status":"completed","call_id":"call_delete","name":"shell_command","arguments":"{ \"command\": \"rm -rf ./dist\" }","unknown_item_field":{"keep":true}}],"usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7},"unknown_response_field":{"keep":true}}`)
	handler := NewResponsesHandler(
		&config.Config{SecurityAuditOnly: false}, resolver, &MockRateLimitChecker{},
		&MockSecurityChecker{}, &MockAuditWriter{},
		&MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallResponse: upstream}},
		client, nil,
	)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), upstream) {
		t.Fatalf("alert_allow changed body bytes\nwant=%s\n got=%s", upstream, w.Body.Bytes())
	}
}

func TestNativeResponsesSSEDestructiveBlockWaitsForDoneAndReturnsSafeTerminal(t *testing.T) {
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"id":"policy-responses-sse","name":"destructive","policy_version":"v1","mode":"light","default_action":"allow","fail_policy":"fail_closed","confirm_channel_enabled":true,"rules":[],"exceptions":[],"config_source":"tenant_policy","destructive":{"mode":"light","action":"block","scope_type":"tenant","scope_ref":""}}}`))
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected control-plane path: %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer controlPlane.Close()

	client := NewToolRiskClient(controlPlane.URL, "internal-secret")
	setToolGuardTestPosture(t, client, false, false)
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-native", ProviderID: "provider-native", ModelName: "gpt-5.6-sol",
		UpstreamModelID: "gpt-5.6", ProviderType: "openai",
		ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true,
	}}
	final := `{"id":"resp_sse","object":"response","status":"completed","model":"gpt-5.6","output":[{"id":"item_1","type":"function_call","status":"completed","call_id":"call_delete","name":"shell_command","arguments":"{\"command\":\"rm -rf /srv/sandbox-target\"}"}],"usage":{"input_tokens":3,"output_tokens":4,"total_tokens":7}}`
	upstream := []byte(
		"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_sse\",\"object\":\"response\",\"status\":\"in_progress\",\"output\":[]}}\n\n" +
			"event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"item_1\",\"output_index\":0,\"delta\":\"{\\\"command\\\":\\\"rm -\"}\n\n" +
			"event: response.function_call_arguments.done\ndata: {\"type\":\"response.function_call_arguments.done\",\"item_id\":\"item_1\",\"output_index\":0,\"arguments\":\"{\\\"command\\\":\\\"rm -rf /srv/sandbox-target\\\"}\"}\n\n" +
			"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":" + final + "}\n\n",
	)
	handler := NewResponsesHandler(
		&config.Config{SecurityAuditOnly: false}, resolver, &MockRateLimitChecker{},
		&MockSecurityChecker{}, &MockAuditWriter{},
		&MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallResponse: upstream}},
		client, nil,
	)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect","stream":true}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	// 阻断提示写命令骨架（与告警证据相同）；被拦下的工具调用本身（调用编号、参数 JSON、参数增量事件）不外泄。
	if strings.Contains(w.Body.String(), "call_delete") || strings.Contains(w.Body.String(), `\"command\"`) ||
		strings.Contains(w.Body.String(), `"arguments"`) || strings.Contains(w.Body.String(), "function_call_arguments") {
		t.Fatalf("blocked SSE call leaked: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "命中内容：shell_command · 删除文件：rm -rf /srv/sandbox-target") {
		t.Fatalf("阻断提示应写命令骨架: %s", w.Body.String())
	}
	events := parseResponsesSSE(t, w.Body.String())
	types := eventTypes(events)
	if len(types) < 3 || types[0] != "response.created" || types[len(types)-1] != "response.completed" {
		t.Fatalf("invalid SSE state machine: %v", types)
	}
	assertSequenceNumbers(t, events)
	completed := events[len(events)-1]["response"].(map[string]interface{})
	output := completed["output"].([]interface{})
	if len(output) != 1 || output[0].(map[string]interface{})["type"] != "message" {
		t.Fatalf("unsafe terminal output: %#v", output)
	}
}

func TestNativeResponsesSSEDuplicateOutputItemDecidesOnceAndReplaysAlertBytes(t *testing.T) {
	var logs atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"id":"policy-responses-duplicate","name":"destructive","policy_version":"v1","mode":"light","default_action":"allow","fail_policy":"fail_closed","confirm_channel_enabled":true,"rules":[],"exceptions":[],"config_source":"tenant_policy","destructive":{"mode":"light","action":"alert_allow","scope_type":"tenant","scope_ref":""}}}`))
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			logs.Add(1)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected control-plane path: %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer controlPlane.Close()

	client := NewToolRiskClient(controlPlane.URL, "internal-secret")
	setToolGuardTestPosture(t, client, false, false)
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-native", ProviderID: "provider-native", ModelName: "gpt-5.6-sol",
		UpstreamModelID: "gpt-5.6", ProviderType: "openai",
		ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true,
	}}
	item := `{"id":"item_duplicate","type":"function_call","status":"completed","call_id":"call_duplicate","name":"shell_command","arguments":"{\"command\":\"rm -rf ./dist\"}"}`
	raw := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_duplicate\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"gpt-5.6\",\"output\":[" + item + "," + item + "],\"usage\":{\"input_tokens\":3,\"output_tokens\":4,\"total_tokens\":7}}}\n\n"
	handler := NewResponsesHandler(
		&config.Config{SecurityAuditOnly: false}, resolver, &MockRateLimitChecker{},
		&MockSecurityChecker{}, &MockAuditWriter{},
		&MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallResponse: []byte(raw)}},
		client, nil,
	)

	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"inspect","stream":true}`)))
	if w.Code != http.StatusOK || w.Body.String() != raw {
		t.Fatalf("alert SSE changed: status=%d\nwant=%s\n got=%s", w.Code, raw, w.Body.String())
	}
	if logs.Load() != 1 {
		t.Fatalf("duplicate output item produced %d decisions/logs, want 1", logs.Load())
	}
}

func TestOperationIDIsStableAndBoundToStableInvocationIdentity(t *testing.T) {
	identity := destructiveOperationIdentity{
		TenantID: "tenant-1", Protocol: "responses", SessionID: "session-1", RequestID: "req-1",
		OutputItemID: "item-1", ToolCallID: "call-1", ToolName: "shell_command",
		CanonicalArgs: `{"command":"rm -rf ./dist"}`,
	}
	base := operationID(identity)
	if base == "" || base != operationID(identity) {
		t.Fatalf("operation ID is not stable: %q", base)
	}
	retry := identity
	retry.RequestID = "req-2"
	if retried := operationID(retry); retried != base {
		t.Fatalf("HTTP reconnect changed operation ID: first=%q retry=%q", base, retried)
	}
	for _, protocol := range []string{"chat", "responses", "mcp"} {
		withoutSession := identity
		withoutSession.Protocol = protocol
		withoutSession.SessionID = ""
		withoutSession.RequestID = "req-without-session-1"
		first := operationID(withoutSession)
		withoutSession.RequestID = "req-without-session-2"
		if second := operationID(withoutSession); second == first {
			t.Fatalf("%s identity without reliable session crossed requests: %q", protocol, first)
		}
	}
	changed := []destructiveOperationIdentity{}
	for _, mutate := range []func(*destructiveOperationIdentity){
		func(v *destructiveOperationIdentity) { v.TenantID = "tenant-2" },
		func(v *destructiveOperationIdentity) { v.Protocol = "chat" },
		func(v *destructiveOperationIdentity) { v.OutputItemID = "item-2" },
		func(v *destructiveOperationIdentity) { v.ToolCallID = "call-2" },
		func(v *destructiveOperationIdentity) { v.CanonicalArgs = `{"command":"rm -rf ./build"}` },
	} {
		candidate := identity
		mutate(&candidate)
		changed = append(changed, candidate)
	}
	for _, candidate := range changed {
		if got := operationID(candidate); got == base {
			t.Fatalf("operation ID collision for changed invocation identity: %+v", candidate)
		}
	}
	rejected := identity
	rejected.IdentityRejected = true
	firstRejected := operationID(rejected)
	rejected.RequestID = "req-2"
	if operationID(rejected) == firstRejected {
		t.Fatal("fail-safe rejected identities must remain request scoped")
	}
}

func TestChatAndResponsesReconnectKeepStableOperationAndSeparateRealCalls(t *testing.T) {
	var logs []map[string]any
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"id":"destructive-log","policy_version":"v1","mode":"strict","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":[],"destructive":{"mode":"strict","action":"block","scope_type":"tenant"}}}`))
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			logs = append(logs, payload)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected control-plane path: %s", r.URL.Path)
		}
	}))
	defer controlPlane.Close()

	client := NewToolRiskClient(controlPlane.URL, "internal-secret")
	setToolGuardTestPosture(t, client, false, false)
	h := &ChatCompletionsHandler{
		cfg: &config.Config{SecurityAuditOnly: false}, securityClient: &MockSecurityChecker{},
		auditWriter: &MockAuditWriter{}, toolRiskClient: client,
	}
	chatEnvelope := &modelrouter.RequestEnvelope{RequestID: "req-chat-log", TenantID: "tenant-1", SessionID: "session-chat", EndpointType: "chat"}
	chatCall := ToolCall{ID: "call-chat-log", Type: "function", Function: ToolCallFunc{
		Name: "shell_command", Arguments: `{"command":"rm -rf /srv/isolated-fixture"}`,
	}}
	if _, _, err := h.applyOutputSecurity(context.Background(), chatEnvelope, nil, destructiveChatResponse(t, "", chatCall)); err != nil {
		t.Fatal(err)
	}
	chatRetry := *chatEnvelope
	chatRetry.RequestID = "req-chat-retry"
	if _, _, err := h.applyOutputSecurity(context.Background(), &chatRetry, nil, destructiveChatResponse(t, "", chatCall)); err != nil {
		t.Fatal(err)
	}
	otherChatCall := chatCall
	otherChatCall.ID = "call-chat-other"
	if _, _, err := h.applyOutputSecurity(context.Background(), chatEnvelope, nil, destructiveChatResponse(t, "", otherChatCall)); err != nil {
		t.Fatal(err)
	}

	responsesEnvelope := &modelrouter.RequestEnvelope{
		RequestID: "req-responses-log", TenantID: "tenant-1",
		SessionID: "session-responses", EndpointType: "responses",
	}
	nativeFinal := []byte(`{"id":"resp-log","object":"response","status":"completed","output":[{"id":"item-native-log","type":"custom_tool_call","call_id":"call-native-log","name":"shell_command","input":"rm -rf /srv/isolated-fixture"}]}`)
	view, err := nativeResponsesSecurityView(nativeFinal)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.applyOutputSecurity(context.Background(), responsesEnvelope, nil, view); err != nil {
		t.Fatal(err)
	}
	responsesRetry := *responsesEnvelope
	responsesRetry.RequestID = "req-responses-retry"
	if _, _, err := h.applyOutputSecurity(context.Background(), &responsesRetry, nil, view); err != nil {
		t.Fatal(err)
	}

	if len(logs) != 10 {
		t.Fatalf("tool logs=%v", logs)
	}
	for i, log := range logs {
		wantEvent := "tool_destructive_intent"
		if i%2 == 1 {
			wantEvent = "tool_attempt_blocked"
		}
		parameters, ok := log["parameters"].(map[string]interface{})
		if log["event_type"] != wantEvent || !ok || len(parameters) != 1 ||
			parameters["command"] != "rm -rf /srv/isolated-fixture" || log["result"] != "" {
			t.Fatalf("log[%d]=%v want event=%s", i, log, wantEvent)
		}
	}
	operation := func(index int) any { return logs[index]["operation_id"] }
	if operation(0) != operation(1) || operation(0) != operation(2) || operation(0) != operation(3) {
		t.Fatalf("chat reconnect changed operation id: %#v", logs[:4])
	}
	if operation(4) != operation(5) || operation(4) == operation(0) {
		t.Fatalf("different chat call collided: first=%v other=%v", operation(0), operation(4))
	}
	if operation(6) != operation(7) || operation(6) != operation(8) || operation(6) != operation(9) {
		t.Fatalf("responses reconnect changed operation id: %#v", logs[6:])
	}
	if operation(6) == operation(0) {
		t.Fatalf("cross-protocol operation collision: chat=%v responses=%v", operation(0), operation(6))
	}

}

func TestDestructiveChatDuplicateNonEmptyCallIDConflictsFailSafe(t *testing.T) {
	for _, test := range []struct {
		name        string
		calls       []ToolCall
		wantCalls   int
		wantLogs    int
		wantBlocked bool
	}{
		{
			name: "conflicting safe then dangerous calls",
			calls: []ToolCall{
				{ID: "call-duplicate", Type: "function", Function: ToolCallFunc{Name: "read_file", Arguments: `{"path":"README.md"}`}},
				{ID: "call-duplicate", Type: "function", Function: ToolCallFunc{Name: "shell_command", Arguments: `{"command":"rm -rf /srv/isolated-fixture"}`}},
			},
			// 2.9.22：身份冲突改为防护项 agent.identity_rejected（默认告警放行），不再把同一批的安全调用
			// 一起按删除与破坏拦下；危险调用照常由删除与破坏卡片拦下。原期望 0 个调用、4 条日志。
			wantCalls: 1, wantLogs: 3, wantBlocked: true,
		},
		{
			name: "byte identical duplicate calls",
			calls: []ToolCall{
				{ID: "call-identical", Type: "function", Function: ToolCallFunc{Name: "read_file", Arguments: `{"path":"README.md"}`}},
				{ID: "call-identical", Type: "function", Function: ToolCallFunc{Name: "read_file", Arguments: `{"path":"README.md"}`}},
			},
			wantCalls: 2, wantLogs: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs []map[string]any
			controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/admin/v1/internal/agentguard/effective-policy":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"data":{"id":"duplicate-id","policy_version":"v1","mode":"strict","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":[],"destructive":{"mode":"strict","action":"block","scope_type":"tenant"}}}`))
				case "/admin/v1/internal/tools/config":
					_, _ = w.Write([]byte(`{"data":[]}`))
				case "/admin/v1/internal/tools/logs":
					var payload map[string]any
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					logs = append(logs, payload)
					w.WriteHeader(http.StatusCreated)
				default:
					t.Fatalf("unexpected control-plane path: %s", r.URL.Path)
				}
			}))
			defer controlPlane.Close()

			client := NewToolRiskClient(controlPlane.URL, "internal-test-value")
			setToolGuardTestPosture(t, client, false, false)
			h := &ChatCompletionsHandler{
				cfg: &config.Config{SecurityAuditOnly: false}, securityClient: &MockSecurityChecker{},
				auditWriter: &MockAuditWriter{}, toolRiskClient: client,
			}
			envelope := &modelrouter.RequestEnvelope{RequestID: "req-" + strings.ReplaceAll(test.name, " ", "-"), TenantID: "tenant-1"}
			secured, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, destructiveChatResponse(t, "", test.calls...))
			if err != nil {
				t.Fatal(err)
			}
			var response ChatCompletionResponse
			if err := json.Unmarshal(secured, &response); err != nil {
				t.Fatal(err)
			}
			if len(response.Choices[0].Message.ToolCalls) != test.wantCalls || len(logs) != test.wantLogs {
				t.Fatalf("calls=%+v logs=%v", response.Choices[0].Message.ToolCalls, logs)
			}
			if test.wantBlocked && auditResult.OutputAction != "block" {
				t.Fatalf("audit=%+v", auditResult)
			}
			if test.wantBlocked && (logs[1]["operation_id"] != logs[2]["operation_id"] || logs[1]["operation_id"] == "" ||
				logs[0]["effective_decision"] != "audit" || logs[1]["effective_decision"] != "block" || logs[2]["effective_decision"] != "block") {
				t.Fatalf("conflicting identities reused a decision: %v", logs)
			}
			if test.wantBlocked && response.Choices[0].Message.ToolCalls[0].Function.Name != "read_file" {
				t.Fatalf("only the dangerous call is withheld: %+v", response.Choices[0].Message.ToolCalls)
			}
			if !test.wantBlocked && (response.Choices[0].Message.ToolCalls[0] != test.calls[0] || response.Choices[0].Message.ToolCalls[1] != test.calls[1]) {
				t.Fatalf("identical duplicates changed: %+v", response.Choices[0].Message.ToolCalls)
			}
		})
	}
}

func TestDestructiveChatMissingCallIDsUseChoiceAndToolIndexes(t *testing.T) {
	h, _ := newDestructiveChatTestHandler(t, "strict", "block")
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-chat-missing-ids", TenantID: "tenant-1", UserID: "user-1"}
	safe := ToolCall{Type: "function", Function: ToolCallFunc{Name: "read_file", Arguments: `{"path":"README.md"}`}}
	dangerous := ToolCall{Type: "function", Function: ToolCallFunc{Name: "shell_command", Arguments: `{"command":"rm -rf /srv/isolated-fixture"}`}}
	response := ChatCompletionResponse{
		ID: "chatcmpl-missing-ids", Object: "chat.completion", Model: "test-model",
		Choices: []Choice{
			{Index: 0, Message: ChoiceMessage{Role: "assistant", ToolCalls: []ToolCall{safe, dangerous}}, FinishReason: "tool_calls"},
			{Index: 1, Message: ChoiceMessage{Role: "assistant", ToolCalls: []ToolCall{dangerous}}, FinishReason: "tool_calls"},
		},
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}

	secured, _, err := h.applyOutputSecurity(context.Background(), envelope, nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	var got ChatCompletionResponse
	if err := json.Unmarshal(secured, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Choices[0].Message.ToolCalls) != 1 || got.Choices[0].Message.ToolCalls[0].Function.Name != "read_file" || got.Choices[0].Message.ToolCalls[0].ID != "" {
		t.Fatalf("same-choice missing IDs reused a decision: %+v", got.Choices[0])
	}
	if len(got.Choices[1].Message.ToolCalls) != 0 || got.Choices[1].FinishReason != "stop" {
		t.Fatalf("multi-choice missing IDs reused a decision: %+v", got.Choices[1])
	}
}

func applyNativeResponsesDestructiveSecurity(t *testing.T, output []interface{}) ([]interface{}, *AuditResult) {
	t.Helper()
	return applyNativeResponsesDestructiveSecurityWith(t, output, "{}")
}

func applyNativeResponsesDestructiveSecurityWith(t *testing.T, output []interface{}, protections string) ([]interface{}, *AuditResult) {
	t.Helper()
	h, _ := newDestructiveChatTestHandlerWithProtections(t, "strict", "block", protections)
	final, err := json.Marshal(map[string]interface{}{
		"id": "resp-identity", "object": "response", "status": "completed", "model": "test", "output": output,
	})
	if err != nil {
		t.Fatal(err)
	}
	view, err := nativeResponsesSecurityView(final)
	if err != nil {
		t.Fatal(err)
	}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-native-identity", TenantID: "tenant-1", UserID: "user-1"}
	securedView, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, view)
	if err != nil {
		t.Fatal(err)
	}
	securedFinal := final
	if auditResult.OutputAction == "block" {
		securedFinal, err = secureNativeResponsesOutput(final, securedView)
		if err != nil {
			t.Fatal(err)
		}
	}
	var response map[string]interface{}
	if err := json.Unmarshal(securedFinal, &response); err != nil {
		t.Fatal(err)
	}
	securedOutput, _ := response["output"].([]interface{})
	return securedOutput, auditResult
}

func TestNativeResponsesCompositeIdentityAndConflictsFailSafe(t *testing.T) {
	safe := func(itemType, itemID, callID string) map[string]interface{} {
		return map[string]interface{}{
			"id": itemID, "type": itemType, "status": "completed", "call_id": callID,
			"name": "read_file", "arguments": `{"path":"README.md"}`, "extension": map[string]interface{}{"keep": true},
		}
	}
	dangerous := func(itemType, itemID, callID string) map[string]interface{} {
		return map[string]interface{}{
			"id": itemID, "type": itemType, "status": "completed", "call_id": callID,
			"name": "shell_command", "arguments": `{"command":"rm -rf /srv/isolated-fixture"}`,
		}
	}
	for _, test := range []struct {
		name       string
		output     []interface{}
		wantSafeID string
	}{
		{
			name: "function and custom calls sharing call id",
			output: []interface{}{
				safe("custom_tool_call", "item-custom-safe", "call-shared"),
				dangerous("function_call", "item-function-danger", "call-shared"),
			},
			wantSafeID: "item-custom-safe",
		},
		{
			name: "duplicate call id on different output items",
			output: []interface{}{
				safe("function_call", "item-safe", "call-duplicate"),
				dangerous("function_call", "item-danger", "call-duplicate"),
			},
			wantSafeID: "item-safe",
		},
		// 2.9.22：身份不可靠改为防护项 agent.identity_rejected。原用例期望只有身份缺口的安全调用也被拦下，
		// 改为默认告警放行（该项配成阻断时照拦，见 TestStructuredToolGateIdentityRejectedFollowsProtectionItem）。
		{
			name:   "missing output item and call ids",
			output: []interface{}{safe("function_call", "", "")},
		},
		// 两个调用共用同一输出项编号：危险调用由删除与破坏卡片拦下，按编号撤下时同编号的另一个一起撤下。
		{
			name: "same identity with conflicting arguments",
			output: []interface{}{
				safe("function_call", "item-conflict", "call-conflict"),
				dangerous("function_call", "item-conflict", "call-conflict"),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, auditResult := applyNativeResponsesDestructiveSecurity(t, test.output)
			if test.name == "missing output item and call ids" {
				if len(output) != 1 || auditResult.OutputAction == "block" {
					t.Fatalf("identity gap alone alerts and allows by default: output=%v audit=%+v", output, auditResult)
				}
				return
			}
			var calls []map[string]interface{}
			for _, raw := range output {
				item, _ := raw.(map[string]interface{})
				itemType, _ := item["type"].(string)
				if strings.Contains(itemType, "call") {
					calls = append(calls, item)
				}
			}
			if test.wantSafeID == "" {
				if len(calls) != 0 || auditResult.OutputAction != "block" {
					t.Fatalf("unreliable identity was not blocked: calls=%v audit=%+v", calls, auditResult)
				}
				return
			}
			if len(calls) != 1 || calls[0]["id"] != test.wantSafeID || calls[0]["extension"] == nil || auditResult.OutputAction != "block" {
				t.Fatalf("allowed call fields/order changed or dangerous call leaked: calls=%v audit=%+v", calls, auditResult)
			}
		})
	}
}
func TestKnownAgentNativeResponsesIdentityGapDoesNotCreateDestructiveAlert(t *testing.T) {
	for _, agentType := range []string{"openai-codex", "claude-code", "opencode", "workbuddy"} {
		t.Run(agentType, func(t *testing.T) {
			h, _ := newDestructiveChatTestHandler(t, "strict", "block")
			final, err := json.Marshal(map[string]interface{}{
				"id": "resp-known-agent", "object": "response", "status": "completed", "model": "test",
				"output": []interface{}{map[string]interface{}{
					"id": "", "type": "custom_tool_call", "call_id": "call-safe", "name": "exec", "input": "pwd",
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			view, err := nativeResponsesSecurityView(final)
			if err != nil {
				t.Fatal(err)
			}
			envelope := &modelrouter.RequestEnvelope{
				RequestID: "req-known-agent-identity", TenantID: "tenant-1", UserID: "user-1", AgentType: agentType,
			}
			secured, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, view)
			if err != nil {
				t.Fatalf("known agent safe call returned error: %v", err)
			}
			if auditResult == nil || auditResult.OutputAction != "allow" {
				t.Fatalf("known agent safe call was treated as destructive: audit=%+v body=%s", auditResult, secured)
			}
		})
	}
}

func TestKnownAgentNativeResponsesExecInputStillDetectsDestructiveCommand(t *testing.T) {
	h, _ := newDestructiveChatTestHandler(t, "strict", "block")
	final, err := json.Marshal(map[string]interface{}{
		"id": "resp-known-agent-danger", "object": "response", "status": "completed", "model": "test",
		"output": []interface{}{map[string]interface{}{
			"id": "", "type": "custom_tool_call", "call_id": "call-danger", "name": "exec", "input": "rm -rf /tmp/jjdguard-loop-victim",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	view, err := nativeResponsesSecurityView(final)
	if err != nil {
		t.Fatal(err)
	}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req-known-agent-danger", TenantID: "tenant-1", UserID: "user-1", AgentType: "openai-codex",
	}
	secured, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, view)
	if err != nil {
		t.Fatalf("destructive call should produce a compatible response: %v", err)
	}
	if auditResult == nil || auditResult.OutputAction != "block" || !strings.Contains(string(secured), "op_") {
		t.Fatalf("known agent destructive exec was not blocked: audit=%+v body=%s", auditResult, secured)
	}
}

func TestKnownAgentNativeResponsesDiscardableCommandWithoutWorkspaceContextIsAuditOnly(t *testing.T) {
	for _, agentType := range []string{"openai-codex", "claude-code", "opencode", "workbuddy"} {
		t.Run(agentType, func(t *testing.T) {
			h, _ := newDestructiveChatTestHandler(t, "strict", "block")
			final, err := json.Marshal(map[string]interface{}{
				"id": "resp-known-agent-discardable", "object": "response", "status": "completed", "model": "test",
				"output": []interface{}{map[string]interface{}{
					"id": "", "type": "custom_tool_call", "call_id": "call-discardable", "name": "exec", "input": "rm -rf dist/assets",
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			view, err := nativeResponsesSecurityView(final)
			if err != nil {
				t.Fatal(err)
			}
			envelope := &modelrouter.RequestEnvelope{
				RequestID: "req-known-agent-discardable", TenantID: "tenant-1", UserID: "user-1", AgentType: agentType,
			}
			secured, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, view)
			if err != nil {
				t.Fatalf("discardable framework command returned error: %v", err)
			}
			if auditResult == nil || auditResult.OutputAction != "audit" {
				t.Fatalf("discardable framework command was treated as high-risk: audit=%+v body=%s", auditResult, secured)
			}
		})
	}
}

// 2.9.22：未知客户端的身份缺口是防护项 agent.identity_rejected；原用例靠“身份异常一律按删除与破坏
// 兜底阻断”锁定，改为该项配成阻断时照拦（默认告警放行，另见身份异常的单元用例）。
func TestUnknownAgentNativeResponsesDiscardableCommandStaysHighRisk(t *testing.T) {
	h, _ := newDestructiveChatTestHandlerWithProtections(t, "strict", "block", `{"agent.identity_rejected":{"action":"block"}}`)
	final, err := json.Marshal(map[string]interface{}{
		"id": "resp-unknown-agent-discardable", "object": "response", "status": "completed", "model": "test",
		"output": []interface{}{map[string]interface{}{
			"id": "", "type": "custom_tool_call", "call_id": "call-unknown-discardable", "name": "exec", "input": "rm -rf dist/assets",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	view, err := nativeResponsesSecurityView(final)
	if err != nil {
		t.Fatal(err)
	}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req-unknown-agent-discardable", TenantID: "tenant-1", UserID: "user-1", AgentType: "custom-client",
	}
	secured, auditResult, err := h.applyOutputSecurity(context.Background(), envelope, nil, view)
	if err != nil {
		t.Fatalf("unknown agent destructive command returned error: %v", err)
	}
	if auditResult == nil || auditResult.OutputAction != "block" || !strings.Contains(string(secured), "op_") {
		t.Fatalf("unknown agent command was downgraded: audit=%+v body=%s", auditResult, secured)
	}
}
