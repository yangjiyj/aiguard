package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 本文件：安全检测期间客户端断开的端到端用例（handler 层，真实 RealAuditWriter，只替换落库的 DB）。
// 每条用例同时覆盖 4 种执行模式 x 5 种检测结果：
//   - client_gone / client_gone_wrapped：请求 ctx 在检测期间被取消，必须记 client_canceled；
//   - deadline / engine_down / engine_internal_cancel：对照组，原行为不变（写 check_failed，
//     protect + fail-closed 仍然是 security_blocked/503，其余仍放行）。

// ---- chat 非流式 ----

func newGoneChatHandler(e *goneEnv, cfg *config.Config) *ChatCompletionsHandler {
	h := NewChatCompletionsHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, e.sec, e.writer,
		fixedAdapterFactory{caller: &MockProviderCaller{}}, e.client, nil)
	h.SetRelayMetrics(e.metrics)
	return h
}

func goneChatRequest(ctx context.Context, stream bool) *http.Request {
	body, _ := json.Marshal(ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []Message{{Role: "user", Content: jsonQuote("Hello")}},
		Stream:   stream,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(setAuthInfo(ctx, "tenant-123", "project-123", "user-123", "key-123", ""))
}

func serveGone(h http.Handler, req *http.Request) goneResult {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return goneResult{httpCode: w.Code, body: w.Body.String()}
}

// controlFor 是对照组（真正的检测失败）在 chat / responses 兼容 / 输入侧路径的原有收尾：
// 只有 protect + fail-closed 是 security_blocked/503，其余放行。
func controlFor(cfg goneConfig, events ...string) goneExpect {
	if cfg.failClosed && !cfg.auditOnly {
		return goneExpect{status: "security_blocked", code: http.StatusServiceUnavailable, events: events}
	}
	return goneExpect{status: "success", code: http.StatusOK, events: events}
}

// controlForNative 是 messages 原生 / responses 原生路径的对照组：这两条路径从来不走
// rejectGuardrailDetectionUnavailable，检测失败 + protect + fail-closed 的现状是
// security_blocked/403（带拦截文案），不是 503。这是修复前就有的行为，本任务不改，
// 测试只钉住「原行为不变」。
func controlForNative(cfg goneConfig, events ...string) goneExpect {
	if cfg.failClosed && !cfg.auditOnly {
		return goneExpect{status: "security_blocked", code: http.StatusForbidden, events: events}
	}
	return goneExpect{status: "success", code: http.StatusOK, events: events}
}

func TestChatNonStreamOutputScanClientGone(t *testing.T) {
	runGoneMatrix(t, "output", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		h := newGoneChatHandler(e, &config.Config{})
		res := serveGone(h.Handler(), goneChatRequest(e.ctx, false))
		e.check(t, res, controlFor(cfg, "security_output_check_failed"))
	})
}

// chat 先攒后发：流式请求但上游不走实时流（GATEWAY_UPSTREAM_STREAMING=false），先攒完再扫描再回放。
func TestChatBufferedStreamOutputScanClientGone(t *testing.T) {
	runGoneMatrix(t, "output", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		h := newGoneChatHandler(e, &config.Config{UpstreamStreaming: false})
		res := serveGone(h.Handler(), goneChatRequest(e.ctx, true))
		e.check(t, res, controlFor(cfg, "security_output_check_failed"))
	})
}

// 先攒后发 + 保活已发头（200 + SSE 头已提交）：客户端断开仍记 client_canceled，且不再往已断开的连接写拦截帧。
func TestChatBufferedStreamKeepaliveCommittedOutputScanClientGone(t *testing.T) {
	runGoneMatrix(t, "output", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		caller := &slowProviderCaller{delay: 60 * time.Millisecond}
		h := NewChatCompletionsHandler(&config.Config{StreamKeepaliveInterval: 20 * time.Millisecond},
			&MockModelResolver{}, &MockRateLimitChecker{}, e.sec, e.writer, fixedAdapterFactory{caller: caller}, e.client, nil)
		h.SetRelayMetrics(e.metrics)
		w := newFlushRecorder()
		h.Handler().ServeHTTP(w, goneChatRequest(e.ctx, true))
		e.check(t, goneResult{httpCode: w.code(), body: w.body()}, controlFor(cfg, "security_output_check_failed"))
	})
}

// ---- 输入侧 ----

func TestChatInputScanClientGone(t *testing.T) {
	runGoneMatrix(t, "input", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		h := newGoneChatHandler(e, &config.Config{})
		res := serveGone(h.Handler(), goneChatRequest(e.ctx, false))
		e.check(t, res, controlFor(cfg, "security_check_failed"))
	})
}

func TestChatStreamInputScanClientGone(t *testing.T) {
	runGoneMatrix(t, "input", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		h := newGoneChatHandler(e, &config.Config{})
		res := serveGone(h.Handler(), goneChatRequest(e.ctx, true))
		e.check(t, res, controlFor(cfg, "security_check_failed"))
	})
}

// ---- messages 原生（非流式 / 先攒后发流式）----

func newGoneMessagesHandler(e *goneEnv, cfg *config.Config) *MessagesHandler {
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-native", ModelName: "claude-opus-5", ProviderID: "provider-native",
		ProviderType: "openai", ProviderBaseURL: "https://boflow.example",
		UpstreamModelID: "kiro-opus", Status: "active",
	}}
	h := NewMessagesHandler(cfg, resolver, &MockRateLimitChecker{}, e.sec, e.writer,
		fixedAdapterFactory{caller: &MockProviderCaller{}}, e.client, nil)
	h.SetRelayMetrics(e.metrics)
	return h
}

func goneMessagesRequest(ctx context.Context, stream bool) *http.Request {
	body := messagesKeepaliveBody0
	if stream {
		body = messagesKeepaliveBody
	}
	req := httptest.NewRequest(http.MethodPost, messagesKeepalivePath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(setAuthInfo(ctx, "tenant-123", "project-123", "user-123", "key-123", "session-123"))
}

func TestMessagesNativeNonStreamOutputScanClientGone(t *testing.T) {
	runGoneMatrix(t, "output", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		h := newGoneMessagesHandler(e, &config.Config{})
		res := serveGone(h.Handler(), goneMessagesRequest(e.ctx, false))
		e.check(t, res, controlForNative(cfg, "security_output_check_failed"))
	})
}

func TestMessagesNativeBufferedStreamOutputScanClientGone(t *testing.T) {
	runGoneMatrix(t, "output", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		h := newGoneMessagesHandler(e, &config.Config{UpstreamStreaming: false})
		res := serveGone(h.Handler(), goneMessagesRequest(e.ctx, true))
		e.check(t, res, controlForNative(cfg, "security_output_check_failed"))
	})
}

func TestMessagesNativeKeepaliveCommittedOutputScanClientGone(t *testing.T) {
	runGoneMatrix(t, "output", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		h := NewMessagesHandler(&config.Config{StreamKeepaliveInterval: 20 * time.Millisecond},
			&MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
				ID: "model-native", ModelName: "claude-opus-5", ProviderID: "provider-native",
				ProviderType: "openai", ProviderBaseURL: "https://boflow.example",
				UpstreamModelID: "kiro-opus", Status: "active",
			}}, &MockRateLimitChecker{}, e.sec, e.writer,
			fixedAdapterFactory{caller: &delayedProviderCaller{delay: 60 * time.Millisecond}}, e.client, nil)
		h.SetRelayMetrics(e.metrics)
		w := newFlushRecorder()
		h.Handler().ServeHTTP(w, goneMessagesRequest(e.ctx, true))
		e.check(t, goneResult{httpCode: w.code(), body: w.body()}, controlForNative(cfg, "security_output_check_failed"))
	})
}

func TestMessagesNativeInputScanClientGone(t *testing.T) {
	runGoneMatrix(t, "input", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		h := newGoneMessagesHandler(e, &config.Config{})
		res := serveGone(h.Handler(), goneMessagesRequest(e.ctx, false))
		e.check(t, res, controlFor(cfg, "security_check_failed"))
	})
}

// ---- responses（兼容转换路径 + 原生路径）----

func newGoneResponsesHandler(e *goneEnv, cfg *config.Config, native bool, caller ProviderCaller) *ResponsesHandler {
	var resolver *MockModelResolver
	if native {
		resolver = &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
			ID: "model-native", ProviderID: "provider-native", ModelName: "gpt-5.6-sol",
			UpstreamModelID: "gpt-5.6", ProviderType: "openai",
			ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true,
		}}
	} else {
		resolver = &MockModelResolver{}
	}
	h := NewResponsesHandler(cfg, resolver, &MockRateLimitChecker{}, e.sec, e.writer,
		fixedAdapterFactory{caller: caller}, e.client, nil)
	h.SetRelayMetrics(e.metrics)
	return h
}

func goneResponsesRequest(ctx context.Context, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, responsesKeepalivePath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(setAuthInfo(ctx, "tenant-123", "project-123", "user-123", "key-123", "session-123"))
}

// Responses 兼容转换路径（上游不是原生 Responses）：非流式与流式。
func TestResponsesCompatOutputScanClientGone(t *testing.T) {
	for _, stream := range []bool{false, true} {
		body := compatKeepalivePlainBody
		name := "non_stream"
		if stream {
			body, name = compatKeepaliveStreamBody, "stream"
		}
		t.Run(name, func(t *testing.T) {
			runGoneMatrix(t, "output", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
				h := newGoneResponsesHandler(e, &config.Config{}, false, &MockProviderCaller{})
				res := serveGone(h.Handler(), goneResponsesRequest(e.ctx, body))
				e.check(t, res, controlFor(cfg, "security_output_check_failed"))
			})
		})
	}
}

// Responses 原生路径（chat_completions.go 里 responses native 之外的 responses_native.go）。
func TestResponsesNativeOutputScanClientGone(t *testing.T) {
	for _, stream := range []bool{false, true} {
		body, response, name := responsesKeepalivePlainBody, nativeResponsesJSON, "non_stream"
		if stream {
			body, response, name = responsesKeepaliveStreamBody, nativeResponsesSSE, "stream"
		}
		t.Run(name, func(t *testing.T) {
			runGoneMatrix(t, "output", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
				caller := &MockProviderCaller{CallResponse: []byte(response)}
				h := newGoneResponsesHandler(e, &config.Config{}, true, caller)
				res := serveGone(h.Handler(), goneResponsesRequest(e.ctx, body))
				e.check(t, res, controlForNative(cfg, "security_output_check_failed"))
			})
		})
	}
}

// ---- 其他走输入扫描的端点：embeddings / images / files ----

func TestEmbeddingsInputScanClientGone(t *testing.T) {
	runGoneMatrix(t, "input", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		h := NewEmbeddingsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, e.sec, e.writer, &MockProviderAdapterFactory{})
		h.SetRuntimeConfigClient(e.client)
		body, _ := json.Marshal(EmbeddingsRequest{Model: "text-embedding-ada-002", Input: "Hello world"})
		req := httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(setAuthInfo(e.ctx, "tenant-123", "project-123", "user-123", "key-123", ""))
		res := serveGone(h.Handler(), req)
		e.check(t, res, controlFor(cfg, "security_check_failed"))
	})
}

func TestImagesInputScanClientGone(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	runGoneMatrix(t, "input", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		h := NewImagesHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, e.sec, e.writer,
			&MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallResponse: []byte(testImageResponse)}}, e.client)
		req := httptest.NewRequest(http.MethodPost, "/v1/images/generations",
			strings.NewReader(`{"model":"gpt-image-2","prompt":"draw a red bridge","n":1}`))
		req = req.WithContext(setAuthInfo(e.ctx, "tenant-a", "project-a", "user-a", "key-a", ""))
		res := serveGone(h.Handler(), req)
		e.check(t, res, controlFor(cfg, "security_check_failed"))
	})
}

// 文件上传输入检测失败原本就是「记录并继续上传」（没有任何配置会把它变成拦截）。
// 客户端断开后不该再写 security_check_failed，也不该继续把文件转发给上游。
func TestFileUploadInputScanClientGone(t *testing.T) {
	runGoneMatrix(t, "input", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		caller := &fileUploadCallerStub{body: []byte(`{"id":"file_upstream","object":"file"}`)}
		resolver := &fileUploadRouteResolverStub{
			MockModelResolver: &MockModelResolver{ProviderAPIKey: "provider-secret"},
			route: &modelrouter.ModelRecord{
				ID: "model-file", ProviderID: "provider-file", ProviderType: "openai", ProviderBaseURL: "https://provider.example/v1",
				ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, Files: true},
			},
		}
		h := NewFileUploadHandler(&config.Config{}, resolver, e.sec, e.writer, &fileUploadFactoryStub{caller: caller}, e.client)
		req := newFileUploadRequest(t, []byte("%PDF-safe-sample")).WithContext(
			setAuthInfo(e.ctx, "tenant-file", "project-file", "user-file", "key-file", ""))
		res := serveGone(h.Handler(), req)
		if e.scenario.gone {
			if caller.calls != 0 {
				t.Errorf("客户端已断开，文件不应再转发给上游，got %d 次", caller.calls)
			}
			e.check(t, res, goneExpect{})
			return
		}
		// 对照组：检测失败仍然「记录并继续上传」，且不受 fail-closed 影响（原行为）。
		e.check(t, res, goneExpect{status: "completed", code: http.StatusOK, events: []string{"security_check_failed"}})
		if caller.calls != 1 {
			t.Errorf("对照组检测失败应继续上传一次，got %d", caller.calls)
		}
	})
}

// 单元级：applyOutputSecurity / secureOutputToolArguments / applyInputSecurity 直接返回哨兵错误，
// 且不写 check_failed 事件、不设置 output_scan_incomplete。
func TestApplyOutputSecurityClientGoneReturnsSentinel(t *testing.T) {
	runGoneMatrix(t, "output", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		audit := &MockAuditWriter{}
		h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: e.client, securityClient: e.sec, auditWriter: audit}
		resp := mustMarshalChatResponse(t, ChatCompletionResponse{ID: "chatcmpl-gone", Object: "chat.completion", Model: "gpt-4",
			Choices: []Choice{{Index: 0, Message: ChoiceMessage{Role: "assistant", Content: "text"}}}})
		_, result, err := h.applyOutputSecurity(e.ctx, newFailModeEnvelope(), nil, resp)
		assertSecurityStageOutcome(t, e, cfg, audit, result, err, "security_output_check_failed")
	})
}

func TestSecureOutputToolArgumentsClientGoneReturnsSentinel(t *testing.T) {
	runGoneMatrix(t, "output", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		audit := &MockAuditWriter{}
		h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: e.client, securityClient: e.sec, auditWriter: audit}
		tool := ToolCall{ID: "call_1", Type: "function", Function: ToolCallFunc{Name: "f", Arguments: `{"a":1}`}}
		result := &AuditResult{}
		_, err := h.secureOutputToolArguments(e.ctx, newFailModeEnvelope(), tool, 0, result)
		assertSecurityStageOutcome(t, e, cfg, audit, result, err, "security_output_check_failed")
	})
}

func TestApplyInputSecurityClientGoneReturnsSentinel(t *testing.T) {
	runGoneMatrix(t, "input", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		audit := &MockAuditWriter{}
		h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: e.client, securityClient: e.sec, auditWriter: audit}
		req := &ChatCompletionRequest{Model: "glm-5", Messages: []Message{{Role: "user", Content: jsonQuote("hello")}}}
		_, err := h.applyInputSecurity(e.ctx, newFailModeEnvelope(), req)
		assertSecurityStageOutcome(t, e, cfg, audit, nil, err, "security_check_failed")
	})
}

func assertSecurityStageOutcome(t *testing.T, e *goneEnv, cfg goneConfig, audit *MockAuditWriter, result *AuditResult, err error, failedEvent string) {
	t.Helper()
	if e.scenario.gone {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("客户端断开应返回包装 context.Canceled 的错误, got %v", err)
		}
		if isGuardrailDetectionUnavailable(err) {
			t.Errorf("客户端断开不应是 fail-closed 拒绝: %v", err)
		}
		if hasSecurityEvent(audit, failedEvent) || hasSecurityEvent(audit, "output_scan_incomplete") {
			t.Errorf("客户端断开不应写检测失败事件: %#v", audit.SecurityEventWrites)
		}
		if result != nil && result.ResponseMetadata != nil && result.ResponseMetadata["output_scan_incomplete"] == true {
			t.Errorf("客户端断开不应标记 output_scan_incomplete: %#v", result.ResponseMetadata)
		}
		return
	}
	// 对照组：检测失败仍写事件；只有 protect + fail-closed 才拒绝（503 语义）。
	if !hasSecurityEvent(audit, failedEvent) {
		t.Errorf("对照组应写 %s: %#v", failedEvent, audit.SecurityEventWrites)
	}
	wantReject := cfg.failClosed && !cfg.auditOnly
	if got := isGuardrailDetectionUnavailable(err); got != wantReject {
		t.Errorf("对照组 fail-closed 拒绝=%v, want %v (err=%v)", got, wantReject, err)
	}
	if !wantReject && err != nil {
		t.Errorf("对照组放行场景不应返回错误: %v", err)
	}
}
