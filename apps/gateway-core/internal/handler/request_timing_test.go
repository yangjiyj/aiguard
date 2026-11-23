package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// 走真实审计序列化但使用内存执行器，不建立数据库连接。
func assertRequestTimingPersisted(t *testing.T, envelope *modelrouter.RequestEnvelope, audit *AuditResult, keys ...string) {
	t.Helper()
	db := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	(&RealAuditWriter{db: db}).FinalizeRequestLog(context.Background(), envelope, nil, "success", 200, 100, audit)
	for _, arg := range db.args[0] {
		raw, ok := arg.([]byte)
		if !ok {
			continue
		}
		var result struct {
			Metadata struct {
				Timing map[string]int64 `json:"timing"`
			} `json:"response_metadata"`
		}
		if json.Unmarshal(raw, &result) != nil || result.Metadata.Timing == nil {
			continue
		}
		for _, key := range keys {
			if _, exists := result.Metadata.Timing[key]; !exists {
				t.Fatalf("审计缺少 %s: %s", key, raw)
			}
		}
		return
	}
	t.Fatal("未持久化分段计时")
}

func TestRequestTimingNonStreamingMainPaths(t *testing.T) {
	for _, endpoint := range []string{"chat", "messages", "responses"} {
		t.Run(endpoint, func(t *testing.T) {
			caller := &MockProviderCaller{}
			security := &MockSecurityChecker{}
			audit := &MockAuditWriter{}
			var handler http.Handler
			var request *http.Request
			switch endpoint {
			case "chat":
				caller.CallResponse = []byte(`{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
				resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{ID: "model", ProviderID: "provider", ModelName: "test", ProviderType: "openai", Status: "active"}}
				handler = NewChatCompletionsHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, security, audit, &MockProviderAdapterFactory{MockProviderCaller: caller}, nil, nil).Handler()
				request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test","messages":[{"role":"user","content":"hi"}]}`))
				request = request.WithContext(setAuthInfo(request.Context(), "tenant", "project", "user", "key", "session"))
			case "messages":
				caller.CallResponse = []byte(`{"id":"x","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`)
				handler = nativeMessagesTestHandler(caller, security, audit).Handler()
				request = httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`))
				request = request.WithContext(setAuthInfo(request.Context(), "tenant", "project", "user", "key", "session"))
			case "responses":
				caller.CallResponse = []byte(`{"id":"x","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1}}`)
				handler = newNativeResponsesTestHandler(caller, security, audit, true).Handler()
				request = nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"hi"}`))
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, request)
			if w.Code != 200 || len(audit.RequestLogFinalizes) != 1 {
				t.Fatalf("请求失败: status=%d body=%s", w.Code, w.Body.String())
			}
			final := audit.RequestLogFinalizes[0]
			assertRequestTimingPersisted(t, final.Envelope, final.AuditResult, "input_security_ms", "output_security_ms", "pre_upstream_ms")
			if _, exists := final.Envelope.Timing["generation_ms"]; exists {
				t.Fatal("没有首事件时不应推测生成耗时")
			}
		})
	}
}

func TestRequestTimingAccumulatesAndPreservesAudit(t *testing.T) {
	envelope := &modelrouter.RequestEnvelope{RequestStartedAt: time.Now().Add(-time.Second)}
	metrics := relay.NewMetrics()
	recordSecurityTiming(envelope, metrics, "output_security_ms", 600*time.Microsecond)
	recordSecurityTiming(envelope, metrics, "output_security_ms", 600*time.Microsecond)
	audit := &AuditResult{OutputAction: "mask", OutputFindings: []map[string]interface{}{{"type": "existing"}}, ResponseMetadata: map[string]interface{}{"retained": true}}
	result := withRequestTiming(envelope, audit)
	if result.OutputAction != "mask" || result.ResponseMetadata["retained"] != true || len(result.OutputFindings) != 1 {
		t.Fatal("原审计字段被改动")
	}
	if result.ResponseMetadata["timing"].(map[string]int64)["output_security_ms"] != 1 {
		t.Fatal("累计必须先保留亚毫秒精度再取整")
	}
	if _, exists := result.ResponseMetadata["timing"].(map[string]int64)["input_security_ms"]; exists {
		t.Fatal("缺失计时不能补零")
	}
	ttft := int64(100)
	envelope.UpstreamTTFTMs = &ttft
	start := time.Now()
	recordGenerationTiming(envelope, start, start.Add(350*time.Millisecond))
	recordGenerationTiming(envelope, start, start.Add(time.Second))
	if withRequestTiming(envelope, audit).ResponseMetadata["timing"].(map[string]int64)["generation_ms"] != 250 {
		t.Fatal("生成耗时应在结束点冻结")
	}
	assertRequestTimingPersisted(t, envelope, audit, "output_security_ms", "generation_ms")
}

func TestRequestTimingStreamingMainPaths(t *testing.T) {
	for _, endpoint := range []string{"chat", "messages", "responses"} {
		t.Run(endpoint, func(t *testing.T) {
			ttft := int64(0)
			envelope := &modelrouter.RequestEnvelope{RequestID: "timing-stream", Model: "test", RequestStartedAt: time.Now(), UpstreamTTFTMs: &ttft}
			caller := &timingStreamCaller{liveRelayCaller: liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{
				{Type: relay.EventTextDelta, Delta: "hello"},
				{Type: relay.EventMessageEnd, FinishReason: "stop"},
			}}}}
			audit := &MockAuditWriter{}
			cfg := &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_audit"}
			security := &MockSecurityChecker{}
			recorder := httptest.NewRecorder()
			tracker := &relay.CommitTracker{}
			started := time.Now()
			var attempted bool
			var err error
			switch endpoint {
			case "chat":
				h := &ChatCompletionsHandler{cfg: cfg, securityClient: security, auditWriter: audit}
				attempted, err = h.tryLiveChatStream(context.Background(), recorder, envelope, caller, []byte("{}"), started, "", tracker)
			case "messages":
				h := &MessagesHandler{cfg: cfg, securityClient: security, auditWriter: audit}
				attempted, err = h.tryLiveNativeMessagesStream(context.Background(), recorder, envelope, caller, []byte("{}"), started, "", tracker, nil)
			case "responses":
				h := &ResponsesHandler{cfg: cfg, securityClient: security, auditWriter: audit}
				attempted, err = h.tryLiveNativeResponsesStream(context.Background(), recorder, envelope, caller, []byte("{}"), started, "", tracker, nil)
			}
			if err != nil || !attempted || len(audit.RequestLogFinalizes) != 1 {
				t.Fatalf("流式处理失败: attempted=%v err=%v body=%s", attempted, err, recorder.Body.String())
			}
			assertRequestTimingPersisted(t, envelope, audit.RequestLogFinalizes[0].AuditResult, "pre_upstream_ms", "output_security_ms", "generation_ms")
		})
	}
}

// 内存流在打开时提供与真实适配器相同的首事件观测，避免依赖监听端口。
type timingStreamCaller struct{ liveRelayCaller }

func (c *timingStreamCaller) OpenStream(_ context.Context, envelope *modelrouter.RequestEnvelope, _ []byte) (relay.StreamReader, provider.StreamResponseMeta, error) {
	ttft := int64(0)
	envelope.UpstreamTTFTMs = &ttft
	return c.reader, provider.StreamResponseMeta{StatusCode: 200}, nil
}

func TestRequestTimingRetryDoesNotReuseFirstEventOrGeneration(t *testing.T) {
	ttft := int64(10)
	started := time.Now()
	envelope := &modelrouter.RequestEnvelope{RequestStartedAt: started, UpstreamTTFTMs: &ttft, Timing: map[string]int64{"generation_ms": int64(time.Second), "input_security_ms": int64(2 * time.Millisecond)}}
	previous := envelope.Timing
	recordPreUpstreamTiming(envelope, started.Add(20*time.Millisecond))
	if envelope.UpstreamTTFTMs != nil {
		t.Fatal("重试不能沿用上一次首事件")
	}
	if _, exists := envelope.Timing["generation_ms"]; exists {
		t.Fatal("重试不能沿用上一次生成耗时")
	}
	if previous["generation_ms"] != int64(time.Second) {
		t.Fatal("复制路由的计时应独立")
	}
	recordGenerationTiming(envelope, started, started.Add(time.Second))
	if _, exists := envelope.Timing["generation_ms"]; exists {
		t.Fatal("重试尚无首事件时不能填写生成耗时")
	}
	recordPreUpstreamTiming(envelope, started.Add(100*time.Millisecond))
	if envelope.Timing["pre_upstream_ms"] != int64(20*time.Millisecond) {
		t.Fatal("前置处理应保持首次发送口径")
	}
}
