package handler

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 扫描期间断开，收尾会把上游响应（或只含 usage 的载体）交给 FinalizeRequestLog 解析 usage。
// 硬约束：这份正文只用于解析 usage，不得写给客户端，不得写内容日志（content_logs），不得落库。
// 上游回答文本用一个独特的标记，测试在客户端响应、assistant 内容日志、所有落库 SQL 参数里搜它。
//
// 覆盖本次新传 respBody 的全部协议：chat 非流式、chat 先攒后发、responses 兼容、messages 原生
// （非流式 + 流式）、responses 原生。每条协议都带一个「断开分支多写一次内容日志」的变异验证（见任务汇报）。

const billingGoneSecretText = "UPSTREAM-ANSWER-MUST-NOT-LEAK"

// 上游响应：usage 为 1800/300，回答文本是独特标记。

func billingGoneLeakChatResponse() []byte {
	return []byte(`{"id":"chatcmpl-leak","object":"chat.completion","created":1716399600,"model":"gpt-4",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"` + billingGoneSecretText + `"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":1800,"completion_tokens":300,"total_tokens":2100}}`)
}

func billingGoneLeakMessagesResponse() []byte {
	return []byte(`{"id":"msg_leak","type":"message","role":"assistant","model":"claude-opus-5",` +
		`"content":[{"type":"text","text":"` + billingGoneSecretText + `"}],"stop_reason":"end_turn","stop_sequence":null,` +
		`"usage":{"input_tokens":1800,"output_tokens":300}}`)
}

func billingGoneLeakMessagesSSE() []byte {
	return []byte("event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_leak\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":1800,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + billingGoneSecretText + "\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":300}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
}

func billingGoneLeakResponsesResponse() string {
	return `{"id":"resp_leak","object":"response","status":"completed","model":"gpt-5.6",` +
		`"output":[{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"` + billingGoneSecretText + `","annotations":[]}]}],` +
		`"usage":{"input_tokens":1800,"output_tokens":300,"total_tokens":2100}}`
}

func argsContain(db *goneDB, needle string) []string {
	db.mu.Lock()
	defer db.mu.Unlock()
	var hits []string
	for _, exec := range db.execs {
		for i, arg := range exec.args {
			var text string
			switch v := arg.(type) {
			case string:
				text = v
			case []byte:
				text = string(v)
			default:
				text = fmt.Sprint(v)
			}
			if strings.Contains(text, needle) {
				hits = append(hits, fmt.Sprintf("arg[%d] of %.60s", i, strings.Join(strings.Fields(exec.query), " ")))
			}
		}
	}
	return hits
}

// teeAuditWriter 把内容日志写入同时记到 content（MockAuditWriter），其余全部转给真实写入器。
type teeAuditWriter struct {
	AuditWriter
	content *MockAuditWriter
}

func (w *teeAuditWriter) WriteContentLog(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, c string, tokens int) {
	w.content.WriteContentLog(ctx, envelope, role, c, tokens)
	w.AuditWriter.WriteContentLog(ctx, envelope, role, c, tokens)
}

func (w *teeAuditWriter) WriteContentLogAnchored(ctx context.Context, envelope *modelrouter.RequestEnvelope, role, c string, tokens, messageIndex int) {
	w.content.WriteContentLogAnchored(ctx, envelope, role, c, tokens, messageIndex)
	if anchored, ok := w.AuditWriter.(AnchoredContentLogWriter); ok {
		anchored.WriteContentLogAnchored(ctx, envelope, role, c, tokens, messageIndex)
		return
	}
	w.AuditWriter.WriteContentLog(ctx, envelope, role, c, tokens)
}

// leakCase 是一条协议的跑法：用 tee 写入器（同时观察内容日志）发一次会在输出扫描期间断开的请求，返回客户端响应。
type leakCase struct {
	name string
	run  func(t *testing.T, e *billingGoneEnv, writer AuditWriter) goneResult
	// control 是该协议在对照语义下的预期（断开场景用 controlFor / controlForNative 的哪一个）。
	native bool
}

func leakCases() []leakCase {
	messagesHandler := func(e *billingGoneEnv, writer AuditWriter, upstream []byte) *MessagesHandler {
		resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
			ID: "model-native", ModelName: "claude-opus-5", ProviderID: "provider-native",
			ProviderType: "openai", ProviderBaseURL: "https://boflow.example", UpstreamModelID: "kiro-opus", Status: "active",
		}}
		h := NewMessagesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, e.sec, writer,
			fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: upstream}}, e.client, nil)
		h.SetRelayMetrics(e.metrics)
		h.SetBillingPreflight(e.billing)
		return h
	}
	return []leakCase{
		{name: "chat_non_stream", run: func(t *testing.T, e *billingGoneEnv, writer AuditWriter) goneResult {
			h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, e.sec, writer,
				fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: billingGoneLeakChatResponse()}}, e.client, nil)
			h.SetRelayMetrics(e.metrics)
			h.SetBillingPreflight(e.billing)
			return serveGone(h.Handler(), billingGoneChatRequest(e.ctx, false))
		}},
		{name: "chat_buffered_stream", run: func(t *testing.T, e *billingGoneEnv, writer AuditWriter) goneResult {
			h := NewChatCompletionsHandler(&config.Config{UpstreamStreaming: false}, &MockModelResolver{}, &MockRateLimitChecker{}, e.sec, writer,
				fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: billingGoneLeakChatResponse()}}, e.client, nil)
			h.SetRelayMetrics(e.metrics)
			h.SetBillingPreflight(e.billing)
			return serveGone(h.Handler(), billingGoneChatRequest(e.ctx, true))
		}},
		{name: "responses_compat", run: func(t *testing.T, e *billingGoneEnv, writer AuditWriter) goneResult {
			h := NewResponsesHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, e.sec, writer,
				fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: billingGoneLeakChatResponse()}}, e.client, nil)
			h.SetRelayMetrics(e.metrics)
			h.SetBillingPreflight(e.billing)
			return serveGone(h.Handler(), goneResponsesRequest(e.ctx, `{"model":"gpt-5.5","input":"Hello","stream":false,"max_output_tokens":32000}`))
		}},
		{name: "messages_native_non_stream", native: true, run: func(t *testing.T, e *billingGoneEnv, writer AuditWriter) goneResult {
			h := messagesHandler(e, writer, billingGoneLeakMessagesResponse())
			return serveGone(h.Handler(), goneMessagesRequestWithMax(e.ctx, false, 32000))
		}},
		{name: "messages_native_stream", native: true, run: func(t *testing.T, e *billingGoneEnv, writer AuditWriter) goneResult {
			h := messagesHandler(e, writer, billingGoneLeakMessagesSSE())
			return serveGone(h.Handler(), goneMessagesRequestWithMax(e.ctx, true, 32000))
		}},
		{name: "responses_native", native: true, run: func(t *testing.T, e *billingGoneEnv, writer AuditWriter) goneResult {
			resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
				ID: "model-native", ProviderID: "provider-native", ModelName: "gpt-5.6-sol",
				UpstreamModelID: "gpt-5.6", ProviderType: "openai",
				ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true,
			}}
			h := NewResponsesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, e.sec, writer,
				fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: []byte(billingGoneLeakResponsesResponse())}}, e.client, nil)
			h.SetRelayMetrics(e.metrics)
			h.SetBillingPreflight(e.billing)
			return serveGone(h.Handler(), goneResponsesRequest(e.ctx, `{"model":"gpt-5.6-sol","input":"inspect","stream":false,"max_output_tokens":32000}`))
		}},
	}
}

func TestClientGoneFinalizeDoesNotLeakUpstreamBody(t *testing.T) {
	for _, lc := range leakCases() {
		t.Run(lc.name, func(t *testing.T) {
			for _, sc := range goneScenarios[:2] { // client_gone / client_gone_wrapped
				for _, cfg := range goneConfigs {
					t.Run(sc.name+"/"+cfg.name, func(t *testing.T) {
						e := newBillingGoneEnv(t, sc, cfg)
						observed := &MockAuditWriter{}
						writer := &teeAuditWriter{AuditWriter: e.audit, content: observed}

						res := lc.run(t, e, writer)

						control := controlFor(cfg, "security_output_check_failed")
						if lc.native {
							control = controlForNative(cfg, "security_output_check_failed")
						}
						e.check(t, res, control)
						if strings.Contains(res.body, billingGoneSecretText) {
							t.Errorf("上游回答正文不得写给已断开的客户端: %q", res.body)
						}
						// 输入侧在调上游之前就写了请求消息的内容日志（既有行为，与本任务无关）；
						// 这里只钉住上游回答不得进内容日志：不能有 assistant 角色的内容日志，也不能含上游回答文本。
						for _, row := range observed.ContentLogWrites {
							if row.Role == "assistant" || strings.Contains(row.Content, billingGoneSecretText) {
								t.Errorf("断开收尾不得把上游回答写进内容日志: role=%s content=%q", row.Role, row.Content)
							}
						}
						if hits := argsContain(e.db, billingGoneSecretText); len(hits) != 0 {
							t.Errorf("上游回答正文不得落库: %v", hits)
						}
						e.assertBilling(t, cfg)
					})
				}
			}
		})
	}
}
