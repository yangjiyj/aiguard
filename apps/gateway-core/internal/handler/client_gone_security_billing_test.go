package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 扫描期间客户端断开的计费口径：上游响应已完整拿到（含 usage），客户端是在输出扫描时才断开的。
// 收尾状态是 client_canceled，但结算必须按上游真实 usage 走，口径与改前 success 路径一致；
// 不能因为收尾正文传 nil 而退回 estimated_incomplete，按预占的 max_tokens 多收。

const (
	billingGonePromptTokens     = 1800
	billingGoneCompletionTokens = 300
)

// 上游响应：usage 为 prompt=1800 / completion=300，远小于下面预占的 2000 / 32000。
func billingGoneChatResponse() []byte {
	return []byte(`{"id":"chatcmpl-bill","object":"chat.completion","created":1716399600,"model":"gpt-4",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"Hello! How can I help?"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":1800,"completion_tokens":300,"total_tokens":2100}}`)
}

func billingGoneMessagesResponse() []byte {
	return []byte(`{"id":"msg_bill","type":"message","role":"assistant","model":"claude-opus-5",` +
		`"content":[{"type":"text","text":"Hello! How can I help?"}],"stop_reason":"end_turn","stop_sequence":null,` +
		`"usage":{"input_tokens":1800,"output_tokens":300}}`)
}

// billingGoneMessagesSSE 是流式请求下上游返回的完整 Anthropic SSE（CallStreaming 的累积结果），usage 同为 1800/300。
func billingGoneMessagesSSE() []byte {
	return []byte("event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_bill\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":1800,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello! How can I help?\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":300}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
}

func billingGoneResponsesResponse() string {
	return `{"id":"resp_native","object":"response","status":"completed","model":"gpt-5.6",` +
		`"output":[{"id":"msg_1","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"native-ok","annotations":[]}]}],` +
		`"usage":{"input_tokens":1800,"output_tokens":300,"total_tokens":2100}}`
}

// billingGoneControlPlane 记录控制面收到的结算：路径与 usage。
type billingGoneControlPlane struct {
	mu          sync.Mutex
	settlements []billingGoneSettlement
	releases    int
	server      *httptest.Server
}

type billingGoneSettlement struct {
	path      string
	promptTok int64
	outputTok int64
	estimated bool
}

func newBillingGoneControlPlane(t *testing.T) *billingGoneControlPlane {
	t.Helper()
	cp := &billingGoneControlPlane{}
	cp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/reservations", "/internal/v1/billing/quotes":
			_, _ = w.Write([]byte(`{"reserved":true,"price_id":"test-price","admitted_at":"2026-10-03T01:00:00Z"}`))
		case "/internal/v1/billing/settlements", "/internal/v1/billing/measurements":
			var payload struct {
				Usage     map[string]int64 `json:"usage"`
				Estimated bool             `json:"estimated"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("settlement payload: %v", err)
			}
			cp.mu.Lock()
			cp.settlements = append(cp.settlements, billingGoneSettlement{
				path: r.URL.Path, promptTok: payload.Usage["prompt_tokens"], outputTok: payload.Usage["output_tokens"], estimated: payload.Estimated,
			})
			cp.mu.Unlock()
			_, _ = w.Write([]byte(`{"amount_micros":10}`))
		case "/internal/v1/billing/releases":
			cp.mu.Lock()
			cp.releases++
			cp.mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(cp.server.Close)
	return cp
}

func (cp *billingGoneControlPlane) last(t *testing.T) billingGoneSettlement {
	t.Helper()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.settlements) == 0 {
		t.Fatalf("控制面没有收到结算 (releases=%d)", cp.releases)
	}
	return cp.settlements[len(cp.settlements)-1]
}

// billingGoneEnv 在 goneEnv 之上换成真实 BillingAuditWriter：先在控制面预占 prompt=2000 / max_tokens=32000，
// 收尾时读到的 usage 才是结算依据。
type billingGoneEnv struct {
	*goneEnv
	cp      *billingGoneControlPlane
	billing *BillingClient
	audit   AuditWriter
}

func newBillingGoneEnv(t *testing.T, sc goneScenario, cfg goneConfig) *billingGoneEnv {
	t.Helper()
	env := newGoneEnv(t, sc, cfg, "output")
	cp := newBillingGoneControlPlane(t)
	client := NewBillingClient(cp.server.URL, "internal-secret", "default")
	return &billingGoneEnv{goneEnv: env, cp: cp, billing: client, audit: NewBillingAuditWriter(env.writer, client)}
}

// 预占的 token 数：远大于上游真实 usage，用来区分「按真实 usage 结算」与「按预占估算结算」。
func billingGoneReserve(t *testing.T, e *billingGoneEnv, envelope *modelrouter.RequestEnvelope) {
	t.Helper()
	if err := e.billing.ReserveUsage(context.Background(), envelope, BillingUsage{PromptTokens: 2000, OutputTokens: 32000}); err != nil {
		t.Fatal(err)
	}
}

func (e *billingGoneEnv) checkSettlement(t *testing.T) {
	t.Helper()
	got := e.cp.last(t)
	if got.promptTok != billingGonePromptTokens || got.outputTok != billingGoneCompletionTokens {
		t.Errorf("结算 usage=%d/%d, want 上游真实 usage %d/%d（不是预占估算 2000/32000）estimated=%v path=%s",
			got.promptTok, got.outputTok, billingGonePromptTokens, billingGoneCompletionTokens, got.estimated, got.path)
	}
	if got.estimated {
		t.Errorf("结算被标成估算 (estimated=true)，应使用上游真实 usage")
	}
}

// 让 RequestEnvelope 在收尾前就带上预占：真实请求里预占发生在输入检测之后、调上游之前，
// 这里用 handler 的 SetBillingPreflight 走真实路径，不手工塞状态。
func billingGoneChatHandler(e *billingGoneEnv, cfg *config.Config) *ChatCompletionsHandler {
	h := NewChatCompletionsHandler(cfg, &MockModelResolver{}, &MockRateLimitChecker{}, e.sec, e.audit,
		fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: billingGoneChatResponse()}}, e.client, nil)
	h.SetRelayMetrics(e.metrics)
	h.SetBillingPreflight(e.billing)
	return h
}

func billingGoneChatRequest(ctx context.Context, stream bool) *http.Request {
	body, _ := json.Marshal(ChatCompletionRequest{
		Model:     "gpt-4",
		Messages:  []Message{{Role: "user", Content: jsonQuote("Hello")}},
		Stream:    stream,
		MaxTokens: 32000,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(setAuthInfo(ctx, "tenant-123", "project-123", "user-123", "key-123", ""))
}

// 核对结算口径。客户端断开：按上游真实 usage 结算（client_canceled 属结算状态族）。
// 对照组（真检测失败）：放行的配置本来就是 success 带真实 usage，同样核对，保证改动前后一致；
// protect + fail-closed 的对照组原本是 security_blocked/503，状态不在结算族，由控制面释放预占，不核对结算。
func (e *billingGoneEnv) assertBilling(t *testing.T, cfg goneConfig) {
	t.Helper()
	if !e.scenario.gone && cfg.failClosed && !cfg.auditOnly {
		return
	}
	e.checkSettlement(t)
}

func TestBillingChatNonStreamOutputScanClientGone(t *testing.T) {
	runBillingGoneMatrix(t, func(t *testing.T, e *billingGoneEnv, cfg goneConfig) {
		h := billingGoneChatHandler(e, &config.Config{})
		res := serveGone(h.Handler(), billingGoneChatRequest(e.ctx, false))
		e.check(t, res, controlFor(cfg, "security_output_check_failed"))
		e.assertBilling(t, cfg)
	})
}

func TestBillingChatBufferedStreamOutputScanClientGone(t *testing.T) {
	runBillingGoneMatrix(t, func(t *testing.T, e *billingGoneEnv, cfg goneConfig) {
		h := billingGoneChatHandler(e, &config.Config{UpstreamStreaming: false})
		res := serveGone(h.Handler(), billingGoneChatRequest(e.ctx, true))
		e.check(t, res, controlFor(cfg, "security_output_check_failed"))
		e.assertBilling(t, cfg)
	})
}

func TestBillingResponsesCompatOutputScanClientGone(t *testing.T) {
	runBillingGoneMatrix(t, func(t *testing.T, e *billingGoneEnv, cfg goneConfig) {
		h := NewResponsesHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, e.sec, e.audit,
			fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: billingGoneChatResponse()}}, e.client, nil)
		h.SetRelayMetrics(e.metrics)
		h.SetBillingPreflight(e.billing)
		res := serveGone(h.Handler(), goneResponsesRequest(e.ctx, `{"model":"gpt-5.5","input":"Hello","stream":false,"max_output_tokens":32000}`))
		e.check(t, res, controlFor(cfg, "security_output_check_failed"))
		e.assertBilling(t, cfg)
	})
}

func TestBillingMessagesNativeOutputScanClientGone(t *testing.T) {
	for _, stream := range []bool{false, true} {
		name := "non_stream"
		if stream {
			name = "stream"
		}
		t.Run(name, func(t *testing.T) {
			runBillingGoneMatrix(t, func(t *testing.T, e *billingGoneEnv, cfg goneConfig) {
				resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
					ID: "model-native", ModelName: "claude-opus-5", ProviderID: "provider-native",
					ProviderType: "openai", ProviderBaseURL: "https://boflow.example",
					UpstreamModelID: "kiro-opus", Status: "active",
				}}
				upstream := billingGoneMessagesResponse()
				if stream {
					upstream = billingGoneMessagesSSE()
				}
				h := NewMessagesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, e.sec, e.audit,
					fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: upstream}}, e.client, nil)
				h.SetRelayMetrics(e.metrics)
				h.SetBillingPreflight(e.billing)
				res := serveGone(h.Handler(), goneMessagesRequestWithMax(e.ctx, stream, 32000))
				e.check(t, res, controlForNative(cfg, "security_output_check_failed"))
				e.assertBilling(t, cfg)
			})
		})
	}
}

func TestBillingResponsesNativeOutputScanClientGone(t *testing.T) {
	runBillingGoneMatrix(t, func(t *testing.T, e *billingGoneEnv, cfg goneConfig) {
		resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
			ID: "model-native", ProviderID: "provider-native", ModelName: "gpt-5.6-sol",
			UpstreamModelID: "gpt-5.6", ProviderType: "openai",
			ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true,
		}}
		h := NewResponsesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, e.sec, e.audit,
			fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: []byte(billingGoneResponsesResponse())}}, e.client, nil)
		h.SetRelayMetrics(e.metrics)
		h.SetBillingPreflight(e.billing)
		res := serveGone(h.Handler(), goneResponsesRequest(e.ctx, `{"model":"gpt-5.6-sol","input":"inspect","stream":false,"max_output_tokens":32000}`))
		e.check(t, res, controlForNative(cfg, "security_output_check_failed"))
		e.assertBilling(t, cfg)
	})
}

func goneMessagesRequestWithMax(ctx context.Context, stream bool, maxTokens int) *http.Request {
	body := `{"model":"claude-opus-5","max_tokens":` + itoa(maxTokens) + `,"stream":` + boolString(stream) + `,"messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, messagesKeepalivePath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(setAuthInfo(ctx, "tenant-123", "project-123", "user-123", "key-123", "session-123"))
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func runBillingGoneMatrix(t *testing.T, fn func(t *testing.T, e *billingGoneEnv, cfg goneConfig)) {
	t.Helper()
	for _, sc := range goneScenarios {
		for _, cfg := range goneConfigs {
			t.Run(sc.name+"/"+cfg.name, func(t *testing.T) {
				e := newBillingGoneEnv(t, sc, cfg)
				fn(t, e, cfg)
			})
		}
	}
}
