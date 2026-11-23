package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// anthropicBudgetUpstream 模拟原生 Anthropic 上游，记录收到的请求体。
// obey=true 时遵守 max_tokens：输出到上限即以 stop_reason=max_tokens 结束并给出权威 usage；
// obey=false 时无视上限持续输出（触发网关兜底）。
type anthropicBudgetUpstream struct {
	mu   sync.Mutex
	body []byte
	obey bool
}

func (u *anthropicBudgetUpstream) received() map[string]any {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out map[string]any
	_ = json.Unmarshal(u.body, &out)
	return out
}

func (u *anthropicBudgetUpstream) rawBody() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return string(u.body)
}

func (u *anthropicBudgetUpstream) server(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.body = raw
		u.mu.Unlock()
		var request struct {
			MaxTokens int `json:"max_tokens"`
		}
		_ = json.Unmarshal(raw, &request)
		chunks, stop, output := 200, "end_turn", 600
		if u.obey && request.MaxTokens < 600 {
			// 每个 chunk 3 token：上游自己停在上限。
			chunks, stop, output = request.MaxTokens/3, "max_tokens", request.MaxTokens
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-b\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-b\",\"content\":[],\"usage\":{\"input_tokens\":9,\"output_tokens\":0}}}\n\n")
		_, _ = io.WriteString(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
		for i := 0; i < chunks; i++ {
			_, _ = io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello world \"}}\n\n")
			flusher.Flush()
		}
		_, _ = io.WriteString(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
		_, _ = io.WriteString(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\""+stop+"\"},\"usage\":{\"output_tokens\":"+itoa64(int64(output))+"}}\n\n")
		_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		flusher.Flush()
	}))
	t.Cleanup(server.Close)
	return server
}

func runAnthropicBudgetStream(t *testing.T, cap *int64, upstream *anthropicBudgetUpstream, requestBody string) (string, *streamBudgetControlPlane, *MockAuditWriter) {
	t.Helper()
	server := upstream.server(t)
	cp := &streamBudgetControlPlane{cap: cap}
	client := NewBillingClientWithMode(cp.server(t).URL, "internal-secret", "", "metering")
	resolver := &MockModelResolver{
		ProviderAPIKey: "provider-key",
		ModelRecord: &modelrouter.ModelRecord{
			ID: "model-b", ProviderID: "provider-b", ModelName: "claude-b", UpstreamModelID: "claude-b",
			ProviderType: "anthropic", ProviderBaseURL: server.URL, Status: "active",
		},
	}
	inner := &MockAuditWriter{}
	handler := NewMessagesHandler(
		&config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_audit"},
		resolver, &MockRateLimitChecker{}, &streamRegressionSecurity{}, NewBillingAuditWriter(inner, client), &RealProviderAdapterFactory{}, nil, nil,
	)
	handler.SetBillingPreflight(client)
	request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(requestBody))
	request = request.WithContext(setAuthInfo(context.Background(), "tenant-b", "project-b", "user-b", "key-b", "session-b"))
	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, request)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	return w.Body.String(), cp, inner
}

const anthropicBudgetRequest = "{\"model\":\"claude-b\",\"max_tokens\":1000,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"long\"}]}"

// 主路径：预算断流开启时 max_tokens 收紧到上限，上游自己停在上限（stop_reason=max_tokens），
// 客户端收到上游原样的合法结束事件，按上游权威 usage 结算。
func TestNativeMessagesBudgetCapTightensMaxTokensAndSettlesUpstreamUsage(t *testing.T) {
	limit := int64(60)
	upstream := &anthropicBudgetUpstream{obey: true}
	body, cp, inner := runAnthropicBudgetStream(t, &limit, upstream, anthropicBudgetRequest)
	if got := upstream.received()["max_tokens"]; got != float64(60) {
		t.Fatalf("upstream max_tokens=%v want 60 (tightened, never raised)", got)
	}
	if !strings.Contains(body, `"stop_reason":"max_tokens"`) || !strings.HasSuffix(strings.TrimSpace(body), `data: {"type":"message_stop"}`) {
		t.Fatalf("client must receive the upstream max_tokens finish: %q", body[max(0, len(body)-400):])
	}
	usage, status, source := cp.settled()
	if usage["output_tokens"] != float64(60) || usage["prompt_tokens"] != float64(9) || source != "upstream" || status != "success" {
		t.Fatalf("settlement must equal the upstream usage: status=%v source=%v usage=%v", status, source, usage)
	}
	if inner.RequestLogFinalizes[0].AuditResult.ResponseMetadata["stream_budget_truncated"] != nil {
		t.Fatal("an upstream that obeyed the cap must not trip the fallback")
	}
}

// 用户自己给的 max_tokens 比上限小时不放大。
func TestNativeMessagesBudgetCapNeverRaisesClientMaxTokens(t *testing.T) {
	limit := int64(500)
	upstream := &anthropicBudgetUpstream{obey: true}
	_, _, _ = runAnthropicBudgetStream(t, &limit, upstream, strings.Replace(anthropicBudgetRequest, `"max_tokens":1000`, `"max_tokens":30`, 1))
	if got := upstream.received()["max_tokens"]; got != float64(30) {
		t.Fatalf("upstream max_tokens=%v want client value 30", got)
	}
}

// 兜底：上游无视 max_tokens 时网关停止转发、补 content_block_stop + stop_reason=max_tokens + message_stop，
// 并继续读到上游结束事件，按上游权威 usage 结算。
func TestNativeMessagesFallbackTruncatesAndSettlesUpstreamUsage(t *testing.T) {
	limit := int64(5)
	upstream := &anthropicBudgetUpstream{obey: false}
	body, cp, _ := runAnthropicBudgetStream(t, &limit, upstream, anthropicBudgetRequest)
	if !strings.Contains(body, `"stop_reason":"max_tokens"`) || !strings.HasSuffix(strings.TrimSpace(body), `data: {"type":"message_stop"}`) {
		t.Fatalf("truncated Messages stream must end with max_tokens + message_stop: %q", body[max(0, len(body)-400):])
	}
	stop := strings.LastIndex(body, `"type":"content_block_stop"`)
	delta := strings.LastIndex(body, `"stop_reason":"max_tokens"`)
	if stop < 0 || stop > delta || strings.Count(body, `"type":"content_block_stop"`) != 1 {
		t.Fatalf("open content block must be closed once before message_delta: %q", body[max(0, len(body)-500):])
	}
	if got := strings.Count(body, "hello world"); got >= 200 || got < 1 {
		t.Fatalf("forwarded %d deltas; stream was not truncated", got)
	}
	usage, status, source := cp.settled()
	if status != "incomplete" || source != "upstream" || usage["output_tokens"] != float64(600) {
		t.Fatalf("settlement must use upstream usage: status=%v source=%v usage=%v", status, source, usage)
	}
}

// 开关关闭：发给上游的请求体与客户端原样一致，转发内容与结算不变。
func TestNativeMessagesWithoutBudgetCapIsUnchanged(t *testing.T) {
	upstream := &anthropicBudgetUpstream{obey: true}
	body, cp, _ := runAnthropicBudgetStream(t, nil, upstream, anthropicBudgetRequest)
	if upstream.rawBody() != anthropicBudgetRequest {
		t.Fatalf("request body must be forwarded byte-for-byte:\nwant=%s\n got=%s", anthropicBudgetRequest, upstream.rawBody())
	}
	if strings.Count(body, "hello world") != 200 || strings.Contains(body, `"stop_reason":"max_tokens"`) {
		t.Fatalf("stream without cap must be untouched: %q", body[max(0, len(body)-400):])
	}
	usage, _, _ := cp.settled()
	if usage["output_tokens"] != float64(600) {
		t.Fatalf("usage=%v", usage)
	}
}
