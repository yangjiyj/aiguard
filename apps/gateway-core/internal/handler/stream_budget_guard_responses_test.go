package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// openAIBudgetUpstream 模拟 OpenAI 上游（Responses 与 Chat Completions），记录收到的请求体。
// obey=true 时遵守输出上限并返回 incomplete/length 与权威 usage；obey=false 时无视上限。
type openAIBudgetUpstream struct {
	mu   sync.Mutex
	body []byte
	path string
	obey bool
}

func (u *openAIBudgetUpstream) received() (map[string]any, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out map[string]any
	_ = json.Unmarshal(u.body, &out)
	return out, string(u.body)
}

func (u *openAIBudgetUpstream) server(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.body, u.path = raw, r.URL.Path
		u.mu.Unlock()
		var request map[string]any
		_ = json.Unmarshal(raw, &request)
		limit := 0
		for _, key := range []string{"max_output_tokens", "max_completion_tokens", "max_tokens"} {
			if v, ok := request[key].(float64); ok && v > 0 {
				limit = int(v)
			}
		}
		chunks, output, limited := 200, 600, false
		if u.obey && limit > 0 && limit < 600 {
			chunks, output, limited = limit/3, limit, true
		}
		stream, _ := request["stream"].(bool)
		if strings.HasSuffix(r.URL.Path, "/responses") {
			status, terminal, details := "completed", "response.completed", ""
			if limited {
				status, terminal, details = "incomplete", "response.incomplete", `,"incomplete_details":{"reason":"max_output_tokens"}`
			}
			final := fmt.Sprintf(`{"id":"resp_b","object":"response","status":"%s"%s,"model":"gpt-b","output":[{"id":"msg_b","type":"message","status":"%s","role":"assistant","content":[{"type":"output_text","text":"%s"}]}],"usage":{"input_tokens":9,"output_tokens":%d,"total_tokens":%d}}`,
				status, details, status, strings.Repeat("hello world ", chunks), output, output+9)
			if !stream {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, final)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			_, _ = io.WriteString(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_b\",\"status\":\"in_progress\"}}\n\n")
			for i := 0; i < chunks; i++ {
				_, _ = io.WriteString(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hello world \"}\n\n")
				flusher.Flush()
			}
			_, _ = io.WriteString(w, "event: "+terminal+"\ndata: {\"type\":\""+terminal+"\",\"response\":"+final+"}\n\n")
			flusher.Flush()
			return
		}
		finish := "stop"
		if limited {
			finish = "length"
		}
		if !stream {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"id":"chat_b","object":"chat.completion","model":"gpt-b","choices":[{"index":0,"message":{"role":"assistant","content":"%s"},"finish_reason":"%s"}],"usage":{"prompt_tokens":9,"completion_tokens":%d,"total_tokens":%d}}`,
				strings.Repeat("hello world ", chunks), finish, output, output+9)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			_, _ = io.WriteString(w, "data: {\"id\":\"chat_b\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-b\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello world \"}}]}\n\n")
			flusher.Flush()
		}
		_, _ = fmt.Fprintf(w, "data: {\"id\":\"chat_b\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-b\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"%s\"}]}\n\n", finish)
		_, _ = fmt.Fprintf(w, "data: {\"id\":\"chat_b\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-b\",\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":%d,\"total_tokens\":%d}}\n\n", output, output+9)
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	t.Cleanup(server.Close)
	return server
}

func openAIBudgetResolver(baseURL string) *MockModelResolver {
	return &MockModelResolver{
		ProviderAPIKey: "provider-key",
		ModelRecord: &modelrouter.ModelRecord{
			ID: "model-b", ProviderID: "provider-b", ModelName: "gpt-b", UpstreamModelID: "gpt-b",
			ProviderType: "openai", ProviderBaseURL: baseURL, ProviderAuthMode: "bearer",
			Status: "active", ResponsesNative: true,
		},
	}
}

func runResponsesBudget(t *testing.T, cap *int64, upstream *openAIBudgetUpstream, requestBody string) (*httptest.ResponseRecorder, *streamBudgetControlPlane, *MockAuditWriter) {
	t.Helper()
	server := upstream.server(t)
	cp := &streamBudgetControlPlane{cap: cap}
	client := NewBillingClientWithMode(cp.server(t).URL, "internal-secret", "", "metering")
	inner := &MockAuditWriter{}
	handler := NewResponsesHandler(
		&config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_audit"},
		openAIBudgetResolver(server.URL), &MockRateLimitChecker{}, &streamRegressionSecurity{}, NewBillingAuditWriter(inner, client), &RealProviderAdapterFactory{}, nil, nil,
	)
	handler.SetBillingPreflight(client)
	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(requestBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	return w, cp, inner
}

func runChatBudget(t *testing.T, cap *int64, upstream *openAIBudgetUpstream, requestBody string) (*httptest.ResponseRecorder, *streamBudgetControlPlane, *MockAuditWriter) {
	t.Helper()
	server := upstream.server(t)
	cp := &streamBudgetControlPlane{cap: cap}
	client := NewBillingClientWithMode(cp.server(t).URL, "internal-secret", "", "metering")
	inner := &MockAuditWriter{}
	handler := NewChatCompletionsHandler(
		&config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_audit"},
		openAIBudgetResolver(server.URL), &MockRateLimitChecker{}, &streamRegressionSecurity{}, NewBillingAuditWriter(inner, client), &RealProviderAdapterFactory{}, nil, nil,
	)
	handler.SetBillingPreflight(client)
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(requestBody))
	request = request.WithContext(setAuthInfo(context.Background(), "tenant-b", "project-b", "user-b", "key-b", "session-b"))
	w := httptest.NewRecorder()
	handler.Handler().ServeHTTP(w, request)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	return w, cp, inner
}

const responsesBudgetStream = `{"model":"gpt-b","input":"long","stream":true,"max_output_tokens":1000}`

// Responses 主路径：max_output_tokens 收紧到上限，上游返回 response.incomplete
// （incomplete_details.reason=max_output_tokens），按上游权威 usage 结算。
func TestNativeResponsesStreamBudgetCapTightensMaxOutputTokens(t *testing.T) {
	limit := int64(60)
	upstream := &openAIBudgetUpstream{obey: true}
	w, cp, _ := runResponsesBudget(t, &limit, upstream, responsesBudgetStream)
	got, _ := upstream.received()
	if got["max_output_tokens"] != float64(60) {
		t.Fatalf("upstream max_output_tokens=%v want 60", got["max_output_tokens"])
	}
	body := w.Body.String()
	if !strings.Contains(body, "response.incomplete") || !strings.Contains(body, `"reason":"max_output_tokens"`) {
		t.Fatalf("client must receive the upstream incomplete terminal: %q", body[max(0, len(body)-400):])
	}
	usage, status, source := cp.settled()
	if usage["output_tokens"] != float64(60) || source != "upstream" || status != "success" {
		t.Fatalf("settlement must equal the upstream usage: status=%v source=%v usage=%v", status, source, usage)
	}
}

// Responses 兜底：上游无视上限时停止转发，网关发 response.incomplete（reason=max_output_tokens），
// 继续读到上游结束事件，按上游权威 usage 结算。
func TestNativeResponsesStreamFallbackTruncatesAndSettlesUpstreamUsage(t *testing.T) {
	limit := int64(5)
	upstream := &openAIBudgetUpstream{obey: false}
	w, cp, inner := runResponsesBudget(t, &limit, upstream, responsesBudgetStream)
	body := w.Body.String()
	if !strings.Contains(body, "event: response.incomplete") || !strings.Contains(body, `"reason":"max_output_tokens"`) || strings.Contains(body, "event: response.completed") {
		t.Fatalf("truncated Responses stream must end with response.incomplete: %q", body[max(0, len(body)-600):])
	}
	if got := strings.Count(body, "response.output_text.delta"); got >= 200 || got < 1 {
		t.Fatalf("forwarded %d deltas; stream was not truncated", got)
	}
	usage, status, source := cp.settled()
	if status != "incomplete" || source != "upstream" || usage["output_tokens"] != float64(600) {
		t.Fatalf("settlement must use upstream usage: status=%v source=%v usage=%v", status, source, usage)
	}
	if inner.RequestLogFinalizes[0].AuditResult.ResponseMetadata["stream_budget_truncated"] != true {
		t.Fatalf("request log meta=%v", inner.RequestLogFinalizes[0].AuditResult.ResponseMetadata)
	}
}

// Responses 非流式：客户端自带更大的 max_output_tokens 时收紧到预算上限，客户端原样拿到上游 incomplete 响应。
// 客户端未带上限时不注入（见 TestNativeResponsesNonStreamBudgetCapDoesNotInjectMaxOutputTokens）。
func TestNativeResponsesNonStreamBudgetCapTightensMaxOutputTokens(t *testing.T) {
	limit := int64(60)
	upstream := &openAIBudgetUpstream{obey: true}
	w, cp, _ := runResponsesBudget(t, &limit, upstream, `{"model":"gpt-b","input":"long","max_output_tokens":4000}`)
	got, _ := upstream.received()
	if got["max_output_tokens"] != float64(60) || !strings.Contains(w.Body.String(), `"status":"incomplete"`) {
		t.Fatalf("upstream body=%v client=%s", got, w.Body.String())
	}
	usage, _, source := cp.settled()
	if usage["output_tokens"] != float64(60) || source != "upstream" {
		t.Fatalf("usage=%v source=%v", usage, source)
	}
}

// Responses 非流式：客户端未带 max_output_tokens 时，预算上限不能被注入成上游请求参数。
func TestNativeResponsesNonStreamBudgetCapDoesNotInjectMaxOutputTokens(t *testing.T) {
	limit := int64(60)
	upstream := &openAIBudgetUpstream{obey: true}
	_, _, _ = runResponsesBudget(t, &limit, upstream, `{"model":"gpt-b","input":"long"}`)
	got, _ := upstream.received()
	if _, present := got["max_output_tokens"]; present {
		t.Fatalf("未设置上限的请求不应被注入 max_output_tokens: %v", got)
	}
}

// 开关关闭：Responses 请求体逐字节透传，SSE 不变。
func TestNativeResponsesWithoutBudgetCapForwardsRequestUnchanged(t *testing.T) {
	upstream := &openAIBudgetUpstream{obey: true}
	w, _, _ := runResponsesBudget(t, nil, upstream, responsesBudgetStream)
	_, raw := upstream.received()
	if raw != responsesBudgetStream || strings.Contains(w.Body.String(), "response.incomplete") {
		t.Fatalf("request must be forwarded byte-for-byte:\nwant=%s\n got=%s", responsesBudgetStream, raw)
	}
	plain := `{"model":"gpt-b","input":"long"}`
	second := &openAIBudgetUpstream{obey: true}
	_, _, _ = runResponsesBudget(t, nil, second, plain)
	if _, raw := second.received(); raw != plain {
		t.Fatalf("non-stream request must be forwarded byte-for-byte:\nwant=%s\n got=%s", plain, raw)
	}
}

// Chat Completions 主路径：只收紧客户端已经给出的上限，更小的值不放大；
// 上游 finish_reason=length 与 usage 原样结算。
func TestChatCompletionsBudgetCapTightensUpstreamOutputParameter(t *testing.T) {
	limit := int64(60)
	for _, tc := range []struct {
		name, request, field string
		want                 float64
		absent               bool
	}{
		{"absent", `{"model":"gpt-b","stream":true,"messages":[{"role":"user","content":"long"}]}`, "max_completion_tokens", 600, true},
		{"larger", `{"model":"gpt-b","stream":true,"max_tokens":1000,"messages":[{"role":"user","content":"long"}]}`, "max_tokens", 60, false},
		{"smaller", `{"model":"gpt-b","stream":true,"max_completion_tokens":30,"messages":[{"role":"user","content":"long"}]}`, "max_completion_tokens", 30, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := &openAIBudgetUpstream{obey: true}
			w, cp, _ := runChatBudget(t, &limit, upstream, tc.request)
			got, raw := upstream.received()
			if (!tc.absent && got[tc.field] != tc.want) || (tc.absent && got[tc.field] != nil) {
				t.Fatalf("upstream %s=%v want %v: %s", tc.field, got[tc.field], tc.want, raw)
			}
			if stream, _ := got["stream_options"].(map[string]any); stream["include_usage"] != true {
				t.Fatalf("streaming upstream must request usage: %s", raw)
			}
			if !strings.Contains(w.Body.String(), `"finish_reason":"length"`) {
				t.Fatalf("client must see the upstream length finish: %q", w.Body.String()[max(0, w.Body.Len()-400):])
			}
			usage, _, source := cp.settled()
			if usage["output_tokens"] != tc.want || source != "upstream" {
				t.Fatalf("usage=%v source=%v", usage, source)
			}
		})
	}
}

// 开关关闭：Chat 发给上游的输出参数不被改写，不新增任何字段。
func TestChatCompletionsWithoutBudgetCapDoesNotRewriteOutputParameters(t *testing.T) {
	for _, request := range []string{
		`{"model":"gpt-b","stream":true,"messages":[{"role":"user","content":"long"}]}`,
		`{"model":"gpt-b","stream":true,"max_tokens":1000,"messages":[{"role":"user","content":"long"}]}`,
	} {
		upstream := &openAIBudgetUpstream{obey: true}
		_, _, _ = runChatBudget(t, nil, upstream, request)
		got, raw := upstream.received()
		var sent map[string]any
		_ = json.Unmarshal([]byte(request), &sent)
		if got["max_completion_tokens"] != nil || got["max_tokens"] != sent["max_tokens"] {
			t.Fatalf("output parameters must be untouched when cutoff is off: sent=%s upstream=%s", request, raw)
		}
	}
}

// Chat 非流式同样收紧（准入前已转换的上游请求体会按收紧后的参数重新转换）。
func TestChatCompletionsNonStreamBudgetCapTightensUpstreamOutputParameter(t *testing.T) {
	limit := int64(60)
	upstream := &openAIBudgetUpstream{obey: true}
	w, cp, _ := runChatBudget(t, &limit, upstream, `{"model":"gpt-b","max_tokens":1000,"messages":[{"role":"user","content":"long"}]}`)
	got, raw := upstream.received()
	if got["max_tokens"] != float64(60) || !strings.Contains(w.Body.String(), `"finish_reason":"length"`) {
		t.Fatalf("upstream=%s client=%s", raw, w.Body.String())
	}
	usage, _, source := cp.settled()
	if usage["output_tokens"] != float64(60) || source != "upstream" {
		t.Fatalf("usage=%v source=%v", usage, source)
	}
}
