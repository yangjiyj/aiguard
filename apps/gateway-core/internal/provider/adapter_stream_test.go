package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

func TestStreamingAdapterRecordsFirstEventTTFT(t *testing.T) {
	firstWritten := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		time.Sleep(20 * time.Millisecond)
		_, _ = io.WriteString(w, "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"}}]}\n\n")
		fl.Flush()
		close(firstWritten)
		time.Sleep(100 * time.Millisecond)
		_, _ = io.WriteString(w, "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
		fl.Flush()
	}))
	defer srv.Close()
	env := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "gpt-4"}
	_, err := (&OpenAIAdapter{BaseURL: srv.URL, APIKey: "test"}).CallStreaming(context.Background(), env, []byte(`{"model":"gpt-4","messages":[]}`))
	<-firstWritten
	if err != nil {
		t.Fatal(err)
	}
	if env.UpstreamTTFTMs == nil || *env.UpstreamTTFTMs < 10 || *env.UpstreamTTFTMs >= 80 {
		t.Fatalf("TTFT = %v", env.UpstreamTTFTMs)
	}
}

func TestOpenAIStreamIdleTimeoutClosesBlockedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{BaseURL: server.URL, APIKey: "test", StreamIdleTimeout: 40 * time.Millisecond}
	reader, _, err := adapter.OpenStream(context.Background(), &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "gpt-4"}, []byte(`{"model":"gpt-4"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	started := time.Now()
	_, err = reader.Next(context.Background())
	if !errors.Is(err, ErrUpstreamStreamIdleTimeout) {
		t.Fatalf("Next error=%v, want ErrUpstreamStreamIdleTimeout", err)
	}
	if elapsed := time.Since(started); elapsed < 25*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Fatalf("idle timeout elapsed=%s", elapsed)
	}
}

func TestOpenAIStreamIdleTimeoutResetsOnHeartbeatAndPartialBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for _, part := range []string{
			": heartbeat\n\n",
			"data: {\"id\":\"x\",\"choices\":[{\"index\":0,",
			"\"delta\":{\"content\":\"ok\"}}]}\n\n",
		} {
			_, _ = io.WriteString(w, part)
			flusher.Flush()
			time.Sleep(20 * time.Millisecond)
		}
		_, _ = io.WriteString(w, "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
		flusher.Flush()
	}))
	defer server.Close()

	adapter := &OpenAIAdapter{BaseURL: server.URL, APIKey: "test", StreamIdleTimeout: 35 * time.Millisecond}
	reader, _, err := adapter.OpenStream(context.Background(), &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "gpt-4"}, []byte(`{"model":"gpt-4"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	event, err := reader.Next(context.Background())
	if err != nil || event.Type != relay.EventTextDelta || event.Delta != "ok" {
		t.Fatalf("event=%+v err=%v", event, err)
	}
}

func TestNonStreamingAdapterLeavesTTFTNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"choices":[]}`) }))
	defer srv.Close()
	env := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "gpt-4"}
	_, _ = (&OpenAIAdapter{BaseURL: srv.URL, APIKey: "test"}).Call(context.Background(), env, []byte(`{"model":"gpt-4"}`))
	if env.UpstreamTTFTMs != nil {
		t.Fatalf("non-streaming TTFT = %v", *env.UpstreamTTFTMs)
	}
}

func TestOpenAIResponsesStreamingPreservesRawSSE(t *testing.T) {
	const raw = "event: response.created\nid: keep-me\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}\n\n" +
		"event: response.custom_unknown\ndata: {\"type\":\"response.custom_unknown\",\"opaque\":{\"x\":1}}\n\n" +
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"stream":true`) {
			t.Fatalf("stream flag missing: %s", body)
		}
		if strings.Contains(string(body), "stream_options") {
			t.Fatalf("chat-only stream_options leaked into Responses: %s", body)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, raw)
	}))
	defer server.Close()

	env := &modelrouter.RequestEnvelope{EndpointType: "responses", Model: "gpt-5.6"}
	got, err := (&OpenAIAdapter{BaseURL: server.URL, APIKey: "test"}).CallStreaming(context.Background(), env, []byte(`{"model":"gpt-5.6","stream":true,"unknown":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != raw {
		t.Fatalf("SSE changed\nwant=%q\n got=%q", raw, got)
	}
}

func TestOpenAIChatResponsesBridgeDoesNotDuplicateFinalToolArguments(t *testing.T) {
	const upstream = "event: response.output_item.added\n" +
		"data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"call-1\",\"name\":\"Skill\"}}\n\n" +
		"event: response.function_call_arguments.delta\n" +
		"data: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"call-1\",\"output_index\":0,\"delta\":\"{\\\"skill\\\":\\\"deploy-jjdguard-upgrade-run\\\"}\"}\n\n" +
		"event: response.function_call_arguments.done\n" +
		"data: {\"type\":\"response.function_call_arguments.done\",\"item_id\":\"call-1\",\"output_index\":0,\"arguments\":\"{\\\"skill\\\":\\\"deploy-jjdguard-upgrade-run\\\"}\"}\n\n" +
		"event: response.completed\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, upstream)
	}))
	defer server.Close()

	reader, _, err := (&OpenAIAdapter{BaseURL: server.URL, APIKey: "test"}).OpenStream(
		context.Background(), chatResponsesBridgeEnvelope(), []byte(`{"model":"vendor-model","input":[]}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	encoder := relay.NewChatEncoder("req-1", "logical-model")
	var arguments string
	for {
		event, nextErr := reader.Next(context.Background())
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		payload, encodeErr := encoder.Encode(event)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		arguments += encodedChatToolArguments(t, payload)
	}

	want := `{"skill":"deploy-jjdguard-upgrade-run"}`
	if arguments != want {
		t.Fatalf("tool arguments=%q; want %q", arguments, want)
	}
}

func encodedChatToolArguments(t *testing.T, payload []byte) string {
	t.Helper()
	if len(payload) == 0 {
		return ""
	}
	var chunk struct {
		Choices []struct {
			Delta struct {
				ToolCalls []struct {
					Function struct {
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(payload, &chunk); err != nil {
		t.Fatal(err)
	}
	var arguments string
	for _, choice := range chunk.Choices {
		for _, tool := range choice.Delta.ToolCalls {
			arguments += tool.Function.Arguments
		}
	}
	return arguments
}

func TestOpenAIChatSSEUsageNormalizesCacheAndReasoningTokens(t *testing.T) {
	events, err := openAIChatSSEToEvents(relay.SSEEvent{Data: "{\"id\":\"chat-usage\",\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":30,\"prompt_tokens_details\":{\"cached_tokens\":25,\"cache_creation_input_tokens\":10},\"completion_tokens_details\":{\"reasoning_tokens\":12}}}"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Usage == nil {
		t.Fatalf("events=%#v", events)
	}
	usage := events[0].Usage
	if usage.InputTokens != 100 || usage.OutputTokens != 30 || usage.CacheReadInputTokens != 25 ||
		usage.CacheCreationInputTokens != 10 || usage.ReasoningTokens != 12 {
		t.Fatalf("normalized stream usage=%#v", usage)
	}
}

func TestOpenAIChatSSEUsageReconstructsDeepSeekCacheTotals(t *testing.T) {
	events, err := openAIChatSSEToEvents(relay.SSEEvent{Data: "{\"choices\":[],\"usage\":{\"prompt_cache_hit_tokens\":60,\"prompt_cache_miss_tokens\":40,\"completion_tokens\":3}}"})
	if err != nil || len(events) != 1 || events[0].Usage == nil {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	usage := events[0].Usage
	if usage.InputTokens != 100 || usage.CacheReadInputTokens != 60 || usage.CacheMissInputTokens != 40 {
		t.Fatalf("DeepSeek stream usage=%#v", usage)
	}
}

func TestValidateNativeResponsesSSETerminal(t *testing.T) {
	incomplete := []byte("event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"status\":\"incomplete\"}}\n\n")
	if err := validateNativeResponsesSSETerminal(incomplete); err != nil {
		t.Fatalf("incomplete is a legal terminal event: %v", err)
	}
	failed := []byte("event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"status\":\"failed\",\"error\":{\"message\":\"boom\"}}}\n\n")
	if err := validateNativeResponsesSSETerminal(failed); err == nil {
		t.Fatal("failed terminal event must be a provider error")
	}
	truncated := []byte("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"half\"}\n\n")
	if err := validateNativeResponsesSSETerminal(truncated); err == nil {
		t.Fatal("stream without terminal event must fail before route success")
	}
	multiData := []byte("event: response.completed\n" +
		"data: {\"type\":\"response.completed\",\n" +
		"data: \"response\":{\"status\":\"completed\"}}\n\n")
	if err := validateNativeResponsesSSETerminal(multiData); err != nil {
		t.Fatalf("multi-data SSE terminal event must be merged: %v", err)
	}
}

func TestForceResponsesStreamPreservesAlreadyStreamingBytes(t *testing.T) {
	raw := []byte("{ \"model\" : \"gpt\", \"stream\" : true, \"unknown_big\" : 9007199254740993123456789 }")
	got, err := forceResponsesStream(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("already-streaming request was re-encoded\nwant=%s\n got=%s", raw, got)
	}
}

func TestOpenAITTFTWaitsForSemanticDelta(t *testing.T) {
	emptyCalled := false
	_, emptyErr := accumulateOpenAISSEWithFirstEvent(strings.NewReader(sseChat(`{}`, `{"choices":[{"index":0,"delta":{}}]}`, `{"choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`, `[DONE]`)), func() { emptyCalled = true })
	if emptyErr != nil || emptyCalled {
		t.Fatalf("non-semantic OpenAI events recorded TTFT: called=%v err=%v", emptyCalled, emptyErr)
	}
	stream := sseChat(`{"choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`, `{"choices":[{"index":0,"delta":{"content":"token"}}]}`, `{"choices":[{"index":0,"delta":{"content":"later"},"finish_reason":"stop"}]}`, `[DONE]`)
	callbackCount := 0
	_, err := accumulateOpenAISSEWithFirstEvent(strings.NewReader(stream), func() { callbackCount++ })
	if err != nil || callbackCount != 1 {
		t.Fatalf("callbackCount=%d err=%v", callbackCount, err)
	}
}

func TestOpenAIEmbeddedErrorDoesNotRecordTTFT(t *testing.T) {
	called := false
	_, err := accumulateOpenAISSEWithFirstEvent(strings.NewReader(sseChat(`{"error":{"message":"bad"}}`)), func() { called = true })
	if err == nil || called {
		t.Fatalf("embedded error recorded TTFT: called=%v err=%v", called, err)
	}
}

func TestAnthropicTTFTWaitsForContentDelta(t *testing.T) {
	nonContent := sseAnthropic([2]string{"ping", `{"type":"ping"}`}, [2]string{"message_start", `{"type":"message_start","message":{"id":"m"}}`}, [2]string{"message_stop", `{"type":"message_stop"}`})
	nonContentCalled := false
	_, nonContentErr := accumulateAnthropicSSEWithFirstEvent(strings.NewReader(nonContent), func() { nonContentCalled = true })
	if nonContentErr != nil || nonContentCalled {
		t.Fatalf("non-content Anthropic events recorded TTFT: called=%v err=%v", nonContentCalled, nonContentErr)
	}
	stream := sseAnthropic(
		[2]string{"ping", `{"type":"ping"}`},
		[2]string{"message_start", `{"type":"message_start","message":{"id":"m","role":"assistant","model":"claude"}}`},
		[2]string{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text"}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"token"}}`},
		[2]string{"message_stop", `{"type":"message_stop"}`},
	)
	called := 0
	_, err := accumulateAnthropicSSEWithFirstEvent(strings.NewReader(stream), func() { called++ })
	if err != nil || called != 1 {
		t.Fatalf("semantic callback count=%d err=%v", called, err)
	}
}

func TestAnthropicErrorDoesNotRecordTTFT(t *testing.T) {
	called := false
	_, err := accumulateAnthropicSSEWithFirstEvent(strings.NewReader(sseAnthropic([2]string{"error", `{"type":"error","error":{"message":"bad"}}`})), func() { called = true })
	if err == nil || called {
		t.Fatalf("error recorded TTFT: called=%v err=%v", called, err)
	}
}

// sseChat 把若干 SSE data 帧用 OpenAI 兼容格式拼成一段流文本(每帧 "data: ...\n\n")。
func sseChat(frames ...string) string {
	var b strings.Builder
	for _, f := range frames {
		b.WriteString("data: ")
		b.WriteString(f)
		b.WriteString("\n\n")
	}
	return b.String()
}

// TestAccumulateOpenAISSE_Equivalence 核心保真度断言: 流式累积结果与等价非流式响应一致。
// 覆盖: 多 chunk content 顺序拼接、跨片 tool_calls arguments 续接、reasoning_content、末帧 usage、[DONE]。
func TestAccumulateOpenAISSE_Equivalence(t *testing.T) {
	stream := sseChat(
		`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":100,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`,
		`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"reasoning_content":"think "},"finish_reason":null}]}`,
		`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"reasoning_content":"more"},"finish_reason":null}]}`,
		`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`,
		`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":", world"},"finish_reason":null}]}`,
		`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"get_weather","arguments":"{\"ci"}}]},"finish_reason":null}]}`,
		`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ty\":\"SF\"}"}}]},"finish_reason":null}]}`,
		`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":22,"total_tokens":33,"completion_tokens_details":{"reasoning_tokens":5}}}`,
		`[DONE]`,
	)

	out, err := accumulateOpenAISSE(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("accumulate error: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal accumulated: %v\nbody=%s", err, out)
	}

	if got["id"] != "chatcmpl-1" {
		t.Errorf("id = %v, want chatcmpl-1", got["id"])
	}
	if got["object"] != "chat.completion" {
		t.Errorf("object = %v, want chat.completion", got["object"])
	}
	if got["model"] != "gpt-4" {
		t.Errorf("model = %v, want gpt-4", got["model"])
	}

	choices := got["choices"].([]interface{})
	if len(choices) != 1 {
		t.Fatalf("choices len = %d, want 1", len(choices))
	}
	ch0 := choices[0].(map[string]interface{})
	if ch0["finish_reason"] != "tool_calls" {
		t.Errorf("finish_reason = %v, want tool_calls", ch0["finish_reason"])
	}
	msg := ch0["message"].(map[string]interface{})
	if msg["content"] != "Hello, world" {
		t.Errorf("content = %q, want %q", msg["content"], "Hello, world")
	}
	if msg["reasoning_content"] != "think more" {
		t.Errorf("reasoning_content = %q, want %q", msg["reasoning_content"], "think more")
	}
	tcs := msg["tool_calls"].([]interface{})
	if len(tcs) != 1 {
		t.Fatalf("tool_calls len = %d, want 1", len(tcs))
	}
	tc0 := tcs[0].(map[string]interface{})
	if tc0["id"] != "call_a" {
		t.Errorf("tool_call id = %v, want call_a", tc0["id"])
	}
	fn := tc0["function"].(map[string]interface{})
	if fn["name"] != "get_weather" {
		t.Errorf("tool_call name = %v, want get_weather", fn["name"])
	}
	if fn["arguments"] != `{"city":"SF"}` {
		t.Errorf("tool_call arguments = %q, want %q", fn["arguments"], `{"city":"SF"}`)
	}

	usage := got["usage"].(map[string]interface{})
	if int(usage["prompt_tokens"].(float64)) != 11 || int(usage["completion_tokens"].(float64)) != 22 || int(usage["total_tokens"].(float64)) != 33 {
		t.Errorf("usage = %v, want 11/22/33", usage)
	}
	details := usage["completion_tokens_details"].(map[string]interface{})
	if int(details["reasoning_tokens"].(float64)) != 5 {
		t.Errorf("reasoning_tokens = %v, want 5", details["reasoning_tokens"])
	}
}

// TestAccumulateOpenAISSE_MultiChoice 多 choice(n>1) 按 index 分桶不串味。
func TestAccumulateOpenAISSE_MultiChoice(t *testing.T) {
	stream := sseChat(
		`{"id":"c","model":"m","choices":[{"index":0,"delta":{"content":"A"}},{"index":1,"delta":{"content":"X"}}]}`,
		`{"id":"c","choices":[{"index":0,"delta":{"content":"B"},"finish_reason":"stop"}]}`,
		`{"id":"c","choices":[{"index":1,"delta":{"content":"Y"},"finish_reason":"stop"}]}`,
		`[DONE]`,
	)
	out, err := accumulateOpenAISSE(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("accumulate error: %v", err)
	}
	var got map[string]interface{}
	_ = json.Unmarshal(out, &got)
	choices := got["choices"].([]interface{})
	if len(choices) != 2 {
		t.Fatalf("choices len = %d, want 2", len(choices))
	}
	c0 := choices[0].(map[string]interface{})["message"].(map[string]interface{})
	c1 := choices[1].(map[string]interface{})["message"].(map[string]interface{})
	if c0["content"] != "AB" {
		t.Errorf("choice0 content = %q, want AB", c0["content"])
	}
	if c1["content"] != "XY" {
		t.Errorf("choice1 content = %q, want XY", c1["content"])
	}
}

// TestAccumulateOpenAISSE_InlineError 200 + SSE 内嵌 error 事件 → *UpstreamHTTPError。
func TestAccumulateOpenAISSE_InlineError(t *testing.T) {
	stream := sseChat(
		`{"id":"c","choices":[{"index":0,"delta":{"content":"partial"}}]}`,
		`{"error":{"message":"rate limited","type":"rate_limit_error"}}`,
	)
	_, err := accumulateOpenAISSE(strings.NewReader(stream))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	ue := GetUpstreamHTTPError(err)
	if ue == nil {
		t.Fatalf("expected *UpstreamHTTPError, got %T: %v", err, err)
	}
	if !strings.Contains(ue.Message, "rate limited") {
		t.Errorf("error message = %q, want contains 'rate limited'", ue.Message)
	}
}

// TestAccumulateOpenAISSE_Truncated 中途断流(无 finish_reason/[DONE]) → error, 不返回半截。
func TestAccumulateOpenAISSE_Truncated(t *testing.T) {
	stream := sseChat(
		`{"id":"c","choices":[{"index":0,"delta":{"content":"half"}}]}`,
		// 没有 finish_reason, 没有 [DONE], 流就结束了
	)
	out, err := accumulateOpenAISSE(strings.NewReader(stream))
	if err == nil {
		t.Fatalf("expected truncation error, got out=%s", out)
	}
	if out != nil {
		t.Errorf("expected nil body on truncation, got %s", out)
	}
}

// TestAccumulateOpenAISSE_LargeFrame 单帧超过 64KB(bufio.Scanner 默认上限)也能解析。
func TestAccumulateOpenAISSE_LargeFrame(t *testing.T) {
	big := strings.Repeat("x", 200*1024) // 200KB
	frame := `{"id":"c","choices":[{"index":0,"delta":{"content":"` + big + `"},"finish_reason":"stop"}]}`
	stream := sseChat(frame, `[DONE]`)
	out, err := accumulateOpenAISSE(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("accumulate large frame error: %v", err)
	}
	var got map[string]interface{}
	_ = json.Unmarshal(out, &got)
	content := got["choices"].([]interface{})[0].(map[string]interface{})["message"].(map[string]interface{})["content"].(string)
	if len(content) != len(big) {
		t.Errorf("content len = %d, want %d (large frame truncated?)", len(content), len(big))
	}
}

// TestSSEParser_MultiDataLinesAndComments 多 data 行拼接 + 注释行(keep-alive)跳过。
func TestSSEParser_MultiDataLinesAndComments(t *testing.T) {
	raw := ": ping\n" +
		"data: {\"id\":\"c\",\"choices\":[{\"index\":0,\n" +
		"data: \"delta\":{\"content\":\"hi\"},\"finish_reason\":\"stop\"}]}\n" +
		"\n" +
		"data: [DONE]\n\n"
	out, err := accumulateOpenAISSE(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("accumulate error: %v", err)
	}
	var got map[string]interface{}
	_ = json.Unmarshal(out, &got)
	content := got["choices"].([]interface{})[0].(map[string]interface{})["message"].(map[string]interface{})["content"]
	if content != "hi" {
		t.Errorf("content = %v, want hi (multi-data-line join failed)", content)
	}
}

// TestOpenAICallStreaming_HTTPErrorPath 上游非 2xx 首包 → *UpstreamHTTPError(走非 SSE 路径)。
func TestOpenAICallStreaming_HTTPErrorPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"slow down"}}`))
	}))
	defer srv.Close()

	a := &OpenAIAdapter{BaseURL: srv.URL, APIKey: "sk-test"}
	env := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "gpt-4"}
	_, err := a.CallStreaming(context.Background(), env, []byte(`{"model":"gpt-4","messages":[]}`))
	if err == nil {
		t.Fatal("expected error")
	}
	ue := GetUpstreamHTTPError(err)
	if ue == nil {
		t.Fatalf("expected *UpstreamHTTPError, got %T", err)
	}
	if ue.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", ue.StatusCode)
	}
}

// TestOpenAICallStreaming_EndToEnd 经真 HTTP server 跑通 SSE 累积, 并断言请求被强制改成 stream:true + include_usage。
func TestOpenAICallStreaming_EndToEnd(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		frames := []string{
			`{"id":"x","model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"}}]}`,
			`{"id":"x","choices":[{"index":0,"delta":{"content":" there"},"finish_reason":"stop"}]}`,
			`{"id":"x","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`,
			`[DONE]`,
		}
		for _, f := range frames {
			_, _ = w.Write([]byte("data: " + f + "\n\n"))
			if fl != nil {
				fl.Flush()
			}
		}
	}))
	defer srv.Close()

	a := &OpenAIAdapter{BaseURL: srv.URL, APIKey: "sk-test"}
	env := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "gpt-4"}
	out, err := a.CallStreaming(context.Background(), env, []byte(`{"model":"gpt-4","messages":[],"stream":false}`))
	if err != nil {
		t.Fatalf("CallStreaming error: %v", err)
	}

	// 请求侧: 被强制改成 stream:true + stream_options.include_usage
	if gotBody["stream"] != true {
		t.Errorf("upstream request stream = %v, want true", gotBody["stream"])
	}
	if so, ok := gotBody["stream_options"].(map[string]interface{}); !ok || so["include_usage"] != true {
		t.Errorf("upstream request stream_options.include_usage not set: %v", gotBody["stream_options"])
	}

	// 响应侧: 累积结果等价
	var got map[string]interface{}
	_ = json.Unmarshal(out, &got)
	content := got["choices"].([]interface{})[0].(map[string]interface{})["message"].(map[string]interface{})["content"]
	if content != "Hi there" {
		t.Errorf("content = %v, want 'Hi there'", content)
	}
	usage := got["usage"].(map[string]interface{})
	if int(usage["total_tokens"].(float64)) != 3 {
		t.Errorf("total_tokens = %v, want 3", usage["total_tokens"])
	}
}

// ---------------- Anthropic 累积器测试 ----------------

// sseAnthropic 把若干 (event, data) 拼成 Anthropic 风格 SSE 文本(每事件 "event: T\ndata: {...}\n\n")。
func sseAnthropic(pairs ...[2]string) string {
	var b strings.Builder
	for _, p := range pairs {
		b.WriteString("event: ")
		b.WriteString(p[0])
		b.WriteString("\n")
		b.WriteString("data: ")
		b.WriteString(p[1])
		b.WriteString("\n\n")
	}
	return b.String()
}

// anthropicHappyStream 一段覆盖 text/tool_use(跨片)/thinking/usage 的完整 Anthropic SSE 流。
func anthropicHappyStream() string {
	return sseAnthropic(
		[2]string{"message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-3","content":[],"usage":{"input_tokens":11,"cache_read_input_tokens":7,"cache_creation_input_tokens":5,"output_tokens":0}}}`},
		// block 0: thinking
		[2]string{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"let me "}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"think"}}`},
		[2]string{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		// block 1: text (分片)
		[2]string{"content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Hello"}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":", world"}}`},
		[2]string{"content_block_stop", `{"type":"content_block_stop","index":1}`},
		// block 2: tool_use (input_json_delta 跨片)
		[2]string{"content_block_start", `{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_a","name":"get_weather","input":{}}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"ci"}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"ty\":\"SF\"}"}}`},
		[2]string{"content_block_stop", `{"type":"content_block_stop","index":2}`},
		// message_delta: stop_reason + usage(output)
		[2]string{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":22}}`},
		[2]string{"message_stop", `{"type":"message_stop"}`},
	)
}

// TestAccumulateAnthropicSSE_Equivalence 核心保真度: 重组的 Anthropic message JSON 正确,
// 且经 TransformResponse 后的 OpenAI 结果正确(text 合并 / tool_use→tool_calls / thinking→reasoning_content)。
func TestAccumulateAnthropicSSE_Equivalence(t *testing.T) {
	out, err := accumulateAnthropicSSE(strings.NewReader(anthropicHappyStream()))
	if err != nil {
		t.Fatalf("accumulate error: %v", err)
	}

	// 1) 断言重组的 Anthropic 原生 message JSON
	var anth map[string]interface{}
	if err := json.Unmarshal(out, &anth); err != nil {
		t.Fatalf("unmarshal anthropic: %v\nbody=%s", err, out)
	}
	if anth["id"] != "msg_1" {
		t.Errorf("id = %v, want msg_1", anth["id"])
	}
	if anth["type"] != "message" {
		t.Errorf("type = %v, want message", anth["type"])
	}
	if anth["model"] != "claude-3" {
		t.Errorf("model = %v, want claude-3", anth["model"])
	}
	if anth["stop_reason"] != "tool_use" {
		t.Errorf("stop_reason = %v, want tool_use", anth["stop_reason"])
	}
	blocks := anth["content"].([]interface{})
	if len(blocks) != 3 {
		t.Fatalf("content blocks = %d, want 3", len(blocks))
	}
	// block 0 thinking
	tb := blocks[0].(map[string]interface{})
	if tb["type"] != "thinking" || tb["thinking"] != "let me think" {
		t.Errorf("thinking block = %v, want 'let me think'", tb)
	}
	// block 1 text
	txt := blocks[1].(map[string]interface{})
	if txt["type"] != "text" || txt["text"] != "Hello, world" {
		t.Errorf("text block = %v, want 'Hello, world'", txt)
	}
	// block 2 tool_use, input 跨片拼接后是合法对象
	tu := blocks[2].(map[string]interface{})
	if tu["type"] != "tool_use" || tu["id"] != "toolu_a" || tu["name"] != "get_weather" {
		t.Errorf("tool_use block meta = %v", tu)
	}
	in := tu["input"].(map[string]interface{})
	if in["city"] != "SF" {
		t.Errorf("tool_use input = %v, want city=SF", in)
	}
	// usage
	usage := anth["usage"].(map[string]interface{})
	if int(usage["input_tokens"].(float64)) != 11 || int(usage["cache_read_input_tokens"].(float64)) != 7 || int(usage["cache_creation_input_tokens"].(float64)) != 5 || int(usage["output_tokens"].(float64)) != 22 {
		t.Errorf("usage = %v, want input/cache-read/cache-write/output 11/7/5/22", usage)
	}

	// 2) 经下游 TransformResponse 转 OpenAI
	a := &AnthropicAdapter{}
	oa, err := a.TransformResponse(out)
	if err != nil {
		t.Fatalf("TransformResponse error: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(oa, &got); err != nil {
		t.Fatalf("unmarshal openai: %v", err)
	}
	if got["object"] != "chat.completion" {
		t.Errorf("object = %v, want chat.completion", got["object"])
	}
	choices := got["choices"].([]interface{})
	if len(choices) != 1 {
		t.Fatalf("choices = %d, want 1", len(choices))
	}
	ch0 := choices[0].(map[string]interface{})
	if ch0["finish_reason"] != "tool_calls" {
		t.Errorf("finish_reason = %v, want tool_calls", ch0["finish_reason"])
	}
	msg := ch0["message"].(map[string]interface{})
	if msg["content"] != "Hello, world" {
		t.Errorf("content = %q, want 'Hello, world'", msg["content"])
	}
	if msg["reasoning_content"] != "let me think" {
		t.Errorf("reasoning_content = %q, want 'let me think'", msg["reasoning_content"])
	}
	tcs := msg["tool_calls"].([]interface{})
	if len(tcs) != 1 {
		t.Fatalf("tool_calls = %d, want 1", len(tcs))
	}
	tc0 := tcs[0].(map[string]interface{})
	if tc0["id"] != "toolu_a" {
		t.Errorf("tool_call id = %v, want toolu_a", tc0["id"])
	}
	fn := tc0["function"].(map[string]interface{})
	if fn["name"] != "get_weather" {
		t.Errorf("tool_call name = %v, want get_weather", fn["name"])
	}
	// arguments 应是合法 JSON 字符串, 解析后 city=SF
	var argObj map[string]interface{}
	if err := json.Unmarshal([]byte(fn["arguments"].(string)), &argObj); err != nil {
		t.Fatalf("tool_call arguments not valid JSON: %q", fn["arguments"])
	}
	if argObj["city"] != "SF" {
		t.Errorf("tool_call arguments = %v, want city=SF", argObj)
	}
	// usage 映射
	u := got["usage"].(map[string]interface{})
	if int(u["prompt_tokens"].(float64)) != 23 || int(u["completion_tokens"].(float64)) != 22 || int(u["total_tokens"].(float64)) != 45 {
		t.Errorf("usage = %v, want 23/22/45", u)
	}
	if int(u["cache_read_input_tokens"].(float64)) != 7 || int(u["cache_creation_input_tokens"].(float64)) != 5 {
		t.Errorf("cache usage = %v, want read/write 7/5", u)
	}
}

// TestAccumulateAnthropicSSE_TextOnly 纯文本流 → finish_reason=stop, 无 tool_calls/reasoning。
func TestAccumulateAnthropicSSE_TextOnly(t *testing.T) {
	stream := sseAnthropic(
		[2]string{"message_start", `{"type":"message_start","message":{"id":"m","model":"c","role":"assistant","usage":{"input_tokens":3}}}`},
		[2]string{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`},
		[2]string{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":4}}`},
		[2]string{"message_stop", `{"type":"message_stop"}`},
	)
	out, err := accumulateAnthropicSSE(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("accumulate error: %v", err)
	}
	a := &AnthropicAdapter{}
	oa, _ := a.TransformResponse(out)
	var got map[string]interface{}
	_ = json.Unmarshal(oa, &got)
	ch0 := got["choices"].([]interface{})[0].(map[string]interface{})
	if ch0["finish_reason"] != "stop" {
		t.Errorf("finish_reason = %v, want stop", ch0["finish_reason"])
	}
	msg := ch0["message"].(map[string]interface{})
	if msg["content"] != "hi" {
		t.Errorf("content = %v, want hi", msg["content"])
	}
	if _, exists := msg["tool_calls"]; exists {
		t.Errorf("unexpected tool_calls present")
	}
	if _, exists := msg["reasoning_content"]; exists {
		t.Errorf("unexpected reasoning_content present")
	}
}

// TestAccumulateAnthropicSSE_Truncated 未见 message_stop → error, 不返回半截。
func TestAccumulateAnthropicSSE_Truncated(t *testing.T) {
	stream := sseAnthropic(
		[2]string{"message_start", `{"type":"message_start","message":{"id":"m","model":"c","usage":{"input_tokens":1}}}`},
		[2]string{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`},
		[2]string{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"half"}}`},
		// 没有 message_delta / message_stop, 流就断了
	)
	out, err := accumulateAnthropicSSE(strings.NewReader(stream))
	if err == nil {
		t.Fatalf("expected truncation error, got out=%s", out)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncation error must be retryable unexpected EOF, got %T %v", err, err)
	}
	if out != nil {
		t.Errorf("expected nil body on truncation, got %s", out)
	}
}

// TestAccumulateAnthropicSSE_InlineError SSE 内嵌 error 事件 → *UpstreamHTTPError。
func TestAccumulateAnthropicSSE_InlineError(t *testing.T) {
	stream := sseAnthropic(
		[2]string{"message_start", `{"type":"message_start","message":{"id":"m","model":"c","usage":{"input_tokens":1}}}`},
		[2]string{"error", `{"type":"error","error":{"type":"overloaded_error","message":"overloaded"}}`},
	)
	_, err := accumulateAnthropicSSE(strings.NewReader(stream))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	ue := GetUpstreamHTTPError(err)
	if ue == nil {
		t.Fatalf("expected *UpstreamHTTPError, got %T: %v", err, err)
	}
	if !strings.Contains(ue.Message, "overloaded") {
		t.Errorf("error message = %q, want contains 'overloaded'", ue.Message)
	}
}

// TestAnthropicCallStreaming_EndToEnd 经真 HTTP server 跑通 Anthropic SSE 累积,
// 并断言请求被强制改成 stream:true、带 Accept: text/event-stream。
func TestAnthropicCallStreaming_EndToEnd(t *testing.T) {
	var gotBody map[string]interface{}
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, anthropicHappyStream())
		if fl != nil {
			fl.Flush()
		}
	}))
	defer srv.Close()

	a := &AnthropicAdapter{BaseURL: srv.URL, APIKey: "sk-ant"}
	env := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "claude-3"}
	out, err := a.CallStreaming(context.Background(), env, []byte(`{"model":"claude-3","max_tokens":50,"messages":[],"stream":false}`))
	if err != nil {
		t.Fatalf("CallStreaming error: %v", err)
	}

	// 请求侧: stream 被强制改 true; Accept 为 SSE
	if gotBody["stream"] != true {
		t.Errorf("upstream request stream = %v, want true", gotBody["stream"])
	}
	if gotAccept != "text/event-stream" {
		t.Errorf("Accept = %q, want text/event-stream", gotAccept)
	}

	// 返回的是上游原生 Anthropic 格式(由下游 TransformResponse 转), 这里直接断言原生字段
	var anth map[string]interface{}
	if err := json.Unmarshal(out, &anth); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%s", err, out)
	}
	if anth["id"] != "msg_1" {
		t.Errorf("id = %v, want msg_1", anth["id"])
	}
	if _, ok := anth["content"].([]interface{}); !ok {
		t.Errorf("content not an array: %v", anth["content"])
	}
}

// TestAnthropicCallStreaming_HTTPErrorPath 上游非 2xx 首包 → *UpstreamHTTPError。
func TestAnthropicCallStreaming_HTTPErrorPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"slow down"}}`))
	}))
	defer srv.Close()

	a := &AnthropicAdapter{BaseURL: srv.URL, APIKey: "sk-ant"}
	env := &modelrouter.RequestEnvelope{EndpointType: "chat", Model: "claude-3"}
	_, err := a.CallStreaming(context.Background(), env, []byte(`{"model":"claude-3","max_tokens":10,"messages":[]}`))
	if err == nil {
		t.Fatal("expected error")
	}
	ue := GetUpstreamHTTPError(err)
	if ue == nil {
		t.Fatalf("expected *UpstreamHTTPError, got %T", err)
	}
	if ue.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", ue.StatusCode)
	}
}
