package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 现场实测（经网关 /v1/messages 非流式，2026-10-22）：
//
//	模型        | 不带 | disabled | adaptive | adaptive+effort | enabled+budget | between_tools
//	opus-5-5    | 200  | 400      | 200      | 200             | 400            | 400
//	sonnet-5-5  | 200  | 400      | 200      | 200             | 400            | 200
//	haiku-5-5   | 200  | 200      | 200      | 200             | 400            | 400
//
// 下面的期望值就是「改写后发往上游的 thinking / output_config.effort」，
// 每一格都必须落在上表为 200 的格子里。
type thinkingForm struct {
	name string
	// thinking 为空串表示请求里不带 thinking 字段。
	thinking string
	// outputConfig 为空串表示请求里不带 output_config。
	outputConfig string
}

var thinkingForms = []thinkingForm{
	{name: "none"},
	{name: "disabled", thinking: `{"type":"disabled"}`},
	{name: "adaptive", thinking: `{"type":"adaptive"}`},
	{name: "adaptive_effort_high", thinking: `{"type":"adaptive"}`, outputConfig: `{"effort":"high"}`},
	{name: "enabled_budget", thinking: `{"type":"enabled","budget_tokens":8000}`},
	{name: "between_tools", thinking: `{"type":"between_tools"}`},
}

// wantThinking 为空串表示发往上游的请求不应再带 thinking；wantEffort 为空串表示不应有 output_config.effort。
type wantThinking struct{ thinking, effort string }

var nativeThinkingExpectations = map[string]map[string]wantThinking{
	"anthropic/claude-opus-5-5": {
		"none":                 {"", ""},
		"disabled":             {"", ""}, // opus 没有关闭方式：去掉字段
		"adaptive":             {`{"type":"adaptive"}`, ""},
		"adaptive_effort_high": {`{"type":"adaptive"}`, "high"},
		"enabled_budget":       {`{"type":"adaptive"}`, "medium"}, // 8000 -> medium
		"between_tools":        {"", ""},
	},
	"anthropic/claude-sonnet-5-5": {
		"none":                 {"", ""},
		"disabled":             {`{"type":"between_tools"}`, ""},
		"adaptive":             {`{"type":"adaptive"}`, ""},
		"adaptive_effort_high": {`{"type":"adaptive"}`, "high"},
		"enabled_budget":       {`{"type":"adaptive"}`, "medium"},
		"between_tools":        {`{"type":"between_tools"}`, ""},
	},
	"anthropic/claude-haiku-5-5": {
		"none":                 {"", ""},
		"disabled":             {`{"type":"disabled"}`, ""},
		"adaptive":             {`{"type":"adaptive"}`, ""},
		"adaptive_effort_high": {`{"type":"adaptive"}`, "high"},
		"enabled_budget":       {`{"type":"adaptive"}`, "medium"},
		"between_tools":        {`{"type":"disabled"}`, ""}, // haiku 不认 between_tools，按 disabled 处理
	},
}

func nativeThinkingBody(model string, stream bool, form thinkingForm) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `{"model":"logical","max_tokens":16000,"stream":%t,"messages":[{"role":"user","content":"hi <&> 你好"}]`, stream)
	if form.thinking != "" {
		b.WriteString(`,"thinking":` + form.thinking)
	}
	if form.outputConfig != "" {
		b.WriteString(`,"output_config":` + form.outputConfig)
	}
	b.WriteString(`}`)
	return []byte(b.String())
}

const nativeStreamSSE = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n" +
	"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"

// sendNativeThroughAdapter 走真实链路：TransformRequest -> Call/CallStreaming -> httptest 上游，返回上游实际收到的请求体。
func sendNativeThroughAdapter(t *testing.T, model string, stream bool, body []byte) map[string]json.RawMessage {
	t.Helper()
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, nativeStreamSSE)
			return
		}
		_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","content":[]}`)
	}))
	defer server.Close()

	adapter := &AnthropicAdapter{BaseURL: server.URL, APIKey: "provider-key"}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "messages", Model: "logical", UpstreamModelID: model, Streaming: stream}
	payload, err := adapter.TransformRequest(envelope, body)
	if err != nil {
		t.Fatalf("TransformRequest: %v", err)
	}
	if stream {
		_, err = adapter.CallStreaming(context.Background(), envelope, payload)
	} else {
		_, err = adapter.Call(context.Background(), envelope, payload)
	}
	if err != nil {
		t.Fatalf("upstream call: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(received, &fields); err != nil {
		t.Fatalf("upstream body is not JSON: %v: %s", err, received)
	}
	return fields
}

func compactJSON(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	if len(raw) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatalf("compact %s: %v", raw, err)
	}
	return buf.String()
}

func upstreamEffort(t *testing.T, fields map[string]json.RawMessage) string {
	t.Helper()
	if len(fields["output_config"]) == 0 {
		return ""
	}
	var output struct {
		Effort string `json:"effort"`
	}
	if err := json.Unmarshal(fields["output_config"], &output); err != nil {
		t.Fatalf("output_config: %v", err)
	}
	return output.Effort
}

// 三个模型 × 六种 thinking 写法 × 流式/非流式：断言上游实际收到的请求体。
func TestNativeAnthropicThinkingCompatMatrix(t *testing.T) {
	for model, expectations := range nativeThinkingExpectations {
		for _, stream := range []bool{false, true} {
			for _, form := range thinkingForms {
				want, ok := expectations[form.name]
				if !ok {
					t.Fatalf("missing expectation %s/%s", model, form.name)
				}
				t.Run(fmt.Sprintf("%s/stream=%t/%s", model, stream, form.name), func(t *testing.T) {
					fields := sendNativeThroughAdapter(t, model, stream, nativeThinkingBody(model, stream, form))
					if got := compactJSON(t, fields["thinking"]); got != want.thinking {
						t.Fatalf("thinking = %q, want %q", got, want.thinking)
					}
					if got := upstreamEffort(t, fields); got != want.effort {
						t.Fatalf("output_config.effort = %q, want %q", got, want.effort)
					}
					// 改写只动 thinking / output_config，其余字段必须原样保留。
					if !sameJSON(t, string(fields["messages"]), `[{"role":"user","content":"hi <&> 你好"}]`) {
						t.Fatalf("messages changed: %s", fields["messages"])
					}
					if string(fields["max_tokens"]) != "16000" {
						t.Fatalf("max_tokens changed: %s", fields["max_tokens"])
					}
				})
			}
		}
	}
}

func transformNativeForTest(t *testing.T, model string, body string) map[string]any {
	t.Helper()
	got, err := (&AnthropicAdapter{}).TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "messages", Model: "logical", UpstreamModelID: model}, []byte(body))
	if err != nil {
		t.Fatalf("TransformRequest(%s): %v", model, err)
	}
	var request map[string]any
	if err := json.Unmarshal(got, &request); err != nil {
		t.Fatalf("decode: %v: %s", err, got)
	}
	return request
}

func TestNativeAnthropicThinkingBudgetMapsToEffortThresholds(t *testing.T) {
	cases := []struct {
		budget int
		want   string
	}{
		{1024, "low"}, {4095, "low"}, {4096, "medium"}, {16383, "medium"}, {16384, "high"}, {63999, "high"},
	}
	for _, tc := range cases {
		body := fmt.Sprintf(`{"model":"x","max_tokens":128000,"messages":[],"thinking":{"type":"enabled","budget_tokens":%d}}`, tc.budget)
		request := transformNativeForTest(t, "claude-opus-5-5", body)
		output, _ := request["output_config"].(map[string]any)
		if output["effort"] != tc.want {
			t.Errorf("budget %d -> effort %v, want %s", tc.budget, output["effort"], tc.want)
		}
		thinking, _ := request["thinking"].(map[string]any)
		if thinking["type"] != "adaptive" || thinking["budget_tokens"] != nil {
			t.Errorf("budget %d -> thinking %v", tc.budget, thinking)
		}
	}
}

func TestNativeAnthropicThinkingKeepsClientEffortAndOtherFields(t *testing.T) {
	body := `{"model":"x","max_tokens":16000,"messages":[],"thinking":{"type":"enabled","budget_tokens":2000,"display":"summarized"},"output_config":{"effort":"max","format":{"type":"json_schema"}}}`
	request := transformNativeForTest(t, "claude-sonnet-5-5", body)
	output, _ := request["output_config"].(map[string]any)
	if output["effort"] != "max" || output["format"] == nil {
		t.Fatalf("客户端已带的 effort/format 不得被覆盖: %v", output)
	}
	thinking, _ := request["thinking"].(map[string]any)
	if thinking["type"] != "adaptive" || thinking["display"] != "summarized" || thinking["budget_tokens"] != nil {
		t.Fatalf("thinking 其余字段（display）应保留、budget_tokens 应删除: %v", thinking)
	}
}

func TestNativeAnthropicThinkingRewriteStillFitsOutputLimit(t *testing.T) {
	// 客户端把 max_tokens 和预算都放得很大：改写成 adaptive 后不能残留 budget_tokens，max_tokens 仍被收紧到模型上限。
	body := `{"model":"x","max_tokens":200000,"messages":[],"thinking":{"type":"enabled","budget_tokens":180000}}`
	request := transformNativeForTest(t, "anthropic/claude-opus-5-5", body)
	thinking, _ := request["thinking"].(map[string]any)
	if request["max_tokens"] != float64(128000) || thinking["type"] != "adaptive" || thinking["budget_tokens"] != nil {
		t.Fatalf("max_tokens/thinking 约束不成立: %v", request)
	}
	output, _ := request["output_config"].(map[string]any)
	if output["effort"] != "high" {
		t.Fatalf("180000 应映射为 high: %v", output)
	}
}

func TestNativeAnthropicThinkingOtherModelFamilies(t *testing.T) {
	cases := []struct {
		model    string
		thinking string
		want     string
	}{
		// Opus 4.6/4.7/4.8：官方文档写明接受 disabled（现场只实测了 5.5 系），保持原样；between_tools 只有 Sonnet 5.5 认。
		{"claude-opus-4-8", `{"type":"disabled"}`, `{"type":"disabled"}`},
		{"us.anthropic.claude-opus-4-7-v1:0", `{"type":"between_tools"}`, `{"type":"disabled"}`},
		{"claude-opus-4-6", `{"type":"disabled"}`, `{"type":"disabled"}`},
		// Opus 4.8/4.7 不认 budget_tokens；4.6 仍可用（已弃用但未移除），不改写。
		{"claude-opus-4-8", `{"type":"enabled","budget_tokens":8000}`, `{"type":"adaptive"}`},
		{"claude-opus-4-6", `{"type":"enabled","budget_tokens":8000}`, `{"type":"enabled","budget_tokens":8000}`},
		// Sonnet 5 / Opus 5 的 disabled 是官方支持的关闭方式，保持原样；between_tools 只有 Sonnet 5.5 认。
		{"claude-sonnet-5", `{"type":"disabled"}`, `{"type":"disabled"}`},
		{"claude-sonnet-5", `{"type":"between_tools"}`, `{"type":"disabled"}`},
		{"claude-opus-5", `{"type":"disabled"}`, `{"type":"disabled"}`},
		// Fable/Mythos 思考常开：任何关闭写法都去掉。
		{"claude-fable-5-1", `{"type":"disabled"}`, ""},
		// 老一代只认 enabled+budget_tokens：enabled 不动，between_tools 降为 disabled。
		{"claude-haiku-4-5", `{"type":"enabled","budget_tokens":2000}`, `{"type":"enabled","budget_tokens":2000}`},
		{"claude-haiku-4-5", `{"type":"between_tools"}`, `{"type":"disabled"}`},
		// 表外/未知模型：一律不改写。
		{"claude-foo-native", `{"type":"enabled","budget_tokens":2000}`, `{"type":"enabled","budget_tokens":2000}`},
		{"claude-foo-native", `{"type":"disabled"}`, `{"type":"disabled"}`},
		{"claude-foo-native", `{"type":"between_tools"}`, `{"type":"between_tools"}`},
		{"private-alias", `{"type":"disabled"}`, `{"type":"disabled"}`},
	}
	for _, tc := range cases {
		body := `{"model":"x","max_tokens":16000,"messages":[],"thinking":` + tc.thinking + `}`
		request := transformNativeForTest(t, tc.model, body)
		got := ""
		if thinking, ok := request["thinking"]; ok {
			raw, _ := json.Marshal(thinking)
			got = string(raw)
		}
		// 比较时忽略 JSON 键序
		if !sameJSON(t, got, tc.want) {
			t.Errorf("%s: %s -> %q, want %q", tc.model, tc.thinking, got, tc.want)
		}
	}
}

func sameJSON(t *testing.T, a, b string) bool {
	t.Helper()
	if a == "" || b == "" {
		return a == b
	}
	var left, right any
	if json.Unmarshal([]byte(a), &left) != nil || json.Unmarshal([]byte(b), &right) != nil {
		return a == b
	}
	l, _ := json.Marshal(left)
	r, _ := json.Marshal(right)
	return string(l) == string(r)
}

func TestNativeAnthropicThinkingUnchangedWhenNothingToRewrite(t *testing.T) {
	for _, body := range []string{
		`{ "model": "claude-opus-5-5", "max_tokens": 4000, "messages": [] }`,
		`{ "model": "claude-opus-5-5", "max_tokens": 4000, "messages": [], "thinking": {"type":"adaptive"} }`,
		`{ "model": "claude-opus-5-5", "max_tokens": 4000, "messages": [], "thinking": null }`,
		`{ "model": "claude-opus-5-5", "max_tokens": 4000, "messages": [], "thinking": "weird" }`,
		`{ "model": "claude-opus-5-5", "max_tokens": 4000, "messages": [], "thinking": {"type":"future_mode"} }`,
		`{ "model": "private-alias", "max_tokens": 4000, "messages": [], "thinking": {"type":"enabled","budget_tokens":2000} }`,
	} {
		got, err := (&AnthropicAdapter{}).TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "messages", Model: "claude-opus-5-5"}, []byte(body))
		if err != nil || string(got) != body {
			t.Errorf("无需改写时必须逐字节原样返回:\n got=%s err=%v\nwant=%s", got, err, body)
		}
	}
}

func TestNativeAnthropicThinkingRewriteLogsOnlyModelAndKind(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)

	body := `{"model":"x","max_tokens":16000,"messages":[{"role":"user","content":"SECRET-PROMPT-TEXT"}],"thinking":{"type":"enabled","budget_tokens":8000}}`
	_, err := (&AnthropicAdapter{}).TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "messages", Model: "logical", UpstreamModelID: "anthropic/claude-sonnet-5-5", RequestID: "req-thinking-1"}, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	logged := logs.String()
	for _, want := range []string{"native_thinking_rewrite", "model=claude-sonnet-5-5", "kind=enabled_to_adaptive"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("日志缺少 %q: %s", want, logged)
		}
	}
	if strings.Contains(logged, "SECRET-PROMPT-TEXT") || strings.Contains(logged, "budget") {
		t.Fatalf("日志不得包含请求内容: %s", logged)
	}

	logs.Reset()
	_, _ = (&AnthropicAdapter{}).TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "messages", Model: "claude-sonnet-5-5"}, []byte(`{"model":"x","max_tokens":16000,"messages":[],"thinking":{"type":"adaptive"}}`))
	if strings.Contains(logs.String(), "native_thinking_rewrite") {
		t.Fatalf("没有发生改写时不应记日志: %s", logs.String())
	}
}

// 以表格形式输出最终能力表（go test -run TestNativeAnthropicThinkingCapabilityTable -v），同时断言每个已知模型的行为稳定。
func TestNativeAnthropicThinkingCapabilityTable(t *testing.T) {
	models := []string{
		"claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6", "claude-opus-5-5", "claude-opus-5",
		"claude-sonnet-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1",
	}
	for _, model := range models {
		var cells []string
		for _, form := range thinkingForms {
			request := transformNativeForTest(t, model, string(nativeThinkingBody(model, false, form)))
			cell := "-"
			if thinking, ok := request["thinking"]; ok {
				raw, _ := json.Marshal(thinking)
				cell = strings.NewReplacer(`"`, "", `type:`, "").Replace(string(raw))
			}
			if output, ok := request["output_config"].(map[string]any); ok && output["effort"] != nil {
				cell += "+effort=" + fmt.Sprint(output["effort"])
			}
			cells = append(cells, form.name+"=>"+cell)
		}
		t.Logf("%-18s %s", model, strings.Join(cells, " | "))
	}
}

// Sonnet 5.5 的 between_tools 只在 effort high 及以下可用（xhigh/max 同样 400），
// 所以 disabled 遇到 xhigh/max 时只能省略 thinking，让模型走默认 adaptive。
func TestNativeAnthropicThinkingSonnet55DisabledDependsOnEffort(t *testing.T) {
	cases := []struct{ outputConfig, want string }{
		{``, `{"type":"between_tools"}`},
		{`,"output_config":{"effort":"low"}`, `{"type":"between_tools"}`},
		{`,"output_config":{"effort":"HIGH"}`, `{"type":"between_tools"}`},
		{`,"output_config":{"effort":"xhigh"}`, ""},
		{`,"output_config":{"effort":"max"}`, ""},
	}
	for _, tc := range cases {
		body := `{"model":"x","max_tokens":16000,"messages":[],"thinking":{"type":"disabled"}` + tc.outputConfig + `}`
		request := transformNativeForTest(t, "claude-sonnet-5-5", body)
		got := ""
		if thinking, ok := request["thinking"]; ok {
			raw, _ := json.Marshal(thinking)
			got = string(raw)
		}
		if !sameJSON(t, got, tc.want) {
			t.Errorf("%q -> %q, want %q", tc.outputConfig, got, tc.want)
		}
		if output, _ := request["output_config"].(map[string]any); tc.outputConfig != "" && output["effort"] == nil {
			t.Errorf("客户端的 effort 不得被丢弃: %v", request["output_config"])
		}
	}
}

// 原生客户端的工具定义是它与 Anthropic API 之间的契约：thinking 改写不得碰 tools（包括 strict 与 maxItems/minItems）。
func TestNativeAnthropicThinkingRewriteLeavesToolsUntouched(t *testing.T) {
	tools := `[{"name":"lookup","strict":true,"input_schema":{"type":"object","additionalProperties":false,"properties":{"rows":{"type":"array","maxItems":2,"minItems":1,"items":{"type":"integer","minimum":1}}}}},{"name":"plain","input_schema":{"type":"object","properties":{"maxItems":{"type":"integer"}}}}]`
	body := `{"model":"x","max_tokens":16000,"messages":[],"tools":` + tools + `,"thinking":{"type":"enabled","budget_tokens":8000}}`
	request := transformNativeForTest(t, "claude-opus-5-5", body)
	if thinking, _ := request["thinking"].(map[string]any); thinking["type"] != "adaptive" {
		t.Fatalf("前置条件：thinking 应已被改写: %v", request["thinking"])
	}
	raw, _ := json.Marshal(request["tools"])
	if !sameJSON(t, string(raw), tools) {
		t.Fatalf("tools 被改动:\n got=%s\nwant=%s", raw, tools)
	}
}

func TestNativeAnthropicThinkingEnabledWithoutBudgetOrWithOddOutputConfig(t *testing.T) {
	// enabled 但没带预算：只改 type，不凭空发明 effort。
	request := transformNativeForTest(t, "claude-opus-5-5", `{"model":"x","max_tokens":16000,"messages":[],"thinking":{"type":"enabled"}}`)
	if thinking, _ := request["thinking"].(map[string]any); thinking["type"] != "adaptive" {
		t.Fatalf("thinking=%v", request["thinking"])
	}
	if request["output_config"] != nil {
		t.Fatalf("没有预算时不应补 effort: %v", request["output_config"])
	}
	// output_config 不是对象：不碰它，交给上游报它自己的错误。
	request = transformNativeForTest(t, "claude-opus-5-5", `{"model":"x","max_tokens":16000,"messages":[],"thinking":{"type":"enabled","budget_tokens":8000},"output_config":"weird"}`)
	if request["output_config"] != "weird" {
		t.Fatalf("非对象 output_config 被改动: %v", request["output_config"])
	}
}

// 实时流式（OpenStream）路径：上游 4xx 的正文与白名单头必须完整保留在 UpstreamHTTPError 里，
// 这样 handler 才能把净化后的 message 透传给客户端。（特征测试：固化既有行为，防止以后改坏。）
func TestNativeAnthropicOpenStreamKeepsUpstream4xxBody(t *testing.T) {
	raw := `{"type":"error","error":{"type":"invalid_request_error","message":"\"thinking.type.enabled\" is not supported for this model."}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Anthropic-Request-Id", "req_up_stream")
		w.Header().Set("Set-Cookie", "must-not-pass=1")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, raw)
	}))
	defer server.Close()

	adapter := &AnthropicAdapter{BaseURL: server.URL, APIKey: "provider-key"}
	envelope := &modelrouter.RequestEnvelope{EndpointType: "messages", Model: "logical", Streaming: true}
	_, meta, err := adapter.OpenStream(context.Background(), envelope, []byte(`{"model":"claude-opus-5-5","stream":true,"messages":[]}`))
	upstreamErr := GetUpstreamHTTPError(err)
	if upstreamErr == nil || upstreamErr.StatusCode != http.StatusBadRequest || string(upstreamErr.Body) != raw {
		t.Fatalf("error=%T %v", err, err)
	}
	if meta.StatusCode != http.StatusBadRequest {
		t.Fatalf("meta.StatusCode=%d", meta.StatusCode)
	}
	if upstreamErr.Headers.Get("Anthropic-Request-Id") != "req_up_stream" || upstreamErr.Headers.Get("Set-Cookie") != "" {
		t.Fatalf("headers=%v", upstreamErr.Headers)
	}
}
