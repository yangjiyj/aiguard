package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

// 本文件验证 Chat -> Anthropic Messages 路径预占估算偏低的根因与修复，见 chat_estimate_anthropic.go。
//
// "actual" 的口径与局限（务必先读）：
//   - 真实 actual 来自 Anthropic 的 usage（input_tokens + cache_read + cache_creation + output_tokens），
//     由 Claude 分词器计数。仓库里没有该分词器，测试环境也不能联网调用 count_tokens，所以这里用
//     refTokens 模拟：ASCII 每 2.4 字节 1 token、其余字符每个 1.9 token。
//   - 这组常数是用客户现场 6 组 (estimated, actual) 反推的（扣除输出预留后 actual/输入估算 ≈ 1.20~1.25），
//     所以"修复后比值落在区间内"在数值上有循环成分，证明不了估算与真实 Claude 计数一致。
//     测试真正能证明的是：①转换没有新增可观的输入（转换前后用同一计数器比较，与校准无关）；
//     ②缓存 token 已经在 actual 的输入总量里（走真实的 TransformResponse + 计费规范化）；
//     ③系数只作用于 Chat+Anthropic 路径，且接进了真实的准入链路；
//     ④修复前该合成场景确实偏低（防止测试永远通过）。
//   - 未验证：与真实 Anthropic count_tokens 的逐条差距。上线后用 reservation_overrun 聚合通知里的
//     max_estimated / max_actual 复核。

func refTokens(text string) float64 {
	var ascii, other float64
	for _, r := range text {
		if r < 0x80 {
			ascii++
		} else {
			other++
		}
	}
	return ascii/2.4 + other*1.9
}

type conversationMix struct {
	name  string
	user  func(i int) string
	reply func(i int) string
	tool  func(i int) string
	args  func(i int) string
}

func cjkMix() conversationMix {
	return conversationMix{
		name: "中文为主",
		user: func(i int) string {
			return fmt.Sprintf("第%d轮：请继续分析上一步的日志，并说明为什么额度预占会比实际用量低，需要给出依据和可复现的步骤。", i) + strings.Repeat("补充背景：客户现场网关的结算与预占口径需要保持一致。", 6)
		},
		reply: func(i int) string {
			return fmt.Sprintf("好的，第%d轮的结论如下。", i) + strings.Repeat("估算是启发式的，没有按当前分词器校准，所以长对话里偏差会稳定地累积。", 8)
		},
		tool: func(i int) string {
			return strings.Repeat(`{"路径":"/var/log/网关/请求.log","行":`+fmt.Sprint(i)+`,"内容":"预占超出告警，结算已按实际用量入账"}`+"\n", 10)
		},
		args: func(i int) string {
			return fmt.Sprintf(`{"path":"/tmp/报告-%d.md","content":"%s"}`, i, strings.Repeat("写入说明。", 20))
		},
	}
}

func codeMix() conversationMix {
	return conversationMix{
		name: "代码为主",
		user: func(i int) string {
			return fmt.Sprintf("round %d: please refactor the following function and keep behaviour identical.\n", i) + strings.Repeat("func handle(w http.ResponseWriter, r *http.Request) { if err := process(r.Context()); err != nil { http.Error(w, err.Error(), 500) } }\n", 8)
		},
		reply: func(i int) string {
			return fmt.Sprintf("Here is the refactored version for round %d:\n", i) + strings.Repeat("if err != nil { return fmt.Errorf(\"step %d: %w\", i, err) }\n", 12)
		},
		tool: func(i int) string {
			return strings.Repeat(fmt.Sprintf(`{"file":"internal/handler/x_%d.go","line":%d,"snippet":"return nil, errors.New(\"unexpected state\")"}`, i, i*7)+"\n", 10)
		},
		args: func(i int) string {
			return fmt.Sprintf(`{"path":"internal/handler/x_%d.go","patch":"%s"}`, i, strings.Repeat("@@ -1,3 +1,3 @@\\n-old line\\n+new line\\n", 8))
		},
	}
}

func mixedMix() conversationMix {
	cjk, code := cjkMix(), codeMix()
	pick := func(i int, a, b func(int) string) string {
		if i%2 == 0 {
			return a(i)
		}
		return b(i)
	}
	return conversationMix{
		name:  "中英混合",
		user:  func(i int) string { return pick(i, cjk.user, code.user) },
		reply: func(i int) string { return pick(i, cjk.reply, code.reply) },
		tool:  func(i int) string { return pick(i, cjk.tool, code.tool) },
		args:  func(i int) string { return pick(i, cjk.args, code.args) },
	}
}

// buildLongChatConversation 构造一个多轮长对话（含系统提示、tools 定义、assistant tool_calls 历史与 tool 结果）。
func buildLongChatConversation(mix conversationMix, turns int) map[string]any {
	messages := []any{map[string]any{"role": "system", "content": strings.Repeat("你是一名资深的网关工程师，回答要有依据、可复现。 You must cite code locations. ", 60)}}
	for i := 1; i <= turns; i++ {
		callID := fmt.Sprintf("call_%d", i)
		messages = append(messages,
			map[string]any{"role": "user", "content": mix.user(i)},
			map[string]any{"role": "assistant", "content": mix.reply(i), "tool_calls": []any{map[string]any{
				"id": callID, "type": "function", "function": map[string]any{"name": "write_file", "arguments": mix.args(i)},
			}}},
			map[string]any{"role": "tool", "tool_call_id": callID, "content": mix.tool(i)},
		)
	}
	messages = append(messages, map[string]any{"role": "user", "content": "请给出最终结论。"})
	tools := make([]any, 0, 6)
	for _, name := range []string{"write_file", "read_file", "run_tests", "search_code", "apply_patch", "list_dir"} {
		tools = append(tools, map[string]any{"type": "function", "function": map[string]any{
			"name": name, "description": "工具 " + name + "：" + strings.Repeat("执行对应操作并返回结果，参数必须是合法 JSON。 ", 6),
			"parameters": map[string]any{"type": "object", "properties": map[string]any{
				"path":    map[string]any{"type": "string", "description": "文件路径"},
				"content": map[string]any{"type": "string", "description": "文件内容"},
			}, "required": []any{"path"}},
		}})
	}
	return map[string]any{"model": "claude-opus-5", "messages": messages, "tools": tools, "stream": true, "max_tokens": 4096}
}

func estMustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// refChatTokens 用同一个计数器统计转换前的 Chat 请求。
func refChatTokens(body map[string]any) float64 {
	var total float64
	for _, raw := range body["messages"].([]any) {
		message := raw.(map[string]any)
		total += 4
		if text, ok := message["content"].(string); ok {
			total += refTokens(text)
		}
		for _, rawCall := range anyList(message["tool_calls"]) {
			function := rawCall.(map[string]any)["function"].(map[string]any)
			total += 4 + refTokens(function["name"].(string)) + refTokens(function["arguments"].(string))
		}
	}
	for _, rawTool := range anyList(body["tools"]) {
		function := rawTool.(map[string]any)["function"].(map[string]any)
		schema, _ := json.Marshal(function["parameters"])
		total += 8 + refTokens(function["name"].(string)) + refTokens(function["description"].(string)) + refTokens(string(schema))
	}
	return total
}

func anyList(value any) []any {
	list, _ := value.([]any)
	return list
}

// refAnthropicTokens 用同一个计数器统计转换后的 Anthropic Messages 请求体（实际发给上游的内容）。
func refAnthropicTokens(t *testing.T, converted []byte) float64 {
	t.Helper()
	var request map[string]any
	if err := json.Unmarshal(converted, &request); err != nil {
		t.Fatal(err)
	}
	var total float64
	switch system := request["system"].(type) {
	case string:
		total += 4 + refTokens(system)
	case []any:
		for _, block := range system {
			total += 4 + refTokens(block.(map[string]any)["text"].(string))
		}
	}
	for _, rawMessage := range anyList(request["messages"]) {
		message := rawMessage.(map[string]any)
		total += 4
		switch content := message["content"].(type) {
		case string:
			total += refTokens(content)
		case []any:
			for _, rawBlock := range content {
				block := rawBlock.(map[string]any)
				switch block["type"] {
				case "text":
					total += refTokens(block["text"].(string))
				case "tool_use":
					input, _ := json.Marshal(block["input"])
					total += 4 + refTokens(block["name"].(string)) + refTokens(string(input))
				case "tool_result":
					total += 4
					switch result := block["content"].(type) {
					case string:
						total += refTokens(result)
					case []any:
						for _, part := range result {
							total += refTokens(part.(map[string]any)["text"].(string))
						}
					}
				}
			}
		}
	}
	for _, rawTool := range anyList(request["tools"]) {
		tool := rawTool.(map[string]any)
		schema, _ := json.Marshal(tool["input_schema"])
		description, _ := tool["description"].(string)
		total += 8 + refTokens(tool["name"].(string)) + refTokens(description) + refTokens(string(schema))
	}
	return total
}

func convertChatForAnthropic(t *testing.T, body []byte) []byte {
	t.Helper()
	adapter := &provider.AnthropicAdapter{}
	converted, err := adapter.TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "chat", Model: "claude-opus-5", Provider: "anthropic"}, body)
	if err != nil {
		t.Fatalf("chat -> messages 转换失败: %v", err)
	}
	return converted
}

func typedChatRequest(t *testing.T, body []byte) *ChatCompletionRequest {
	t.Helper()
	var request ChatCompletionRequest
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	return &request
}

// 证据 1：转换本身没有新增可观的输入内容（排除"估算在转换前、转换后多了内容"这一候选根因）。
// 转换前后用同一个计数器比较，结果与校准常数无关；cache_control 标记不产生输入 token，这里也不计。
func TestChatToAnthropicConversionDoesNotAddMaterialInput(t *testing.T) {
	for _, mix := range []conversationMix{cjkMix(), codeMix(), mixedMix()} {
		t.Run(mix.name, func(t *testing.T) {
			body := estMustJSON(t, buildLongChatConversation(mix, 40))
			var parsed map[string]any
			_ = json.Unmarshal(body, &parsed)
			before := refChatTokens(parsed)
			converted := convertChatForAnthropic(t, body)
			if !bytes.Contains(converted, []byte(`"cache_control"`)) {
				t.Fatal("转换结果应带自动加的 cache_control 断点（本测试要覆盖它不增加输入的结论）")
			}
			after := refAnthropicTokens(t, converted)
			ratio := after / before
			t.Logf("转换前 %.0f，转换后 %.0f，比值 %.4f", before, after, ratio)
			if ratio < 0.97 || ratio > 1.05 {
				t.Fatalf("转换前后输入量差异 %.1f%% 超出 [-3%%, +5%%]，说明转换新增/丢失了大量内容", (ratio-1)*100)
			}
		})
	}
}

// 证据 2：缓存 token 已经在 actual 的输入总量里。
// 走真实的 AnthropicAdapter.TransformResponse（Anthropic usage -> Chat usage）和计费规范化，
// actual 的 prompt = input_tokens + cache_read + cache_creation，估算的对象本来就是这个总量。
func TestAnthropicUsageCacheTokensAreInsidePromptTotal(t *testing.T) {
	upstream := []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5",` +
		`"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn",` +
		`"usage":{"input_tokens":1200,"cache_read_input_tokens":80000,"cache_creation_input_tokens":5000,"output_tokens":300}}`)
	chatBody, err := (&provider.AnthropicAdapter{}).TransformResponse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	prompt, completion, state := responseUsageTokenState(chatBody)
	if state != "upstream" && state != "upstream_total_adjusted" {
		t.Fatalf("usage 状态=%q", state)
	}
	if prompt != 86200 || completion != 300 {
		t.Fatalf("prompt=%d completion=%d，want 86200(=1200+80000+5000) / 300", prompt, completion)
	}
}

// 证据 3 + 修复验证：多轮长对话走真实的 chat->messages 转换，估算相对 actual 的比值。
func TestChatAdmissionEstimateTracksAnthropicActualOnLongConversation(t *testing.T) {
	const completionTokens = 350
	for _, mix := range []conversationMix{cjkMix(), codeMix(), mixedMix()} {
		for _, turns := range []int{40, 60, 80} {
			t.Run(fmt.Sprintf("%s/%d轮", mix.name, turns), func(t *testing.T) {
				body := estMustJSON(t, buildLongChatConversation(mix, turns))
				request := typedChatRequest(t, body)
				actualPrompt := refAnthropicTokens(t, convertChatForAnthropic(t, body))
				if actualPrompt < 30000 {
					t.Fatalf("构造的对话只有 %.0f token，需要 >= 30000 才能代表长对话（输出预留占比才可忽略）", actualPrompt)
				}
				actual := actualPrompt + completionTokens

				before := float64(estimatedChatAdmissionTokens(request)) / actual
				permille := chatAdmissionPromptPermille(
					&modelrouter.RequestEnvelope{EndpointType: "chat", Provider: "anthropic", UpstreamProtocol: "messages"}, nil)
				after := float64(estimatedChatAdmissionTokensScaled(request, permille)) / actual
				t.Logf("prompt actual=%.0f  修复前 est/actual=%.3f  修复后 est/actual=%.3f (系数=%d‰)", actualPrompt, before, after, permille)

				if before >= 0.95 {
					t.Fatalf("修复前比值 %.3f 已不低于 0.95，说明这个合成场景没有复现偏低，测试没有鉴别力", before)
				}
				if after < 0.95 || after > 1.30 {
					t.Fatalf("修复后 est/actual=%.3f，want 在 [0.95, 1.30]", after)
				}
			})
		}
	}
}

// 系数只作用于 Chat 入口 + Anthropic Messages 上游；其他入口/协议估算不变，输出预留不被放大。
func TestChatAdmissionPermilleOnlyAppliesToChatToAnthropic(t *testing.T) {
	cases := []struct {
		name     string
		envelope *modelrouter.RequestEnvelope
		record   *modelrouter.ModelRecord
		want     int64
	}{
		{"nil", nil, nil, 1000},
		{"chat+anthropic供应商", &modelrouter.RequestEnvelope{EndpointType: "chat", Provider: "anthropic"}, nil, 1250},
		{"chat+已确定上游为messages", &modelrouter.RequestEnvelope{EndpointType: "chat", Provider: "custom", UpstreamProtocol: "messages"}, nil, 1250},
		{"chat+Claude桥接(openai类型供应商+显式messages能力)", &modelrouter.RequestEnvelope{EndpointType: "chat", Provider: "openai"},
			&modelrouter.ModelRecord{ProviderType: "openai", ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true}}, 1250},
		{"chat+openai上游不放大", &modelrouter.RequestEnvelope{EndpointType: "chat", Provider: "openai", UpstreamProtocol: "chat"}, nil, 1000},
		{"原生messages入口不放大", &modelrouter.RequestEnvelope{EndpointType: "messages", Provider: "anthropic", UpstreamProtocol: "messages"}, nil, 1000},
		{"responses入口不放大", &modelrouter.RequestEnvelope{EndpointType: "responses", Provider: "anthropic"}, nil, 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := chatAdmissionPromptPermille(tc.envelope, tc.record); got != tc.want {
				t.Fatalf("系数=%d want %d", got, tc.want)
			}
		})
	}

	request := &ChatCompletionRequest{MaxTokens: 8000, Messages: []Message{{Role: "user", Content: jsonQuote(strings.Repeat("a", 3000))}}}
	base, scaled := estimatedChatAdmissionTokensScaled(request, 1000), estimatedChatAdmissionTokensScaled(request, 1250)
	prompt := estimateChatPromptTokens(request)
	if base != prompt+8000 {
		t.Fatalf("系数 1000 必须与旧行为一致: %d vs %d", base, prompt+8000)
	}
	if want := int64(math.Ceil(float64(prompt)*1.25)) + 8000; scaled != want {
		t.Fatalf("只放大输入、不放大输出预留: got %d want %d", scaled, want)
	}
	if got := scaleEstimatePermille(maxExactTokenCount, 2000); got != maxExactTokenCount {
		t.Fatalf("放大必须在 maxExactTokenCount 饱和: %d", got)
	}
}

func TestAnthropicChatEstimatePermilleEnvOverride(t *testing.T) {
	for raw, want := range map[string]int64{"": 1250, "1000": 1000, "1100": 1100, "900": 1000, "5000": 2000, "abc": 1250} {
		t.Setenv(anthropicChatEstimatePermilleEnv, raw)
		if got := anthropicChatEstimatePermille(); got != want {
			t.Fatalf("env=%q 系数=%d want %d", raw, got, want)
		}
	}
}

// 端到端：真实的 ChatCompletionsHandler 准入链路。供应商类型 anthropic，上游返回用真实转换体算出来的 usage，
// 断言交给准入的预占量与结算 actual 的比值，以及关闭开关后回到旧行为。
func TestChatHandlerAdmissionReservationMatchesAnthropicUsage(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	body := estMustJSON(t, func() map[string]any {
		conversation := buildLongChatConversation(mixedMix(), 60)
		conversation["stream"] = false
		return conversation
	}())
	actualPrompt := int64(math.Round(refAnthropicTokens(t, convertChatForAnthropic(t, body))))
	response := estMustJSON(t, map[string]any{
		"id": "chatcmpl-x", "object": "chat.completion", "model": "claude-opus-5",
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": "结论"}, "finish_reason": "stop"}},
		"usage":   map[string]any{"prompt_tokens": actualPrompt, "completion_tokens": 350, "total_tokens": actualPrompt + 350},
	})

	run := func(t *testing.T) (estimated, actual int64) {
		admission := &recordingEntrypointQuotaAdmission{}
		audit := &RealAuditWriter{db: &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}}
		caller := &MockProviderCaller{CallResponse: response}
		resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
			ID: "model-claude", ProviderID: "provider-claude", ModelName: "claude-opus-5", ProviderType: "anthropic",
			ProviderBaseURL: "https://anthropic.example", Status: "active",
			ProtocolCapabilities: modelrouter.ProtocolCapabilities{Explicit: true, AnthropicMessages: true, ChatCompletions: true},
		}}
		h := NewChatCompletionsHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit,
			&MockProviderAdapterFactory{MockProviderCaller: caller}, nil, nil)
		h.SetQuotaAdmission(admission)
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
		recorder := httptest.NewRecorder()
		h.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		admission.mu.Lock()
		requests := append([]governor.AdmissionRequest(nil), admission.requests...)
		admission.mu.Unlock()
		calls := admission.terminalCalls()
		if len(requests) != 1 || len(calls) != 1 || !calls[0].settle {
			t.Fatalf("requests=%d terminal=%+v", len(requests), calls)
		}
		return requests[0].EstimatedTokens, calls[0].actual
	}

	t.Run("修复后", func(t *testing.T) {
		estimated, actual := run(t)
		if actual != actualPrompt+350 {
			t.Fatalf("结算 actual=%d want %d（计费口径不得改变）", actual, actualPrompt+350)
		}
		ratio := float64(estimated) / float64(actual)
		t.Logf("预占=%d 实际=%d 比值=%.3f", estimated, actual, ratio)
		if ratio < 0.95 || ratio > 1.30 {
			t.Fatalf("est/actual=%.3f want [0.95,1.30]", ratio)
		}
	})
	t.Run("开关关闭回到旧行为", func(t *testing.T) {
		t.Setenv(anthropicChatEstimatePermilleEnv, "1000")
		estimated, actual := run(t)
		ratio := float64(estimated) / float64(actual)
		t.Logf("预占=%d 实际=%d 比值=%.3f", estimated, actual, ratio)
		if ratio >= 0.95 {
			t.Fatalf("关闭系数后应复现旧的偏低（比值 %.3f）", ratio)
		}
		if actual != actualPrompt+350 {
			t.Fatalf("关闭系数不得影响结算 actual: %d", actual)
		}
	})
}
