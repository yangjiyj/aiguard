package handler

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

func TestCapJSONOutputTokensOnlyTightens(t *testing.T) {
	body := []byte(`{"model":"m","max_output_tokens":30,"input":"x"}`)
	out, changed, err := capResponsesRequestOutputTokens(body, 60)
	if err != nil || changed || string(out) != string(body) {
		t.Fatalf("smaller client value must be kept byte-for-byte: changed=%v out=%s err=%v", changed, out, err)
	}
	out, changed, _ = capResponsesRequestOutputTokens([]byte(`{"model":"m","input":"x"}`), 60)
	var decoded map[string]any
	_ = json.Unmarshal(out, &decoded)
	if changed || decoded["max_output_tokens"] != nil {
		t.Fatalf("客户端未设置上限时不得注入: %s", out)
	}
}

// Anthropic 扩展思考：budget_tokens 必须小于 max_tokens；收紧后放不下 1024 时关闭 thinking。
func TestCapMessagesRequestKeepsThinkingBudgetValid(t *testing.T) {
	out, _, err := capMessagesRequestOutputTokens([]byte(`{"model":"c","max_tokens":20000,"thinking":{"type":"enabled","budget_tokens":16000},"messages":[]}`), 4000)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	_ = json.Unmarshal(out, &decoded)
	thinking, _ := decoded["thinking"].(map[string]any)
	if decoded["max_tokens"] != float64(4000) || thinking["budget_tokens"] != float64(3999) {
		t.Fatalf("budget_tokens must stay below max_tokens: %s", out)
	}
	out, _, _ = capMessagesRequestOutputTokens([]byte(`{"model":"c","max_tokens":20000,"thinking":{"type":"enabled","budget_tokens":16000},"messages":[]}`), 500)
	decoded = nil
	_ = json.Unmarshal(out, &decoded)
	if decoded["max_tokens"] != float64(500) || decoded["thinking"] != nil {
		t.Fatalf("thinking that cannot fit must be disabled: %s", out)
	}
}

func TestCapChatRequestTightensStructAndBody(t *testing.T) {
	req := &ChatCompletionRequest{MaxTokens: 1000}
	out, changed, err := capChatRequestOutputTokens(req, []byte(`{"model":"m","max_tokens":1000,"messages":[]}`), "custom", 60)
	var decoded map[string]any
	_ = json.Unmarshal(out, &decoded)
	if err != nil || !changed || req.MaxTokens != 60 || decoded["max_tokens"] != float64(60) || decoded["max_completion_tokens"] != nil {
		t.Fatalf("req=%+v out=%s err=%v", req, out, err)
	}
	req = &ChatCompletionRequest{}
	_, _, _ = capChatRequestOutputTokens(req, []byte(`{"model":"m","messages":[]}`), "custom", 60)
	if req.MaxTokens != 0 || req.MaxCompletionTokens != 0 {
		t.Fatalf("客户端未设置上限时结构体也不得注入: %+v", req)
	}
}

func TestBudgetCapAllProtocols(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, protocol := range []string{"chat", "messages", "responses"} {
			field := "max_tokens"
			if protocol == "responses" {
				field = "max_output_tokens"
			}
			for _, value := range []int{0, 4000, 30} {
				bodyMap := map[string]any{"model": "anthropic/claude-haiku-5-5", "stream": stream}
				if value != 0 {
					bodyMap[field] = value
				}
				body, _ := json.Marshal(bodyMap)
				var out []byte
				var changed bool
				var err error
				switch protocol {
				case "responses":
					out, changed, err = capResponsesRequestOutputTokens(body, 60)
				case "chat":
					req := &ChatCompletionRequest{MaxTokens: value}
					out, changed, err = capChatRequestOutputTokens(req, body, "anthropic", 60)
					if value > 60 && req.MaxTokens != 60 {
						t.Fatal("结构体未收紧")
					}
				default:
					out, changed, err = capMessagesRequestOutputTokens(body, 60)
				}
				var got map[string]any
				_ = json.Unmarshal(out, &got)
				if err != nil || changed != (value > 60) {
					t.Fatalf("收紧状态错误: %s %v", out, err)
				}
				if value > 60 && got[field] != float64(60) {
					t.Fatalf("未收紧: %s", out)
				}
				if !changed && string(out) != string(body) {
					t.Fatal("未收紧时应逐字节保持")
				}
			}
		}
		body, _ := json.Marshal(map[string]any{"model": "anthropic/claude-haiku-5-5", "stream": stream, "messages": []any{}})
		req := &ChatCompletionRequest{}
		out, changed, err := capChatRequestOutputTokens(req, body, "anthropic", 599999982)
		if err != nil || changed || string(out) != string(body) || req.MaxTokens != 0 || req.MaxCompletionTokens != 0 {
			t.Fatalf("大额余额不得注入: %s %+v %v", out, req, err)
		}
	}
}

func TestBudgetCapThenAnthropicConversion(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, tc := range []struct {
			client int
			cap    int64
			want   float64
		}{
			{0, 599999982, 4096}, {131072, 599999982, 128000}, {4000, 60, 60},
		} {
			raw := map[string]any{"model": "anthropic/claude-haiku-5-5", "messages": []any{map[string]any{"role": "user", "content": "你好"}}, "stream": stream}
			if tc.client > 0 {
				raw["max_tokens"] = tc.client
			}
			body, _ := json.Marshal(raw)
			var req ChatCompletionRequest
			_ = json.Unmarshal(body, &req)
			capped, _, err := capChatRequestOutputTokens(&req, body, "anthropic", tc.cap)
			if err != nil {
				t.Fatal(err)
			}
			marshaled, err := marshalChatProviderBody(capped, &req)
			if err != nil {
				t.Fatal(err)
			}
			got, err := (&provider.AnthropicAdapter{}).TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "chat", Model: req.Model, UpstreamModelID: req.Model}, marshaled)
			if err != nil {
				t.Fatal(err)
			}
			var request map[string]any
			_ = json.Unmarshal(got, &request)
			if request["max_tokens"] != tc.want {
				t.Fatalf("预算到转换的完整参数链错误: %s", got)
			}
		}
	}
}
