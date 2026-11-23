package provider

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestNativeAnthropicMessagesOutputLimits(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, limit := range []int{131072, 4000, 0} {
			bodyMap := map[string]any{"model": "logical", "stream": stream, "messages": []any{}, "tools": []any{map[string]any{"name": "test", "input_schema": map[string]any{"maxItems": 2}}}}
			if limit > 0 {
				bodyMap["max_tokens"] = limit
			}
			body, _ := json.Marshal(bodyMap)
			envelope := &modelrouter.RequestEnvelope{EndpointType: "messages", Model: "logical", UpstreamModelID: "anthropic/claude-haiku-5-5"}
			got, err := (&AnthropicAdapter{}).TransformRequest(envelope, body)
			if err != nil {
				t.Fatal(err)
			}
			var request map[string]any
			_ = json.Unmarshal(got, &request)
			want := any(nil)
			if limit > 0 {
				want = float64(min(limit, 128000))
			}
			if request["max_tokens"] != want {
				t.Fatalf("原生路径仅收紧不注入: %s", got)
			}
			tools, _ := json.Marshal(request["tools"])
			original, _ := json.Marshal(bodyMap["tools"])
			if string(tools) != string(original) {
				t.Fatalf("原生工具不得修改: %s", got)
			}
		}
	}
}

func TestNativeAnthropicMessagesThinkingFitsOutputLimit(t *testing.T) {
	for _, model := range []string{"anthropic/claude-foo-native", "claude-3-5-sonnet"} {
		profileLimit := 128000
		if model == "claude-3-5-sonnet" {
			profileLimit = 8192
		}
		body := []byte(fmt.Sprintf(`{"model":%q,"max_tokens":200000,"thinking":{"type":"enabled","budget_tokens":180000},"messages":[]}`, model))
		got, err := (&AnthropicAdapter{}).TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "messages", Model: model}, body)
		if err != nil {
			t.Fatal(err)
		}
		var request map[string]any
		_ = json.Unmarshal(got, &request)
		thinking, _ := request["thinking"].(map[string]any)
		if request["max_tokens"] != float64(profileLimit) || thinking["budget_tokens"] != float64(profileLimit-1) {
			t.Fatalf("原生思考预算必须小于输出上限: %s", got)
		}
	}
}

func TestNativeAnthropicMessagesUnchangedBelowLimit(t *testing.T) {
	body := []byte(`{ "model": "claude-haiku-5-5", "max_tokens": 4000, "messages": [] }`)
	got, err := (&AnthropicAdapter{}).TransformRequest(&modelrouter.RequestEnvelope{EndpointType: "messages", Model: "claude-haiku-5-5"}, body)
	if err != nil || string(got) != string(body) {
		t.Fatalf("未收紧必须原样返回: %s %v", got, err)
	}
}
