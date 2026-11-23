package provider

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestAnthropicChatToolSchemaCleanup(t *testing.T) {
	for _, strict := range []bool{false, true} {
		body := fmt.Sprintf(`{"model":"claude-haiku-5-5","messages":[],"tools":[{"type":"function","function":{"name":"lookup","strict":%t,"parameters":{"type":"object","$schema":"https://json-schema.org/draft/2020-12/schema","properties":{"rows":{"type":"array","maxItems":20,"minItems":1,"uniqueItems":true,"contains":{"type":"number"},"items":{"type":"object","properties":{"count":{"type":"integer","minimum":1,"maximum":9,"exclusiveMinimum":0,"exclusiveMaximum":10,"multipleOf":1},"label":{"type":"string","minLength":1,"maxLength":10,"pattern":"x"},"maxItems":{"type":"integer"}}}}},"$defs":{"rows":{"type":"array","maxItems":2}},"allOf":[{"properties":{"other":{"type":"array","minItems":1}}}],"default":{"maxItems":9}}}}]}`, strict)
		// 直接经过真实 Chat→Anthropic 转换，修复前 maxItems 会原样到达 input_schema。
		got, _, err := transformOpenAIChatToAnthropic(nil, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		var request map[string]any
		_ = json.Unmarshal(got, &request)
		tool := request["tools"].([]any)[0].(map[string]any)
		schema := tool["input_schema"].(map[string]any)
		rows := schema["properties"].(map[string]any)["rows"].(map[string]any)
		if rows["maxItems"] != nil || rows["minItems"] != nil {
			t.Fatalf("数组约束仍被透传: %s", got)
		}
		nested := rows["items"].(map[string]any)["properties"].(map[string]any)
		count := nested["count"].(map[string]any)
		label := nested["label"].(map[string]any)
		if strict {
			for _, key := range []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"} {
				if count[key] != nil {
					t.Fatalf("strict 数值约束未删除: %s", got)
				}
			}
			for _, key := range []string{"minLength", "maxLength", "pattern"} {
				if label[key] != nil {
					t.Fatalf("strict 字符串约束未删除: %s", got)
				}
			}
			if rows["uniqueItems"] != nil || rows["contains"] != nil || schema["$schema"] != nil {
				t.Fatalf("strict 不支持关键字未删除: %s", got)
			}
		} else if count["minimum"] != float64(1) || label["pattern"] != "x" {
			t.Fatalf("非 strict 不应清理数值/字符串约束: %s", got)
		}
		if nested["maxItems"] == nil || schema["default"].(map[string]any)["maxItems"] != float64(9) {
			t.Fatalf("属性名和业务数据不得删除: %s", got)
		}
		definitions := schema["$defs"].(map[string]any)["rows"].(map[string]any)
		if definitions["maxItems"] != nil {
			t.Fatalf("$defs 未递归清理: %s", got)
		}
		other := schema["allOf"].([]any)[0].(map[string]any)["properties"].(map[string]any)["other"].(map[string]any)
		if other["minItems"] != nil {
			t.Fatalf("组合 schema 未递归清理: %s", got)
		}
	}
}
