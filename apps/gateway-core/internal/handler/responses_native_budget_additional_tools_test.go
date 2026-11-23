package handler

import (
	"encoding/json"
	"testing"
)

// 预算断流把客户端给的超限 max_output_tokens 收紧时，网关会改写（转换后的）chatReq，
// “安全回填”因此误以为请求被改过，对 input 里每个带 role 的条目回填 content。
// additional_tools 没有 content，被塞入后上游报 Unknown parameter: 'input[0].content'。
func TestNativeResponsesBudgetCapDoesNotInjectContentIntoNonMessageItems(t *testing.T) {
	limit := int64(60)
	upstream := &openAIBudgetUpstream{obey: true}
	body := `{"model":"gpt-b","stream":true,"max_output_tokens":1000,"input":[` +
		`{"type":"additional_tools","id":"at_1","role":"developer","tools":[{"type":"function","name":"f","parameters":{}}]},` +
		`{"type":"message","id":"msg_1","role":"developer","content":[{"type":"input_text","text":"dev"}]},` +
		`{"type":"message","id":"msg_2","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`
	runResponsesBudget(t, &limit, upstream, body)
	got, _ := upstream.received()
	input, _ := got["input"].([]any)
	if len(input) != 3 {
		t.Fatalf("input 条目数不对: %v", got["input"])
	}
	first, _ := input[0].(map[string]any)
	if _, bad := first["content"]; bad {
		b, _ := json.Marshal(got)
		t.Fatalf("预算上限生效时 additional_tools 被塞入 content: %s", b)
	}
	if got["max_output_tokens"] != float64(60) {
		t.Fatalf("预算上限应写入 max_output_tokens=60, got %v", got["max_output_tokens"])
	}
}
