package retentionturn

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"strings"
)

// ToolObservation is protocol evidence, not proof of successful execution.
// Arguments/results remain in the dedicated tool audit, never in this index.
type ToolObservation struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Kind string `json:"kind"`
}

func toolObservations(raw []byte, request bool) []ToolObservation {
	out := []ToolObservation{}
	seen := map[string]int{}
	add := func(id, name, kind string) {
		if id == "" {
			return
		}
		if len([]rune(name)) > 128 {
			name = string([]rune(name)[:128])
		}
		id = Digest("tool-id\x00" + id)
		key := id + kind
		if index, exists := seen[key]; exists {
			if name != "" {
				out[index].Name = name
			}
			return
		}
		if len(out) >= 256 {
			return
		}
		seen[key] = len(out)
		out = append(out, ToolObservation{ID: id, Name: name, Kind: kind})
	}
	str := func(v interface{}) string { s, _ := v.(string); return s }
	var visit func(interface{}, string, string, int)
	visit = func(value interface{}, key, role string, depth int) {
		if depth > 32 {
			return
		}
		switch v := value.(type) {
		case []interface{}:
			for _, item := range v {
				visit(item, key, role, depth+1)
			}
		case map[string]interface{}:
			if r := str(v["role"]); r != "" {
				role = r
			}
			// Never interpret a JSON object embedded in a human text/content block.
			typ := str(v["type"])
			if key == "tool_calls" && role != "user" && role != "tool" {
				fn, _ := v["function"].(map[string]interface{})
				add(str(v["id"]), str(fn["name"]), "invocation_proposed")
			}
			switch typ {
			case "tool_use":
				if role != "user" {
					add(str(v["id"]), str(v["name"]), "invocation_proposed")
				}
			case "function_call":
				if role != "user" {
					add(str(v["call_id"]), str(v["name"]), "invocation_proposed")
				}
			case "tool_result":
				add(str(v["tool_use_id"]), "", "result_observed")
			case "function_call_output":
				add(str(v["call_id"]), "", "result_observed")
			}
			if role == "tool" {
				add(str(v["tool_call_id"]), str(v["name"]), "result_observed")
			}
			for _, child := range []string{"messages", "input", "output", "content", "choices", "message", "delta", "tool_calls", "content_block", "item", "response"} {
				if child == "content" && role == "user" { // Anthropic user content may contain real tool_result blocks.
					if blocks, ok := v[child].([]interface{}); ok {
						for _, block := range blocks {
							if obj, ok := block.(map[string]interface{}); ok && str(obj["type"]) == "tool_result" {
								add(str(obj["tool_use_id"]), "", "result_observed")
							}
						}
					}
					continue
				}
				// Function arguments, result bodies and arbitrary payload keys are excluded.
				if child == "input" && typ == "tool_use" || child == "output" && typ == "function_call_output" || child == "content" && (role == "tool" || typ == "tool_result") {
					continue
				}
				if val, ok := v[child]; ok {
					visit(val, child, role, depth+1)
				}
			}
		}
	}
	var decoded interface{}
	if json.Unmarshal(raw, &decoded) == nil {
		if request {
			if obj, ok := decoded.(map[string]interface{}); ok {
				for field, tail := range TailAfterLastUserText(obj) {
					obj[field] = tail
				}
			}
		}
		visit(decoded, "", "", 0)
	} else {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &decoded) == nil {
				visit(decoded, "", "", 0)
			}
		}
	}
	return out
}

// TailAfterLastUserText 返回请求体里 messages / input 数组中「最后一条真实用户文本」及其之后的
// 条目（含该用户消息本身）。工具轮留证只需要这段尾巴：用户消息之前的历史助手/工具内容属于更早的
// 轮次，重复留证只会把 64KB 预算耗光、把本轮证据挤掉。
//
// 返回 map 的键是原始字段名（messages / input）；字段不存在或不是数组时不出现该键。
// 没有用户文本时返回该字段的完整数组——增量式 API（只发 function_call_output）语义不变。
func TailAfterLastUserText(object map[string]interface{}) map[string][]interface{} {
	out := map[string][]interface{}{}
	for _, field := range []string{"messages", "input"} {
		items, ok := object[field].([]interface{})
		if !ok {
			continue
		}
		start := 0
		for i, item := range items {
			m, ok := item.(map[string]interface{})
			if !ok || m["role"] != "user" {
				continue
			}
			path := "/v1/messages"
			if field == "input" {
				path = "/v1/responses"
			}
			body, _ := json.Marshal(map[string]interface{}{field: []interface{}{item}})
			if parsed, ok := aimsg.ParseChatRequest(path, body); ok && parsed.LastUserText != "" {
				start = i
			}
		}
		out[field] = items[start:]
	}
	return out
}
