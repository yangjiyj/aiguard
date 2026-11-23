package handler

import (
	"encoding/json"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionturn"
)

// 工具调用元数据的取值域。Stage/Kind 是机器可读的固定字面量，前端据此分列展示，不要翻译。
const (
	retainedToolStageRequest  = "request"
	retainedToolStageResponse = "response"

	retainedToolKindInvocation = "invocation_proposed"
	retainedToolKindResult     = "result_observed"

	// 预览只留头 256 个 rune：这是索引不是正文，完整证据在 request/response_content_redacted 里。
	maxRetainedToolPreviewRunes = 256
	maxRetainedToolNameRunes    = 128
)

// retainedToolCall 是 access_content_logs.tool_call_metadata_json 的元素：工具轮的结构索引。
// 只存工具名、种类与脱敏后的参数/结果预览——原始参数与结果正文一律不在这里重复落库。
type retainedToolCall struct {
	// ID 是 retentionturn.Digest("tool-id\x00"+rawID)，与 request_logs.retention_turn_context
	// 里 tools[].id 同口径，两侧可用同一 digest 关联同一次工具调用。
	ID               string `json:"id,omitempty"`
	Name             string `json:"name,omitempty"`
	Kind             string `json:"kind"`  // invocation_proposed | result_observed
	Stage            string `json:"stage"` // request | response
	ArgumentsPreview string `json:"arguments_preview,omitempty"`
	ResultPreview    string `json:"result_preview,omitempty"`
}

// retainedRequestToolCalls 从请求原始 JSON 里抽取本轮（最后一条真实用户消息之后）的工具调用。
// 只做结构索引：参数取 tool_use.input / tool_calls[].function.arguments，结果取 tool_result.content /
// function_call_output.output，两者都经 redactRetainedText 脱敏后再截到 256 rune。
func retainedRequestToolCalls(raw []byte) []retainedToolCall {
	if len(raw) == 0 {
		return nil
	}
	var decoded map[string]interface{}
	if json.Unmarshal(raw, &decoded) != nil {
		return nil
	}
	tails := retentionturn.TailAfterLastUserText(decoded)
	out := []retainedToolCall{}
	for _, field := range []string{"messages", "input"} {
		for _, item := range tails[field] {
			out = append(out, retainedToolCallsFromEntry(item)...)
		}
	}
	return out
}

// retainedResponseToolCalls 从响应文本里抽取模型提出的工具调用。名字与参数从
// `[tool_use:Name] args` 行取（SSE 重组后该行带 `[tool] ` 前缀，这里一并剥掉）；
// id 只能按出现顺序与 TurnResponse.Tools 里同名的 invocation_proposed 配对，配不上就留空——
// 宁可没有 id，也不给错误的关联。
func retainedResponseToolCalls(text string, observations []retentionturn.ToolObservation) []retainedToolCall {
	pending := make([]retentionturn.ToolObservation, 0, len(observations))
	for _, observation := range observations {
		if observation.Kind == retainedToolKindInvocation {
			pending = append(pending, observation)
		}
	}
	out := []retainedToolCall{}
	position := 0
	for _, line := range strings.Split(normalizeNewlines(text), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[tool] ") {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "[tool] "))
		}
		if !strings.HasPrefix(trimmed, "[tool_use:") {
			continue
		}
		name, arguments := parseRetainedToolUseLine(trimmed)
		call, ok := newRetainedToolCall("", name, retainedToolKindInvocation, retainedToolStageResponse, arguments, "")
		if !ok {
			continue
		}
		if position < len(pending) && (pending[position].Name == "" || pending[position].Name == name) {
			call.ID = pending[position].ID
		}
		position++
		out = append(out, call)
	}
	return out
}

// retainedToolCallsFromEntry 处理一个消息/条目的所有工具位置：Anthropic 的 tool_use / tool_result、
// OpenAI Responses 的 function_call / function_call_output、OpenAI chat 的 tool_calls[] 与 role=tool。
// 与 retentionturn.toolObservations 用同一套位置约束：不把嵌在人话里的 JSON 当工具调用。
func retainedToolCallsFromEntry(item interface{}) []retainedToolCall {
	entry, ok := item.(map[string]interface{})
	if !ok {
		return nil
	}
	role := retainedStringField(entry, "role")
	out := retainedToolCallsFromTypedEntry(entry, role)
	// Anthropic 把 tool_use / tool_result 放在消息 content 的块数组里。
	if blocks, ok := entry["content"].([]interface{}); ok {
		for _, block := range blocks {
			nested, ok := block.(map[string]interface{})
			if !ok {
				continue
			}
			out = append(out, retainedToolCallsFromTypedEntry(nested, role)...)
		}
	}
	// OpenAI chat：assistant 消息的 tool_calls[] 是「模型提出调用」。
	if role != "user" && role != "tool" {
		for _, raw := range retainedSliceField(entry, "tool_calls") {
			call, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			name, arguments := "", ""
			if fn, ok := call["function"].(map[string]interface{}); ok {
				name = retainedStringField(fn, "name")
				arguments = retainedToolPreview(fn["arguments"])
			}
			if prepared, ok := newRetainedToolCall(retainedStringField(call, "id"), name, retainedToolKindInvocation, retainedToolStageRequest, arguments, ""); ok {
				out = append(out, prepared)
			}
		}
	}
	// OpenAI chat：role=tool 的消息是「已观察到结果」。
	if role == "tool" {
		if prepared, ok := newRetainedToolCall(retainedStringField(entry, "tool_call_id"), retainedStringField(entry, "name"), retainedToolKindResult, retainedToolStageRequest, "", retainedToolResultPreview(entry["content"])); ok {
			out = append(out, prepared)
		}
	}
	return out
}

func retainedToolCallsFromTypedEntry(entry map[string]interface{}, role string) []retainedToolCall {
	var out []retainedToolCall
	add := func(id, name, kind, arguments, result string) {
		if prepared, ok := newRetainedToolCall(id, name, kind, retainedToolStageRequest, arguments, result); ok {
			out = append(out, prepared)
		}
	}
	switch retainedStringField(entry, "type") {
	case "tool_use":
		if role != "user" {
			add(retainedStringField(entry, "id"), retainedStringField(entry, "name"), retainedToolKindInvocation, retainedToolPreview(entry["input"]), "")
		}
	case "function_call":
		if role != "user" {
			add(retainedStringField(entry, "call_id"), retainedStringField(entry, "name"), retainedToolKindInvocation, retainedToolPreview(entry["arguments"]), "")
		}
	case "tool_result":
		add(retainedStringField(entry, "tool_use_id"), "", retainedToolKindResult, "", retainedToolResultPreview(entry["content"]))
	case "function_call_output":
		add(retainedStringField(entry, "call_id"), "", retainedToolKindResult, "", retainedToolResultPreview(entry["output"]))
	}
	return out
}

// newRetainedToolCall 归一化一条工具调用索引。请求侧的 ID 是硬要求：没有 id 就没有稳定关联键，
// 丢弃以对齐 retention_turn_context.tools（那边同样只接受已知协议位置上的非空 id）。
// 响应侧 id 允许为空（文本行里没有稳定 id），但整条全空时不产出无意义条目。
func newRetainedToolCall(rawID, name, kind, stage, arguments, result string) (retainedToolCall, bool) {
	id := strings.TrimSpace(rawID)
	if id == "" && stage == retainedToolStageRequest {
		return retainedToolCall{}, false
	}
	call := retainedToolCall{
		Kind:             kind,
		Stage:            stage,
		Name:             truncateRetainedRunes(strings.TrimSpace(name), maxRetainedToolNameRunes),
		ArgumentsPreview: truncateRetainedPreview(arguments),
		ResultPreview:    truncateRetainedPreview(result),
	}
	if id != "" {
		call.ID = retentionturn.Digest("tool-id\x00" + id)
	}
	if call.ID == "" && call.Name == "" && call.ArgumentsPreview == "" && call.ResultPreview == "" {
		return retainedToolCall{}, false
	}
	return call, true
}

// parseRetainedToolUseLine 拆 `[tool_use:Name] {json}` → (Name, {json})。
func parseRetainedToolUseLine(line string) (string, string) {
	rest := strings.TrimPrefix(strings.TrimSpace(line), "[tool_use:")
	end := strings.IndexByte(rest, ']')
	if end < 0 {
		return strings.TrimSpace(rest), ""
	}
	return strings.TrimSpace(rest[:end]), strings.TrimSpace(rest[end+1:])
}

// truncateRetainedPreview 先脱敏再截断——顺序不能反：截断后再脱敏会留下一段不再匹配密钥正则的
// 半截密钥字面值。
func truncateRetainedPreview(value string) string {
	value = redactRetainedText(value)
	if value == "" {
		return ""
	}
	return truncateRetainedRunes(value, maxRetainedToolPreviewRunes)
}

func truncateRetainedRunes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

// retainedToolPreview 把参数/结果值渲染成文本：字符串原样，对象/数组走 JSON。
func retainedToolPreview(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	default:
		raw, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}

// retainedToolResultPreview 解工具结果：Anthropic tool_result.content 是 string 或 text 块数组，
// Responses function_call_output.output 是 string，OpenAI chat role=tool.content 是 string。
func retainedToolResultPreview(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []interface{}:
		parts := []string{}
		for _, block := range typed {
			entry, ok := block.(map[string]interface{})
			if !ok {
				continue
			}
			if text, ok := entry["text"].(string); ok && strings.TrimSpace(text) != "" {
				parts = append(parts, strings.TrimSpace(text))
			}
		}
		return strings.Join(parts, "\n")
	default:
		return retainedToolPreview(value)
	}
}

func retainedStringField(entry map[string]interface{}, key string) string {
	value, _ := entry[key].(string)
	return strings.TrimSpace(value)
}

func retainedSliceField(entry map[string]interface{}, key string) []interface{} {
	value, _ := entry[key].([]interface{})
	return value
}
