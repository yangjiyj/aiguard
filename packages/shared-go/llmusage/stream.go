package llmusage

import (
	"bytes"
	"encoding/json"
	"strings"
)

// BodyUsage 是从一次完整响应体里取出的用量；Parser 标记来源（json / sse），写入计费证据。
type BodyUsage struct {
	Usage
	Parser string
}

// FromResponseBody 从已解密、已解压的完整响应体中取 token 用量，只复用 Canonicalize 的口径，
// 不解析任何对话协议：
//   - 非流式 JSON：顶层 usage；
//   - SSE：逐帧找 usage（OpenAI 末帧 usage、Responses 的 response.completed.response.usage、
//     Anthropic 的 message_start.message.usage 与 message_delta.usage），按出现的字段覆盖合并，末次显式值（包括零）为准；
//
// 解析不出可信用量（没有 usage、数值非法）返回 false，由调用方记“用量未知”。
func FromResponseBody(body []byte, contentType string) (BodyUsage, bool) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return BodyUsage{}, false
	}
	if !isEventStream(contentType, body) {
		usage := Canonicalize(body)
		return BodyUsage{Usage: usage, Parser: "json"}, trusted(usage)
	}
	merged := map[string]json.RawMessage{}
	found := false
	normalized := strings.ReplaceAll(string(body), "\r\n", "\n")
	for _, block := range strings.Split(normalized, "\n\n") {
		var lines []string
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "data:") {
				lines = append(lines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			}
		}
		payload := strings.TrimSpace(strings.Join(lines, "\n"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		for _, candidate := range usageCarriers([]byte(payload)) {
			var carrier struct {
				Usage json.RawMessage `json:"usage"`
			}
			if json.Unmarshal(candidate, &carrier) != nil || len(carrier.Usage) == 0 || string(carrier.Usage) == "null" {
				continue
			}
			var patch map[string]json.RawMessage
			if json.Unmarshal(carrier.Usage, &patch) != nil || patch == nil {
				return BodyUsage{}, false
			}
			// An old total must not override a newer component-only correction.
			if _, total := patch["total_tokens"]; !total {
				for _, key := range []string{"prompt_tokens", "input_tokens", "completion_tokens", "output_tokens"} {
					if _, present := patch[key]; present {
						delete(merged, "total_tokens")
						break
					}
				}
			}
			for key, value := range patch {
				if string(value) == "null" {
					continue
				}
				if strings.HasSuffix(key, "_details") {
					var before, after map[string]json.RawMessage
					_ = json.Unmarshal(merged[key], &before)
					if json.Unmarshal(value, &after) != nil || after == nil {
						return BodyUsage{}, false
					}
					if before == nil {
						before = map[string]json.RawMessage{}
					}
					for name, count := range after {
						before[name] = count
					}
					value, _ = json.Marshal(before)
				}
				merged[key] = value
			}
			raw, _ := json.Marshal(map[string]any{"usage": merged})
			usage := Canonicalize(raw)
			if usage.State == "invalid" {
				return BodyUsage{}, false
			}
			found = found || trusted(usage)
		}
	}
	raw, _ := json.Marshal(map[string]any{"usage": merged})
	usage := Canonicalize(raw)
	return BodyUsage{Usage: usage, Parser: "sse"}, found && trusted(usage)
}

// usageCarriers 返回一帧里可能带 usage 的对象：帧本身，以及 response / message 子对象。
func usageCarriers(frame []byte) [][]byte {
	out := [][]byte{frame}
	var nested struct {
		Response json.RawMessage `json:"response"`
		Message  json.RawMessage `json:"message"`
	}
	if json.Unmarshal(frame, &nested) == nil {
		for _, raw := range []json.RawMessage{nested.Response, nested.Message} {
			if len(raw) > 0 && raw[0] == '{' {
				out = append(out, raw)
			}
		}
	}
	return out
}

func trusted(usage Usage) bool {
	return usage.State == "upstream" || usage.State == "upstream_total_adjusted"
}

func isEventStream(contentType string, body []byte) bool {
	if strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		return true
	}
	return bytes.HasPrefix(body, []byte("data:")) || bytes.HasPrefix(body, []byte("event:"))
}
