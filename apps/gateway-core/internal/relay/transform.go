package relay

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func ResponsesSSEToEvent(input SSEEvent) (StreamEvent, error) {
	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(input.Data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return StreamEvent{}, fmt.Errorf("decode Responses SSE event: %w", err)
	}
	eventType, _ := document["type"].(string)
	if eventType == "" {
		eventType = input.Event
	}
	event := StreamEvent{ID: stringValue(document, "id"), Model: stringValue(document, "model"), Raw: []byte(input.Data)}
	switch eventType {
	case "response.created":
		event.Type = EventStreamStart
	case "response.in_progress", "response.output_item.added":
		item, _ := document["item"].(map[string]any)
		if stringValue(item, "type") == "function_call" {
			event.Type = EventToolCallStart
			event.ToolCall = &ToolCall{ID: firstString(stringValue(document, "item_id"), stringValue(item, "id")), Name: stringValue(item, "name"), Index: intValue(document, "output_index")}
		} else {
			event.Type = EventMessageStart
		}
	case "response.output_text.delta":
		event.Type = EventTextDelta
		event.Delta = stringValue(document, "delta")
	case "response.reasoning_summary_text.delta", "response.reasoning_text.delta", "response.output_text.reasoning.delta":
		event.Type = EventReasoningDelta
		event.Delta = stringValue(document, "delta")
	case "response.function_call_arguments.delta":
		event.Type = EventToolArgumentsDelta
		event.Delta = stringValue(document, "delta")
		event.ToolCall = &ToolCall{ID: stringValue(document, "item_id"), Index: intValue(document, "output_index")}
	case "response.function_call_arguments.done":
		event.Type = EventToolArgumentsDone
		event.Delta = firstString(stringValue(document, "arguments"), stringValue(document, "delta"))
		event.ToolCall = &ToolCall{ID: stringValue(document, "item_id"), Index: intValue(document, "output_index")}
	case "response.completed", "response.incomplete":
		event.Type = EventMessageEnd
		event.FinishReason = strings.TrimPrefix(eventType, "response.")
		event.Usage = responseUsage(document)
	case "response.failed", "response.error", "error":
		event.Type = EventStreamError
		event.Err = fmt.Errorf("Responses upstream event: %s", firstString(stringValue(document, "message"), stringValue(document, "code"), "upstream_error"))
	default:
		event.Type = EventUnknown
	}
	return event, nil
}

func responseUsage(document map[string]any) *Usage {
	response, _ := document["response"].(map[string]any)
	usage, _ := response["usage"].(map[string]any)
	if usage == nil {
		usage, _ = document["usage"].(map[string]any)
	}
	if usage == nil {
		return nil
	}
	inputTokens := maxNonNegativeInt64(int64Value(usage, "input_tokens"), int64Value(usage, "prompt_tokens"))
	cacheReadTokens := maxNonNegativeInt64(
		int64Value(usage, "cache_read_input_tokens"),
		int64Value(usage, "cached_tokens"),
		int64Value(usage, "prompt_cache_hit_tokens"),
		nestedInt64Value(usage, "input_tokens_details", "cached_tokens"),
	)
	cacheMissTokens := maxNonNegativeInt64(int64Value(usage, "prompt_cache_miss_tokens"))
	if inputTokens == 0 {
		inputTokens = cacheReadTokens + cacheMissTokens
	}
	return &Usage{
		InputTokens:  inputTokens,
		OutputTokens: maxNonNegativeInt64(int64Value(usage, "output_tokens"), int64Value(usage, "completion_tokens")),
		ReasoningTokens: maxNonNegativeInt64(
			int64Value(usage, "reasoning_tokens"),
			nestedInt64Value(usage, "output_tokens_details", "reasoning_tokens"),
		),
		CacheReadInputTokens: cacheReadTokens,
		CacheCreationInputTokens: maxNonNegativeInt64(
			int64Value(usage, "cache_creation_input_tokens"),
			nestedInt64Value(usage, "input_tokens_details", "cache_creation_input_tokens"),
		),
		CacheMissInputTokens: cacheMissTokens,
	}
}

func nestedInt64Value(document map[string]any, parent, key string) int64 {
	nested, _ := document[parent].(map[string]any)
	return int64Value(nested, key)
}

func maxNonNegativeInt64(values ...int64) int64 {
	var result int64
	for _, value := range values {
		if value > result {
			result = value
		}
	}
	return result
}

type ChatEncoder struct {
	// PromptIncludesCache 表示上游 InputTokens 不含缓存读写（Anthropic Messages 口径），
	// 输出 Chat usage 时要把缓存加回 prompt_tokens 并给出 prompt_tokens_details。
	PromptIncludesCache bool
	id                  string
	model               string
	created             int64
	toolIDs             map[string]int
	toolArgs            map[int]bool
	nextTool            int
}

func NewChatEncoder(id, model string) *ChatEncoder {
	return &ChatEncoder{id: id, model: model, created: time.Now().Unix(), toolIDs: make(map[string]int), toolArgs: make(map[int]bool)}
}

func (e *ChatEncoder) Encode(event StreamEvent) ([]byte, error) {
	chunk := map[string]any{
		"id": e.id, "object": "chat.completion.chunk", "created": e.created, "model": e.model,
	}
	switch event.Type {
	case EventStreamStart, EventMessageStart:
		chunk["choices"] = []any{map[string]any{"index": event.Index, "delta": map[string]any{"role": "assistant"}}}
	case EventTextDelta:
		chunk["choices"] = []any{map[string]any{"index": event.Index, "delta": map[string]any{"content": event.Delta}}}
	case EventReasoningDelta:
		chunk["choices"] = []any{map[string]any{"index": event.Index, "delta": map[string]any{"reasoning_content": event.Delta}}}
	case EventToolCallStart:
		tool := e.ensureTool(event.ToolCall)
		chunk["choices"] = []any{map[string]any{"index": event.Index, "delta": map[string]any{"tool_calls": []any{map[string]any{"index": tool.Index, "id": tool.ID, "type": "function", "function": map[string]any{"name": tool.Name}}}}}}
	case EventToolArgumentsDelta, EventToolArgumentsDone:
		tool := e.ensureTool(event.ToolCall)
		if event.Type == EventToolArgumentsDone && (e.toolArgs[tool.Index] || event.Delta == "") {
			return nil, nil
		}
		if event.Delta != "" {
			e.toolArgs[tool.Index] = true
		}
		chunk["choices"] = []any{map[string]any{"index": event.Index, "delta": map[string]any{"tool_calls": []any{map[string]any{"index": tool.Index, "function": map[string]any{"arguments": event.Delta}}}}}}
	case EventUsageDelta, EventUsageFinal, EventCacheUsage:
		chunk["choices"] = []any{}
		chunk["usage"] = usageMap(event.Usage, event.CacheUsage, e.PromptIncludesCache)
	case EventMessageEnd:
		choice := map[string]any{"index": event.Index, "delta": map[string]any{}, "finish_reason": firstString(event.FinishReason, "stop")}
		chunk["choices"] = []any{choice}
		if event.Usage != nil {
			chunk["usage"] = usageMap(event.Usage, nil, e.PromptIncludesCache)
		}
	case EventStreamError:
		chunk = map[string]any{"error": map[string]string{"message": errorMessage(event.Err), "type": "upstream_error"}}
	case EventUnknown:
		return nil, nil
	default:
		return nil, fmt.Errorf("event %q cannot be encoded as Chat SSE", event.Type)
	}
	return json.Marshal(chunk)
}

func (e *ChatEncoder) ensureTool(tool *ToolCall) *ToolCall {
	if tool == nil {
		tool = &ToolCall{}
	}
	if index, ok := e.toolIDs[tool.ID]; ok {
		copy := *tool
		copy.Index = index
		return &copy
	}
	copy := *tool
	if copy.ID == "" {
		copy.ID = "tool_call_" + strconv.Itoa(e.nextTool)
	}
	copy.Index = e.nextTool
	e.toolIDs[copy.ID] = copy.Index
	e.nextTool++
	return &copy
}

func usageMap(usage *Usage, cache *CacheUsage, promptAddsCache bool) map[string]any {
	out := map[string]any{}
	if usage != nil {
		promptTokens := usage.InputTokens
		if promptAddsCache {
			promptTokens += usage.CacheReadInputTokens + usage.CacheCreationInputTokens
			if usage.CacheReadInputTokens > 0 || usage.CacheCreationInputTokens > 0 {
				out["prompt_tokens_details"] = map[string]any{
					"cached_tokens":               usage.CacheReadInputTokens,
					"cache_creation_input_tokens": usage.CacheCreationInputTokens,
				}
			}
		}
		out["prompt_tokens"] = promptTokens
		out["completion_tokens"] = usage.OutputTokens
		out["total_tokens"] = promptTokens + usage.OutputTokens
		if usage.ReasoningTokens > 0 {
			out["completion_tokens_details"] = map[string]any{"reasoning_tokens": usage.ReasoningTokens}
		}
		if usage.CacheReadInputTokens > 0 {
			out["cache_read_input_tokens"] = usage.CacheReadInputTokens
		}
		if usage.CacheCreationInputTokens > 0 {
			out["cache_creation_input_tokens"] = usage.CacheCreationInputTokens
		}
		if usage.CacheReadInputTokens > 0 {
			out["prompt_cache_hit_tokens"] = usage.CacheReadInputTokens
		}
		if usage.CacheMissInputTokens > 0 {
			out["prompt_cache_miss_tokens"] = usage.CacheMissInputTokens
		}
	}
	if cache != nil {
		out["cache_read_input_tokens"] = cache.ReadTokens
		out["cache_creation_input_tokens"] = cache.CreationTokens
		out["prompt_cache_hit_tokens"] = cache.ReadTokens
	}
	return out
}

func stringValue(document map[string]any, key string) string {
	if document == nil {
		return ""
	}
	value, _ := document[key].(string)
	return value
}

func intValue(document map[string]any, key string) int {
	return int(int64Value(document, key))
}

func int64Value(document map[string]any, key string) int64 {
	switch value := document[key].(type) {
	case json.Number:
		result, _ := value.Int64()
		return result
	case float64:
		return int64(value)
	default:
		return 0
	}
}

func firstString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func errorMessage(err error) string {
	if err == nil {
		return "stream error"
	}
	return err.Error()
}
