package provider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// Messages ingress is normalized to Chat first, then optionally to Responses.
// The reverse path always restores the public Anthropic Messages contract.
func usesMessagesOpenAIBridge(envelope *modelrouter.RequestEnvelope) bool {
	if envelope == nil || envelope.EndpointType != "messages" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(envelope.UpstreamProtocol)) {
	case "chat", "responses":
		return true
	default:
		return false
	}
}

func usesMessagesResponsesBridge(envelope *modelrouter.RequestEnvelope) bool {
	return usesMessagesOpenAIBridge(envelope) &&
		strings.EqualFold(strings.TrimSpace(envelope.UpstreamProtocol), "responses")
}

func transformAnthropicMessagesToChat(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, error) {
	var source map[string]any
	decoder := json.NewDecoder(bytes.NewReader(rawBody))
	decoder.UseNumber()
	if err := decoder.Decode(&source); err != nil {
		return nil, fmt.Errorf("decode Anthropic Messages request: %w", err)
	}
	modelName := compatStringValue(source["model"])
	if envelope != nil && strings.TrimSpace(envelope.UpstreamModelID) != "" {
		modelName = strings.TrimSpace(envelope.UpstreamModelID)
	}
	if modelName == "" {
		return nil, fmt.Errorf("Anthropic Messages model is required")
	}

	request := map[string]any{"model": modelName}
	messages := make([]any, 0)
	if system, exists := source["system"]; exists {
		text, err := anthropicBridgeText(system)
		if err != nil {
			return nil, fmt.Errorf("Anthropic system cannot be converted: %w", err)
		}
		if text != "" {
			messages = append(messages, map[string]any{"role": "system", "content": text})
		}
	}
	for index, rawMessage := range anySlice(source["messages"]) {
		message, ok := rawMessage.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("Anthropic message %d must be an object", index)
		}
		converted, err := anthropicBridgeMessage(message)
		if err != nil {
			return nil, fmt.Errorf("Anthropic message %d cannot be converted: %w", index, err)
		}
		messages = append(messages, converted...)
	}
	if len(messages) == 0 {
		return nil, fmt.Errorf("Anthropic request has no convertible messages")
	}
	request["messages"] = messages

	if value, ok := source["max_tokens"]; ok {
		request["max_completion_tokens"] = value
	}
	for _, fields := range [][2]string{
		{"temperature", "temperature"}, {"top_p", "top_p"}, {"stream", "stream"},
		{"stop_sequences", "stop"},
	} {
		if value, ok := source[fields[0]]; ok {
			request[fields[1]] = value
		}
	}
	tools, err := anthropicBridgeTools(source["tools"])
	if err != nil {
		return nil, err
	}
	if len(tools) > 0 {
		request["tools"] = tools
	}
	if choice, err := anthropicBridgeToolChoice(source["tool_choice"]); err != nil {
		return nil, err
	} else if choice != nil {
		request["tool_choice"] = choice
	}
	if rawOutput, exists := source["output_config"]; exists {
		output, ok := rawOutput.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("Anthropic output_config must be an object")
		}
		for field := range output {
			if field != "effort" && field != "format" {
				return nil, fmt.Errorf("Anthropic output_config.%s has no safe OpenAI mapping", field)
			}
		}
		if effort := compatStringValue(output["effort"]); effort != "" {
			request["reasoning_effort"] = effort
		}
		if rawFormat, exists := output["format"]; exists {
			format, ok := rawFormat.(map[string]any)
			if !ok || compatStringValue(format["type"]) != "json_schema" || format["schema"] == nil {
				return nil, fmt.Errorf("Anthropic output_config.format must contain a json_schema")
			}
			request["response_format"] = map[string]any{
				"type": "json_schema",
				"json_schema": map[string]any{
					"name": "anthropic_messages_output", "schema": format["schema"], "strict": true,
				},
			}
		}
	}
	if rawThinking, exists := source["thinking"]; exists {
		thinking, ok := rawThinking.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("Anthropic thinking must be an object")
		}
		switch compatStringValue(thinking["type"]) {
		case "", "adaptive":
			if _, exists := request["reasoning_effort"]; !exists {
				request["reasoning_effort"] = "high"
			}
		case "enabled":
			if _, exists := request["reasoning_effort"]; !exists {
				request["reasoning_effort"] = anthropicBridgeEffort(thinking["budget_tokens"])
			}
		case "disabled":
			return nil, fmt.Errorf("Anthropic thinking disabled has no lossless OpenAI mapping")
		default:
			return nil, fmt.Errorf("Anthropic thinking.type %q is unsupported", compatStringValue(thinking["type"]))
		}
	}
	if metadata, ok := source["metadata"]; ok {
		request["metadata"] = metadata
	}
	supported := map[string]bool{
		"model": true, "messages": true, "system": true, "max_tokens": true,
		"temperature": true, "top_p": true, "stream": true, "stop_sequences": true,
		"tools": true, "tool_choice": true, "thinking": true, "output_config": true,
		"metadata": true,
		// context_management 是 Anthropic 专有的上下文编辑提示（新版 Claude Code 每个请求都带），
		// OpenAI 上游没有等价语义，丢弃只影响成本，不改变回答，不应因此拒绝整条路由。
		"context_management": true,
	}
	for field := range source {
		if !supported[field] {
			return nil, fmt.Errorf("Anthropic field %q has no safe OpenAI mapping", field)
		}
	}
	return json.Marshal(request)
}

func anthropicBridgeMessage(message map[string]any) ([]any, error) {
	role := strings.ToLower(strings.TrimSpace(compatStringValue(message["role"])))
	if role == "system" {
		// 新版 Claude Code 把运行环境信息放进 messages 里的 role=system 消息。内容要原样交给上游，
		// 所以映射为上游的 system 消息；只接受文本块，其他块没有安全映射，仍然报错而不是静默丢弃。
		text, err := anthropicBridgeText(message["content"])
		if err != nil {
			return nil, fmt.Errorf("inline system message cannot be converted: %w", err)
		}
		return []any{map[string]any{"role": "system", "content": text}}, nil
	}
	if role != "user" && role != "assistant" {
		return nil, fmt.Errorf("role %q is unsupported", role)
	}
	if text, ok := message["content"].(string); ok {
		return []any{map[string]any{"role": role, "content": text}}, nil
	}
	blocks, ok := message["content"].([]any)
	if !ok {
		return nil, fmt.Errorf("content must be a string or block array")
	}
	if role == "assistant" {
		content, calls := make([]any, 0), make([]any, 0)
		for _, raw := range blocks {
			block, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("assistant block must be an object")
			}
			switch compatStringValue(block["type"]) {
			case "text":
				content = append(content, map[string]any{"type": "text", "text": compatStringValue(block["text"])})
			case "tool_use":
				id, name := compatStringValue(block["id"]), compatStringValue(block["name"])
				if id == "" || name == "" {
					return nil, fmt.Errorf("tool_use requires id and name")
				}
				arguments, _ := json.Marshal(block["input"])
				calls = append(calls, map[string]any{
					"id": id, "type": "function",
					"function": map[string]any{"name": name, "arguments": string(arguments)},
				})
			case "thinking", "redacted_thinking":
				return nil, fmt.Errorf("signed thinking history is model-bound")
			default:
				return nil, fmt.Errorf("assistant block type %q is unsupported", compatStringValue(block["type"]))
			}
		}
		result := map[string]any{"role": "assistant", "content": content}
		if len(calls) > 0 {
			result["tool_calls"] = calls
		}
		return []any{result}, nil
	}

	result, pending := make([]any, 0), make([]any, 0)
	flush := func() {
		if len(pending) > 0 {
			result = append(result, map[string]any{"role": "user", "content": pending})
			pending = nil
		}
	}
	for _, raw := range blocks {
		block, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("user block must be an object")
		}
		switch compatStringValue(block["type"]) {
		case "text":
			pending = append(pending, map[string]any{"type": "text", "text": compatStringValue(block["text"])})
		case "image", "document", "file":
			part, err := anthropicBridgeMedia(block)
			if err != nil {
				return nil, err
			}
			pending = append(pending, part)
		case "tool_result":
			flush()
			callID := compatStringValue(block["tool_use_id"])
			if callID == "" {
				return nil, fmt.Errorf("tool_result requires tool_use_id")
			}
			text, media, err := anthropicBridgeToolResult(block["content"])
			if err != nil {
				return nil, err
			}
			result = append(result, map[string]any{"role": "tool", "tool_call_id": callID, "content": text})
			if len(media) > 0 {
				result = append(result, map[string]any{"role": "user", "content": media})
			}
		default:
			return nil, fmt.Errorf("user block type %q is unsupported", compatStringValue(block["type"]))
		}
	}
	flush()
	return result, nil
}

func anthropicBridgeText(value any) (string, error) {
	if text, ok := value.(string); ok {
		return text, nil
	}
	parts := make([]string, 0)
	for _, raw := range anySlice(value) {
		block, ok := raw.(map[string]any)
		if !ok || compatStringValue(block["type"]) != "text" {
			return "", fmt.Errorf("only text blocks are supported")
		}
		parts = append(parts, compatStringValue(block["text"]))
	}
	return strings.Join(parts, "\n"), nil
}

func anthropicBridgeMedia(block map[string]any) (map[string]any, error) {
	source, ok := block["source"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("media source must be an object")
	}
	if compatStringValue(block["type"]) == "image" {
		switch compatStringValue(source["type"]) {
		case "base64":
			mediaType, data := compatStringValue(source["media_type"]), compatStringValue(source["data"])
			if mediaType == "" || data == "" {
				return nil, fmt.Errorf("base64 image requires media_type and data")
			}
			if _, err := base64.StdEncoding.DecodeString(data); err != nil {
				return nil, fmt.Errorf("image data is not valid base64")
			}
			return map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:" + mediaType + ";base64," + data}}, nil
		case "url":
			if compatStringValue(source["url"]) == "" {
				return nil, fmt.Errorf("image URL is empty")
			}
			return map[string]any{"type": "image_url", "image_url": map[string]any{"url": source["url"]}}, nil
		default:
			return nil, fmt.Errorf("image source type %q is unsupported", compatStringValue(source["type"]))
		}
	}
	file := map[string]any{"type": "input_file"}
	filename := compatStringValue(block["title"])
	if filename == "" {
		filename = compatStringValue(block["filename"])
	}
	switch compatStringValue(source["type"]) {
	case "base64":
		data := compatStringValue(source["data"])
		if data == "" {
			return nil, fmt.Errorf("document base64 data is empty")
		}
		if _, err := base64.StdEncoding.DecodeString(data); err != nil {
			return nil, fmt.Errorf("document data is not valid base64")
		}
		if filename == "" {
			filename = "document"
		}
		file["file_data"] = source["data"]
	case "text":
		text := compatStringValue(source["text"])
		if text == "" {
			text = compatStringValue(source["data"])
		}
		if filename == "" {
			filename = "document.txt"
		}
		file["file_data"] = base64.StdEncoding.EncodeToString([]byte(text))
	case "file":
		if compatStringValue(source["file_id"]) == "" {
			return nil, fmt.Errorf("document file source requires file_id")
		}
		file["file_id"] = source["file_id"]
	case "url":
		if compatStringValue(source["url"]) == "" {
			return nil, fmt.Errorf("document URL is empty")
		}
		file["file_url"] = source["url"]
	default:
		return nil, fmt.Errorf("document source type %q is unsupported", compatStringValue(source["type"]))
	}
	if filename != "" {
		file["filename"] = filename
	}
	return file, nil
}

func anthropicBridgeToolResult(value any) (string, []any, error) {
	if text, ok := value.(string); ok {
		return text, nil, nil
	}
	texts, media := make([]string, 0), make([]any, 0)
	for _, raw := range anySlice(value) {
		block, ok := raw.(map[string]any)
		if !ok {
			return "", nil, fmt.Errorf("tool_result block must be an object")
		}
		if compatStringValue(block["type"]) == "text" {
			texts = append(texts, compatStringValue(block["text"]))
			continue
		}
		part, err := anthropicBridgeMedia(block)
		if err != nil {
			return "", nil, err
		}
		media = append(media, part)
	}
	return strings.Join(texts, "\n"), media, nil
}

func anthropicBridgeTools(value any) ([]any, error) {
	if value == nil {
		return nil, nil
	}
	rawTools, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("Anthropic tools must be an array")
	}
	result := make([]any, 0)
	for index, raw := range rawTools {
		tool, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("Anthropic tool %d must be an object", index)
		}
		name := compatStringValue(tool["name"])
		if name == "" {
			return nil, fmt.Errorf("Anthropic tool %d requires name", index)
		}
		schema, ok := tool["input_schema"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("Anthropic tool %q requires input_schema", name)
		}
		function := map[string]any{"name": name, "parameters": schema}
		if description, ok := tool["description"]; ok {
			function["description"] = description
		}
		if strict, ok := tool["strict"]; ok {
			function["strict"] = strict
		}
		result = append(result, map[string]any{"type": "function", "function": function})
	}
	return result, nil
}

func anthropicBridgeToolChoice(value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	choice, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Anthropic tool_choice must be an object")
	}
	switch compatStringValue(choice["type"]) {
	case "auto":
		return "auto", nil
	case "any":
		return "required", nil
	case "none":
		return "none", nil
	case "tool":
		name := compatStringValue(choice["name"])
		if name == "" {
			return nil, fmt.Errorf("Anthropic tool_choice tool requires name")
		}
		return map[string]any{"type": "function", "function": map[string]any{"name": name}}, nil
	default:
		return nil, fmt.Errorf("Anthropic tool_choice type %q is unsupported", compatStringValue(choice["type"]))
	}
}

func anthropicBridgeEffort(value any) string {
	number, ok := value.(json.Number)
	if !ok {
		return "high"
	}
	budget, err := number.Int64()
	if err != nil {
		return "high"
	}
	switch {
	case budget <= 2048:
		return "low"
	case budget <= 8192:
		return "medium"
	case budget <= 16384:
		return "high"
	default:
		return "xhigh"
	}
}

func transformChatResponseToAnthropicMessages(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, error) {
	var response map[string]any
	decoder := json.NewDecoder(bytes.NewReader(rawBody))
	decoder.UseNumber()
	if err := decoder.Decode(&response); err != nil {
		return nil, fmt.Errorf("decode OpenAI Chat response: %w", err)
	}
	choices := anySlice(response["choices"])
	if len(choices) == 0 {
		return nil, fmt.Errorf("OpenAI Chat response has no choices")
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("OpenAI Chat response choice is invalid")
	}
	message, ok := choice["message"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("OpenAI Chat response message is invalid")
	}
	content := make([]any, 0)
	if text := openAIContentText(message["content"]); text != "" {
		content = append(content, map[string]any{"type": "text", "text": text})
	}
	for _, rawCall := range anySlice(message["tool_calls"]) {
		call, _ := rawCall.(map[string]any)
		id, name, input, valid := openAIToolCall(call)
		if !valid {
			return nil, fmt.Errorf("OpenAI response contains an invalid tool call")
		}
		content = append(content, map[string]any{"type": "tool_use", "id": id, "name": name, "input": input})
	}
	if len(content) == 0 {
		content = append(content, map[string]any{"type": "text", "text": ""})
	}
	stopReason := "end_turn"
	if len(anySlice(message["tool_calls"])) > 0 || compatStringValue(choice["finish_reason"]) == "tool_calls" {
		stopReason = "tool_use"
	} else if compatStringValue(choice["finish_reason"]) == "length" {
		stopReason = "max_tokens"
	} else if reason := compatStringValue(choice["finish_reason"]); reason != "" && reason != "stop" {
		stopReason = reason
	}
	inputTokens, outputTokens := 0, 0
	if usage, ok := response["usage"].(map[string]any); ok {
		inputTokens, outputTokens = bridgeInt(usage["prompt_tokens"]), bridgeInt(usage["completion_tokens"])
	}
	modelName := compatStringValue(response["model"])
	if envelope != nil && strings.TrimSpace(envelope.Model) != "" {
		modelName = strings.TrimSpace(envelope.Model)
	}
	id := compatStringValue(response["id"])
	if id == "" {
		id = "msg_openai_bridge"
	}
	result := map[string]any{
		"id": id, "type": "message", "role": "assistant", "model": modelName,
		"content": content, "stop_reason": stopReason, "stop_sequence": nil,
		"usage": map[string]any{"input_tokens": inputTokens, "output_tokens": outputTokens},
	}
	if envelope != nil && envelope.Streaming {
		return encodeAnthropicBridgeSSE(result, content, stopReason, outputTokens), nil
	}
	return json.Marshal(result)
}

func bridgeInt(value any) int {
	if number, ok := value.(json.Number); ok {
		parsed, _ := number.Int64()
		return int(parsed)
	}
	return 0
}

func encodeAnthropicBridgeSSE(message map[string]any, content []any, stopReason string, outputTokens int) []byte {
	var buffer bytes.Buffer
	event := func(name string, payload any) {
		data, _ := json.Marshal(payload)
		fmt.Fprintf(&buffer, "event: %s\n", name)
		fmt.Fprintf(&buffer, "data: %s\n\n", data)
	}
	start := make(map[string]any, len(message))
	for key, value := range message {
		start[key] = value
	}
	start["content"] = []any{}
	event("message_start", map[string]any{"type": "message_start", "message": start})
	for index, raw := range content {
		block, _ := raw.(map[string]any)
		if compatStringValue(block["type"]) == "tool_use" {
			event("content_block_start", map[string]any{
				"type": "content_block_start", "index": index,
				"content_block": map[string]any{
					"type": "tool_use", "id": block["id"], "name": block["name"], "input": map[string]any{},
				},
			})
			input, _ := json.Marshal(block["input"])
			event("content_block_delta", map[string]any{
				"type": "content_block_delta", "index": index,
				"delta": map[string]any{"type": "input_json_delta", "partial_json": string(input)},
			})
		} else {
			event("content_block_start", map[string]any{
				"type": "content_block_start", "index": index,
				"content_block": map[string]any{"type": "text", "text": ""},
			})
			if text := compatStringValue(block["text"]); text != "" {
				event("content_block_delta", map[string]any{
					"type": "content_block_delta", "index": index,
					"delta": map[string]any{"type": "text_delta", "text": text},
				})
			}
		}
		event("content_block_stop", map[string]any{"type": "content_block_stop", "index": index})
	}
	event("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": stopReason, "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": outputTokens},
	})
	event("message_stop", map[string]any{"type": "message_stop"})
	return buffer.Bytes()
}
