package provider

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	modelrouter "github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func responsesBridgeStreamToJSON(raw []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), maxNativeResponsesSSEBytes+1)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		var event struct {
			Type     string          `json:"type"`
			Response json.RawMessage `json:"response"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return nil, fmt.Errorf("parse Responses bridge stream event: %w", err)
		}
		switch event.Type {
		case "response.completed", "response.done", "response.incomplete":
			if len(event.Response) == 0 || string(event.Response) == "null" {
				return nil, fmt.Errorf("Responses bridge stream terminal event has no response")
			}
			return append([]byte(nil), event.Response...), nil
		case "response.failed", "response.error":
			return nil, fmt.Errorf("Responses bridge stream failed: %s", data)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Responses bridge stream: %w", err)
	}
	return nil, fmt.Errorf("Responses bridge stream has no terminal response")
}

func usesChatResponsesBridge(envelope *modelrouter.RequestEnvelope) bool {
	if envelope == nil || envelope.EndpointType != "chat" {
		return false
	}
	c := envelope.ProtocolCapabilities
	if strings.EqualFold(strings.TrimSpace(envelope.UpstreamProtocol), "responses") {
		return c.ResponsesNative && !c.Gemini
	}
	return c.ChatResponsesBridge && c.ResponsesNative && !c.ChatCompletions && !c.Gemini
}

func usesOpenAIResponsesBridge(envelope *modelrouter.RequestEnvelope) bool {
	return usesChatResponsesBridge(envelope) || usesMessagesResponsesBridge(envelope)
}

type chatBridgeMessage struct {
	Role       string               `json:"role"`
	Content    json.RawMessage      `json:"content"`
	ToolCalls  []chatBridgeToolCall `json:"tool_calls,omitempty"`
	ToolCallID string               `json:"tool_call_id,omitempty"`
}

type chatBridgeToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

func transformChatCompletionsToResponses(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, error) {
	var chat struct {
		Model               string              `json:"model"`
		Messages            []chatBridgeMessage `json:"messages"`
		Tools               []json.RawMessage   `json:"tools"`
		ToolChoice          json.RawMessage     `json:"tool_choice"`
		Stream              bool                `json:"stream"`
		N                   *int                `json:"n"`
		MaxTokens           *int                `json:"max_tokens"`
		MaxCompletionTokens *int                `json:"max_completion_tokens"`
		Temperature         *float64            `json:"temperature"`
		TopP                *float64            `json:"top_p"`
		FrequencyPenalty    *float64            `json:"frequency_penalty"`
		PresencePenalty     *float64            `json:"presence_penalty"`
		ReasoningEffort     string              `json:"reasoning_effort"`
		ResponseFormat      json.RawMessage     `json:"response_format"`
		ParallelToolCalls   *bool               `json:"parallel_tool_calls"`
		Store               *bool               `json:"store"`
		Metadata            json.RawMessage     `json:"metadata"`
		User                json.RawMessage     `json:"user"`
		PromptCacheKey      string              `json:"prompt_cache_key"`
		EnableThinking      json.RawMessage     `json:"enable_thinking"`
		ThinkingBudget      json.RawMessage     `json:"thinking_budget"`
	}
	decoder := json.NewDecoder(bytes.NewReader(rawBody))
	decoder.UseNumber()
	if err := decoder.Decode(&chat); err != nil {
		return nil, fmt.Errorf("parse Chat request for Responses bridge: %w", err)
	}
	modelName := strings.TrimSpace(chat.Model)
	if envelope != nil && strings.TrimSpace(envelope.UpstreamModelID) != "" {
		modelName = strings.TrimSpace(envelope.UpstreamModelID)
	}
	if modelName == "" {
		return nil, fmt.Errorf("Chat request model is required for Responses bridge")
	}
	if chat.N != nil && *chat.N > 1 {
		return nil, fmt.Errorf("Chat n>1 is not supported in Responses compatibility mode")
	}

	responsesRequest := map[string]any{"model": modelName}
	var instructions []string
	input := make([]map[string]any, 0, len(chat.Messages))
	for index, message := range chat.Messages {
		switch message.Role {
		case "system", "developer":
			text, err := chatContentText(message.Content)
			if err != nil {
				return nil, fmt.Errorf("Chat system message %d cannot be converted: %w", index, err)
			}
			if text = strings.TrimSpace(text); text != "" {
				instructions = append(instructions, text)
			}
			continue
		case "tool", "function":
			output, err := chatToolOutputValue(message.Content)
			if err != nil {
				return nil, fmt.Errorf("Chat tool message %d cannot be converted: %w", index, err)
			}
			if message.ToolCallID == "" {
				input = append(input, map[string]any{
					"role":    "user",
					"content": fmt.Sprintf("[tool_output_missing_call_id] %v", output),
				})
				continue
			}
			input = append(input, map[string]any{
				"type":    "function_call_output",
				"call_id": message.ToolCallID,
				"output":  output,
			})
			continue
		}

		if strings.TrimSpace(message.Role) == "" {
			continue
		}
		if len(bytes.TrimSpace(message.Content)) == 0 || string(bytes.TrimSpace(message.Content)) == "null" {
			input = append(input, map[string]any{"role": message.Role, "content": ""})
		} else {
			content, err := responsesInputContent(message.Role, message.Content)
			if err != nil {
				return nil, fmt.Errorf("Chat message %d cannot be converted: %w", index, err)
			}
			input = append(input, map[string]any{"role": message.Role, "content": content})
		}
		if message.Role == "assistant" {
			for _, call := range message.ToolCalls {
				if strings.TrimSpace(call.ID) == "" || strings.TrimSpace(call.Function.Name) == "" {
					continue
				}
				if call.Type != "" && call.Type != "function" {
					continue
				}
				input = append(input, map[string]any{
					"type":      "function_call",
					"call_id":   call.ID,
					"name":      call.Function.Name,
					"arguments": call.Function.Arguments,
				})
			}
		}
	}
	if len(input) == 0 && len(instructions) == 0 {
		return nil, fmt.Errorf("Chat request has no convertible messages")
	}
	responsesRequest["input"] = input
	if len(instructions) > 0 {
		responsesRequest["instructions"] = strings.Join(instructions, "\n\n")
	}
	maxOutputTokens := 0
	if chat.MaxTokens != nil {
		maxOutputTokens = *chat.MaxTokens
	}
	if chat.MaxCompletionTokens != nil && *chat.MaxCompletionTokens > maxOutputTokens {
		maxOutputTokens = *chat.MaxCompletionTokens
	}
	if chat.MaxTokens != nil || chat.MaxCompletionTokens != nil {
		responsesRequest["max_output_tokens"] = maxOutputTokens
	}
	if chat.Temperature != nil {
		responsesRequest["temperature"] = *chat.Temperature
	}
	if chat.TopP != nil {
		responsesRequest["top_p"] = *chat.TopP
	}
	if chat.FrequencyPenalty != nil {
		responsesRequest["frequency_penalty"] = *chat.FrequencyPenalty
	}
	if chat.PresencePenalty != nil {
		responsesRequest["presence_penalty"] = *chat.PresencePenalty
	}
	if chat.ReasoningEffort != "" {
		responsesRequest["reasoning"] = map[string]any{"effort": chat.ReasoningEffort, "summary": "detailed"}
	}
	if len(bytes.TrimSpace(chat.ResponseFormat)) > 0 && string(bytes.TrimSpace(chat.ResponseFormat)) != "null" {
		textFormat, err := responsesTextFormat(chat.ResponseFormat)
		if err != nil {
			return nil, err
		}
		responsesRequest["text"] = map[string]any{"format": textFormat}
	}
	if chat.ParallelToolCalls != nil {
		responsesRequest["parallel_tool_calls"] = *chat.ParallelToolCalls
	}
	if chat.Store != nil {
		responsesRequest["store"] = *chat.Store
	}
	if len(bytes.TrimSpace(chat.Metadata)) > 0 && string(bytes.TrimSpace(chat.Metadata)) != "null" {
		var metadata any
		if err := json.Unmarshal(chat.Metadata, &metadata); err != nil {
			return nil, fmt.Errorf("Chat metadata is invalid: %w", err)
		}
		responsesRequest["metadata"] = metadata
	}
	copyRawJSONField(responsesRequest, "user", chat.User)
	if chat.PromptCacheKey != "" {
		responsesRequest["prompt_cache_key"] = chat.PromptCacheKey
	}
	copyRawJSONField(responsesRequest, "enable_thinking", chat.EnableThinking)
	copyRawJSONField(responsesRequest, "thinking_budget", chat.ThinkingBudget)
	if raw, ok := rawField(rawBody, "stream"); ok {
		var stream bool
		if err := json.Unmarshal(raw, &stream); err != nil {
			return nil, fmt.Errorf("Chat stream must be a boolean")
		}
		responsesRequest["stream"] = stream
	}
	if chat.Tools != nil {
		tools := make([]map[string]any, 0, len(chat.Tools))
		for index, rawTool := range chat.Tools {
			var tool map[string]any
			if err := json.Unmarshal(rawTool, &tool); err != nil {
				return nil, fmt.Errorf("Chat tool %d is invalid: %w", index, err)
			}
			toolType, _ := tool["type"].(string)
			if toolType != "function" {
				tools = append(tools, tool)
				continue
			}
			function, ok := tool["function"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("Chat tool %d is missing function", index)
			}
			name, _ := function["name"].(string)
			if strings.TrimSpace(name) == "" {
				return nil, fmt.Errorf("Chat tool %d function name is missing", index)
			}
			responsesTool := map[string]any{
				"type": "function",
				"name": name,
			}
			if description, ok := function["description"]; ok {
				responsesTool["description"] = description
			}
			if parameters, ok := function["parameters"]; ok && parameters != nil {
				responsesTool["parameters"] = parameters
			} else {
				responsesTool["parameters"] = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			if strict, ok := function["strict"]; ok {
				responsesTool["strict"] = strict
			}
			tools = append(tools, responsesTool)
		}
		responsesRequest["tools"] = tools
	}
	if len(chat.ToolChoice) > 0 && string(chat.ToolChoice) != "null" {
		toolChoice, err := responsesToolChoice(chat.ToolChoice)
		if err != nil {
			return nil, err
		}
		responsesRequest["tool_choice"] = toolChoice
	}
	return json.Marshal(responsesRequest)
}

func copyRawJSONField(dst map[string]any, name string, raw json.RawMessage) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return
	}
	var value any
	if json.Unmarshal(raw, &value) == nil {
		dst[name] = value
	}
}

func chatToolOutputValue(raw json.RawMessage) (string, error) {
	value, err := chatContentValue(raw)
	if err != nil {
		return "", err
	}
	if text, ok := value.(string); ok {
		return text, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func responsesTextFormat(raw json.RawMessage) (map[string]any, error) {
	var chatFormat map[string]any
	if err := json.Unmarshal(raw, &chatFormat); err != nil {
		return nil, fmt.Errorf("Chat response_format is invalid: %w", err)
	}
	typ, _ := chatFormat["type"].(string)
	switch typ {
	case "text", "json_object":
		return map[string]any{"type": typ}, nil
	case "json_schema":
		schema, ok := chatFormat["json_schema"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("Chat json_schema response_format is missing json_schema")
		}
		result := map[string]any{"type": "json_schema"}
		for _, key := range []string{"name", "description", "schema", "strict"} {
			if value, ok := schema[key]; ok {
				result[key] = value
			}
		}
		if _, ok := result["name"]; !ok || result["name"] == "" {
			return nil, fmt.Errorf("Chat json_schema response_format is missing json_schema.name")
		}
		if _, ok := result["schema"]; !ok {
			return nil, fmt.Errorf("Chat json_schema response_format is missing json_schema.schema")
		}
		return result, nil
	default:
		return nil, fmt.Errorf("Chat response_format type %q is unsupported for Responses bridge", typ)
	}
}

func rawField(rawBody []byte, name string) (json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &fields); err != nil {
		return nil, false
	}
	value, ok := fields[name]
	return value, ok
}

func chatContentValue(raw json.RawMessage) (any, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return "", nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if text, ok := value.(string); ok {
		return text, nil
	}
	return value, nil
}

func chatContentText(raw json.RawMessage) (string, error) {
	value, err := chatContentValue(raw)
	if err != nil {
		return "", err
	}
	if text, ok := value.(string); ok {
		return text, nil
	}
	parts, ok := value.([]any)
	if !ok {
		return "", fmt.Errorf("content must be a string or content-part array")
	}
	var text strings.Builder
	for _, part := range parts {
		object, ok := part.(map[string]any)
		if !ok {
			return "", fmt.Errorf("content part must be an object")
		}
		if partText, ok := object["text"].(string); ok && strings.TrimSpace(partText) != "" {
			if text.Len() > 0 {
				text.WriteString("\n")
			}
			text.WriteString(partText)
		}
	}
	return text.String(), nil
}

func responsesInputContent(role string, raw json.RawMessage) (any, error) {
	value, err := chatContentValue(raw)
	if err != nil {
		return nil, err
	}
	if text, ok := value.(string); ok {
		return text, nil
	}
	parts, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("content must be a string or content-part array")
	}
	result := make([]map[string]any, 0, len(parts))
	for index, part := range parts {
		object, ok := part.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("content part %d must be an object", index)
		}
		switch object["type"] {
		case "text", "input_text":
			text, ok := object["text"].(string)
			if !ok {
				return nil, fmt.Errorf("content part %d text is missing", index)
			}
			textType := "input_text"
			if role == "assistant" {
				textType = "output_text"
			}
			result = append(result, map[string]any{"type": textType, "text": text})
		case "image_url":
			imageURL := object["image_url"]
			detail := ""
			switch image := imageURL.(type) {
			case string:
				imageURL = image
			case map[string]any:
				imageURL = image["url"]
				detail, _ = image["detail"].(string)
			}
			if imageURL == nil {
				return nil, fmt.Errorf("content part %d image_url is missing", index)
			}
			imagePart := map[string]any{"type": "input_image", "image_url": imageURL}
			if detail != "" {
				imagePart["detail"] = detail
			}
			result = append(result, imagePart)
		case "input_image":
			result = append(result, object)
		case "input_audio":
			result = append(result, object)
		case "file", "input_file":
			cloned := make(map[string]any, len(object))
			for key, value := range object {
				cloned[key] = value
			}
			cloned["type"] = "input_file"
			result = append(result, cloned)
		case "video_url", "input_video":
			cloned := make(map[string]any, len(object))
			for key, value := range object {
				cloned[key] = value
			}
			cloned["type"] = "input_video"
			result = append(result, cloned)
		default:
			result = append(result, object)
		}
	}
	return result, nil
}

func responsesToolChoice(raw json.RawMessage) (any, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("Chat tool_choice is invalid: %w", err)
	}
	if text, ok := value.(string); ok {
		return text, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Chat tool_choice must be a string or object")
	}
	if object["type"] != "function" {
		return object, nil
	}
	function, ok := object["function"].(map[string]any)
	if !ok || function["name"] == "" {
		return nil, fmt.Errorf("Chat function tool_choice is missing function.name")
	}
	return map[string]any{"type": "function", "name": function["name"]}, nil
}

type responsesBridgeResponse struct {
	ID                string                           `json:"id"`
	CreatedAt         int64                            `json:"created_at"`
	Status            string                           `json:"status"`
	Model             string                           `json:"model"`
	Output            []responsesBridgeOutput          `json:"output"`
	Usage             *responsesBridgeUsage            `json:"usage"`
	Error             json.RawMessage                  `json:"error"`
	IncompleteDetails *responsesBridgeIncompleteDetail `json:"incomplete_details"`
}

type responsesBridgeOutput struct {
	ID        string                   `json:"id"`
	Type      string                   `json:"type"`
	Role      string                   `json:"role"`
	CallID    string                   `json:"call_id"`
	Name      string                   `json:"name"`
	Arguments json.RawMessage          `json:"arguments"`
	Input     json.RawMessage          `json:"input"`
	Content   []responsesBridgeContent `json:"content"`
	Summary   []responsesBridgeContent `json:"summary"`
}

type responsesBridgeContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type responsesBridgeIncompleteDetail struct {
	Reason string `json:"reason"`
}

type responsesBridgeUsage struct {
	InputTokens         int            `json:"input_tokens"`
	OutputTokens        int            `json:"output_tokens"`
	TotalTokens         int            `json:"total_tokens"`
	InputTokensDetails  map[string]any `json:"input_tokens_details"`
	OutputTokensDetails map[string]any `json:"output_tokens_details"`
}

func (a *OpenAIAdapter) TransformResponseForEnvelope(envelope *modelrouter.RequestEnvelope, respBody []byte) ([]byte, error) {
	if usesOpenAIResponsesBridge(envelope) {
		chatBody, err := transformResponsesResponseToChat(envelope, respBody)
		if err != nil {
			return nil, err
		}
		respBody = chatBody
	}
	chatBody, err := restoreChatToolNames(respBody, a.toolNames)
	if err != nil {
		return nil, err
	}
	if usesMessagesOpenAIBridge(envelope) {
		return transformChatResponseToAnthropicMessages(envelope, chatBody)
	}
	return chatBody, nil
}

func transformResponsesResponseToChat(envelope *modelrouter.RequestEnvelope, respBody []byte) ([]byte, error) {
	var response responsesBridgeResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("parse Responses response for Chat bridge: %w", err)
	}
	if len(response.Error) > 0 && string(response.Error) != "null" {
		return nil, fmt.Errorf("Responses upstream returned an error: %s", response.Error)
	}
	if response.Status == "failed" || response.Status == "cancelled" || response.Status == "canceled" {
		return nil, fmt.Errorf("Responses upstream completed with status %q", response.Status)
	}

	var preferredText strings.Builder
	var fallbackText strings.Builder
	var reasoning strings.Builder
	toolCalls := make([]map[string]any, 0)
	for _, item := range response.Output {
		for _, content := range item.Content {
			if content.Text != "" {
				fallbackText.WriteString(content.Text)
			}
		}
		switch item.Type {
		case "message", "":
			for _, content := range item.Content {
				if (item.Role == "" || item.Role == "assistant") && content.Type == "output_text" {
					preferredText.WriteString(content.Text)
				}
			}
		case "reasoning":
			for _, content := range item.Content {
				if content.Text != "" {
					reasoning.WriteString(content.Text)
				}
			}
			for _, content := range item.Summary {
				if content.Text != "" {
					reasoning.WriteString(content.Text)
				}
			}
		case "function_call", "custom_tool_call":
			if strings.TrimSpace(item.Name) == "" {
				continue
			}
			callID := item.CallID
			if callID == "" {
				callID = item.ID
			}
			arguments := responsesArgumentsString(item.Arguments)
			if arguments == "" && item.Type == "custom_tool_call" {
				arguments = responsesArgumentsString(item.Input)
			}
			toolCalls = append(toolCalls, map[string]any{
				"id":   callID,
				"type": "function",
				"function": map[string]any{
					"name":      item.Name,
					"arguments": arguments,
				},
			})
		}
	}
	text := preferredText.String()
	if text == "" {
		text = fallbackText.String()
	}
	modelName := response.Model
	if envelope != nil && envelope.Model != "" {
		modelName = envelope.Model
	}
	choiceMessage := map[string]any{"role": "assistant", "content": text}
	if reasoning.Len() > 0 {
		choiceMessage["reasoning_content"] = reasoning.String()
	}
	finishReason := "stop"
	if len(toolCalls) > 0 {
		choiceMessage["tool_calls"] = toolCalls
		finishReason = "tool_calls"
	}
	if response.Status == "incomplete" {
		finishReason = "length"
		if response.IncompleteDetails != nil && response.IncompleteDetails.Reason == "content_filter" {
			finishReason = "content_filter"
		}
	}
	responseID := response.ID
	if responseID == "" {
		responseID = "chatcmpl_bridge"
	}
	usage := map[string]any{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
	if response.Usage != nil {
		usage["prompt_tokens"] = response.Usage.InputTokens
		usage["completion_tokens"] = response.Usage.OutputTokens
		totalTokens := response.Usage.TotalTokens
		if totalTokens == 0 {
			totalTokens = response.Usage.InputTokens + response.Usage.OutputTokens
		}
		usage["total_tokens"] = totalTokens
		if response.Usage.InputTokensDetails != nil {
			usage["prompt_tokens_details"] = response.Usage.InputTokensDetails
		}
		if response.Usage.OutputTokensDetails != nil {
			usage["completion_tokens_details"] = response.Usage.OutputTokensDetails
		}
	}
	return json.Marshal(map[string]any{
		"id":      responseID,
		"object":  "chat.completion",
		"created": response.CreatedAt,
		"model":   modelName,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       choiceMessage,
			"finish_reason": finishReason,
		}},
		"usage": usage,
	})
}

func responsesArgumentsString(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	if trimmed[0] != '"' {
		return string(trimmed)
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return string(trimmed)
	}
	return value
}
