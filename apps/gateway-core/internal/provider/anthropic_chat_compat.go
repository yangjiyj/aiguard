package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func transformOpenAIChatToAnthropic(envelope *modelrouter.RequestEnvelope, rawBody []byte) ([]byte, *compatibleToolNameMap, error) {
	normalized, nameMap, err := normalizeChatToolNames(rawBody)
	if err != nil {
		return nil, nil, err
	}
	var openAI map[string]any
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	decoder.UseNumber()
	if err := decoder.Decode(&openAI); err != nil {
		return nil, nil, fmt.Errorf("decode OpenAI Chat request for Anthropic provider: %w", err)
	}

	modelName, _ := openAI["model"].(string)
	clientModel := modelName
	envelopeModel := ""
	if envelope != nil {
		envelopeModel = envelope.Model
		if strings.TrimSpace(envelope.UpstreamModelID) != "" {
			modelName = envelope.UpstreamModelID
		}
	}
	// 上游真正执行的模型 id 优先；供应商别名认不出来时退回客户端请求的模型名。
	profile := anthropicRequestModelProfile(modelName, envelopeModel, clientModel)
	request := map[string]any{
		"model":      modelName,
		"max_tokens": firstPresent(openAI, "max_tokens", "max_completion_tokens", 4096),
	}
	clampAnthropicMaxTokens(request, profile)
	if value, ok := openAI["stream"]; ok {
		request["stream"] = value
	}
	applyOpenAISamplingControls(openAI, request, profile)
	if err := applyOpenAIReasoningControls(openAI, request, profile); err != nil {
		return nil, nil, err
	}
	if err := applyOpenAIResponseFormat(openAI, request); err != nil {
		return nil, nil, err
	}
	if stop, ok := openAI["stop"]; ok {
		switch value := stop.(type) {
		case string:
			request["stop_sequences"] = []any{value}
		case []any:
			request["stop_sequences"] = value
		}
	}

	systemParts := make([]string, 0)
	var systemCacheControl any
	messages := make([]any, 0)
	for _, rawMessage := range anySlice(openAI["messages"]) {
		message, _ := rawMessage.(map[string]any)
		if message == nil {
			continue
		}
		role, _ := message["role"].(string)
		switch role {
		case "system", "developer":
			if text := openAIContentText(message["content"]); strings.TrimSpace(text) != "" {
				systemParts = append(systemParts, text)
			}
			if systemCacheControl == nil {
				systemCacheControl = openAIContentCacheControl(message["content"])
			}
		case "tool":
			toolUseID := compatStringValue(message["tool_call_id"])
			if toolUseID == "" {
				return nil, nil, fmt.Errorf("OpenAI Chat tool result is missing tool_call_id")
			}
			converted := map[string]any{
				"role": "user",
				"content": []any{map[string]any{
					"type":        "tool_result",
					"tool_use_id": toolUseID,
					"content":     anthropicToolResultContent(message["content"]),
				}},
			}
			messages = appendOrMergeAnthropicToolResult(messages, converted)
		case "assistant":
			// 空的 assistant 轮（客户端中断后常见）在 Messages API 里是 400，直接丢弃。
			if converted, ok := convertOpenAIAssistantMessage(message); ok {
				messages = append(messages, converted)
			}
		default:
			content := convertOpenAIContent(message["content"])
			if anthropicContentEmpty(content) {
				continue
			}
			messages = append(messages, map[string]any{
				"role":    "user",
				"content": content,
			})
		}
	}
	request["messages"] = messages
	if len(systemParts) > 0 {
		systemText := strings.Join(systemParts, "\n\n")
		if systemCacheControl != nil {
			// 客户端在 system 上打的缓存标记原样保留（拍平成字符串会把它丢掉）。
			request["system"] = []any{map[string]any{"type": "text", "text": systemText, "cache_control": systemCacheControl}}
		} else {
			request["system"] = systemText
		}
	}

	if tools := convertOpenAITools(openAI["tools"]); len(tools) > 0 {
		request["tools"] = tools
	}
	applyAnthropicChatPromptCache(request, openAI["cache_control"])
	choice, choiceErr := convertOpenAIToolChoice(openAI["tool_choice"])
	if choiceErr != nil {
		return nil, nil, choiceErr
	}
	if choice != nil {
		request["tool_choice"] = choice
	}
	if parallel, ok := openAI["parallel_tool_calls"].(bool); ok && !parallel {
		choice, _ := request["tool_choice"].(map[string]any)
		if choice == nil {
			if _, hasTools := request["tools"]; hasTools {
				choice = map[string]any{"type": "auto"}
			}
		}
		if choice != nil && choice["type"] != "none" {
			choice["disable_parallel_tool_use"] = true
			request["tool_choice"] = choice
		}
	}

	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, nil, fmt.Errorf("encode Anthropic Messages request: %w", err)
	}
	return encoded, nameMap, nil
}

// applyOpenAISamplingControls 只转发上游还接受的采样参数。
// Opus 4.7+/Sonnet 5/Fable 已移除 temperature/top_p/top_k（非默认值 400）；
// Claude 4 系列两者只能二选一；Anthropic 的 temperature 取值是 0~1 而 OpenAI 允许到 2。
func applyOpenAISamplingControls(openAI, request map[string]any, profile anthropicModelProfile) {
	if profile.RejectsSampling {
		return
	}
	if raw, ok := openAI["temperature"]; ok && raw != nil {
		if value, isNumber := anthropicFloatValue(raw); isNumber {
			if value > 1 {
				value = 1
			}
			if value < 0 {
				value = 0
			}
			request["temperature"] = value
		} else {
			request["temperature"] = raw
		}
		return
	}
	if raw, ok := openAI["top_p"]; ok && raw != nil {
		request["top_p"] = raw
	}
}

// applyOpenAIReasoningControls translates the reasoning extensions used by
// OpenAI-compatible agent clients into the current Anthropic Messages
// controls. The mapping is capability based; the model profile only decides
// which of the two Anthropic thinking dialects (adaptive+effort vs.
// enabled+budget_tokens) the upstream still accepts.
func applyOpenAIReasoningControls(openAI, request map[string]any, profile anthropicModelProfile) error {
	effort := ""
	if raw, exists := openAI["reasoning_effort"]; exists {
		value, ok := raw.(string)
		if !ok {
			return fmt.Errorf("OpenAI reasoning_effort must be a string")
		}
		effort = normalizeAnthropicEffort(value)
		if effort == "" && strings.TrimSpace(value) != "" {
			return fmt.Errorf("OpenAI reasoning_effort %q is not supported by Anthropic Messages", value)
		}
	}
	if raw, exists := openAI["reasoning"]; exists {
		config, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("OpenAI reasoning must be an object")
		}
		if value, exists := config["effort"]; exists {
			text, ok := value.(string)
			if !ok {
				return fmt.Errorf("OpenAI reasoning.effort must be a string")
			}
			normalized := normalizeAnthropicEffort(text)
			if normalized == "" && strings.TrimSpace(text) != "" {
				return fmt.Errorf("OpenAI reasoning.effort %q is not supported by Anthropic Messages", text)
			}
			if effort == "" {
				effort = normalized
			}
		}
	}

	if native, exists := openAI["thinking"]; exists {
		config, ok := native.(map[string]any)
		if !ok {
			return fmt.Errorf("Anthropic thinking extension must be an object")
		}
		thinkingType := strings.ToLower(strings.TrimSpace(compatStringValue(config["type"])))
		if thinkingType == "" {
			return fmt.Errorf("Anthropic thinking extension is missing type")
		}
		cloned := make(map[string]any, len(config))
		for key, value := range config {
			cloned[key] = value
		}
		switch thinkingType {
		case "enabled":
			// 4.6 起 budget_tokens 弃用、4.7 起直接 400：换成 adaptive，预算折算成 effort。
			if profile.AdaptiveThinking {
				if effort == "" {
					effort = anthropicEffortFromBudget(config["budget_tokens"])
				}
				delete(cloned, "budget_tokens")
				cloned["type"] = "adaptive"
			}
		case "disabled":
			// Fable/Mythos 的 thinking 不能关，显式 disabled 会 400，只能省略。
			if profile.ThinkingAlwaysOn {
				cloned = nil
			}
		case "adaptive":
			// 老模型只认 enabled + budget_tokens。
			if profile.legacyThinking() {
				cloned = map[string]any{"type": "enabled", "budget_tokens": legacyThinkingBudget(effort)}
			}
		}
		if cloned != nil {
			request["thinking"] = cloned
		}
	} else if raw, exists := openAI["enable_thinking"]; exists {
		enabled, ok := raw.(bool)
		if !ok {
			return fmt.Errorf("OpenAI enable_thinking must be a boolean")
		}
		switch {
		case enabled && profile.legacyThinking():
			budget, ok := anthropicIntValue(openAI["thinking_budget"])
			if !ok || budget <= 0 {
				budget = int64(legacyThinkingBudget(effort))
			}
			request["thinking"] = map[string]any{"type": "enabled", "budget_tokens": budget}
		case enabled:
			if effort == "" {
				effort = anthropicEffortFromBudget(openAI["thinking_budget"])
			}
			request["thinking"] = map[string]any{"type": "adaptive"}
		case !profile.ThinkingAlwaysOn:
			request["thinking"] = map[string]any{"type": "disabled"}
		}
	}

	if effort == "none" {
		if profile.ThinkingAlwaysOn {
			delete(request, "thinking")
		} else {
			request["thinking"] = map[string]any{"type": "disabled"}
		}
		return nil
	}
	if effort != "" {
		if profile.legacyThinking() {
			// 老模型不认 output_config.effort，effort 折算成 budget_tokens。
			if _, has := request["thinking"]; !has {
				request["thinking"] = map[string]any{"type": "enabled", "budget_tokens": legacyThinkingBudget(effort)}
			}
		} else if !anthropicThinkingDisabled(request) {
			// thinking 关掉时 effort 没有意义，而且 Opus 5 上 disabled + xhigh/max 会 400。
			output, _ := request["output_config"].(map[string]any)
			if output == nil {
				output = map[string]any{}
			}
			output["effort"] = effort
			request["output_config"] = output
		}
	}
	if profile.legacyThinking() {
		fitLegacyThinkingBudget(request)
	}
	return nil
}

func anthropicThinkingDisabled(request map[string]any) bool {
	thinking, _ := request["thinking"].(map[string]any)
	return thinking != nil && strings.EqualFold(compatStringValue(thinking["type"]), "disabled")
}

// legacyThinkingBudget 把 effort 档位换算成老模型的 budget_tokens。
func legacyThinkingBudget(effort string) int {
	switch effort {
	case "low":
		return 2048
	case "high":
		return 16384
	case "xhigh", "max":
		return 32000
	default:
		return 8192
	}
}

// fitLegacyThinkingBudget 保证 budget_tokens 满足上游约束：至少 1024 且小于 max_tokens；
// 塞不下时宁可不开 thinking，也不要让整个请求 400。
func fitLegacyThinkingBudget(request map[string]any) {
	thinking, _ := request["thinking"].(map[string]any)
	if thinking == nil || !strings.EqualFold(compatStringValue(thinking["type"]), "enabled") {
		return
	}
	budget, ok := anthropicIntValue(thinking["budget_tokens"])
	if !ok {
		return
	}
	if maxTokens, ok := anthropicIntValue(request["max_tokens"]); ok && budget >= maxTokens {
		budget = maxTokens - 1
	}
	if budget < 1024 {
		delete(request, "thinking")
		return
	}
	thinking["budget_tokens"] = budget
}

// applyOpenAIResponseFormat maps the portable Chat JSON Schema shape to the
// current Anthropic output_config.format contract. json_object has no schema,
// so it fails closed instead of pretending to provide structured output.
func applyOpenAIResponseFormat(openAI, request map[string]any) error {
	raw, exists := openAI["response_format"]
	if !exists || raw == nil {
		return nil
	}
	format, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("OpenAI response_format must be an object")
	}
	switch compatStringValue(format["type"]) {
	case "", "text":
		return nil
	case "json_schema":
		definition, ok := format["json_schema"].(map[string]any)
		if !ok || definition["schema"] == nil {
			return fmt.Errorf("OpenAI json_schema response_format is missing json_schema.schema")
		}
		output, _ := request["output_config"].(map[string]any)
		if output == nil {
			output = map[string]any{}
		}
		output["format"] = map[string]any{"type": "json_schema", "schema": definition["schema"]}
		request["output_config"] = output
		return nil
	case "json_object":
		return fmt.Errorf("OpenAI json_object response_format has no schema for Anthropic structured output")
	default:
		return fmt.Errorf("OpenAI response_format type %q is unsupported by Anthropic Messages", compatStringValue(format["type"]))
	}
}

func normalizeAnthropicEffort(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "none":
		return "none"
	case "minimal":
		return "low"
	case "low", "medium", "high", "xhigh", "max":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

// thinking_budget is a legacy OpenAI-compatible hint. Current Anthropic
// Messages models use adaptive thinking plus effort instead of a fixed budget.
func anthropicEffortFromBudget(raw any) string {
	value, ok := anthropicIntValue(raw)
	if !ok || value <= 0 {
		return ""
	}
	switch {
	case value <= 2048:
		return "low"
	case value <= 8192:
		return "medium"
	case value <= 16384:
		return "high"
	case value <= 32768:
		return "xhigh"
	default:
		return "max"
	}
}

func firstPresent(body map[string]any, primary, secondary string, fallback any) any {
	if value, ok := body[primary]; ok && value != nil {
		return value
	}
	if value, ok := body[secondary]; ok && value != nil {
		return value
	}
	return fallback
}

func convertOpenAITools(raw any) []any {
	tools := make([]any, 0)
	for _, item := range anySlice(raw) {
		tool, _ := item.(map[string]any)
		function := openAIToolDefinition(tool)
		if function == nil {
			continue
		}
		name, _ := function["name"].(string)
		if name == "" {
			continue
		}
		schema, _ := function["parameters"].(map[string]any)
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		strict, _ := function["strict"].(bool)
		cleanAnthropicToolSchema(schema, strict)
		converted := map[string]any{"name": name, "input_schema": schema}
		if strict, ok := function["strict"].(bool); ok {
			converted["strict"] = strict
		}
		if description, ok := function["description"].(string); ok {
			converted["description"] = description
		}
		if cacheControl := firstNonNil(tool["cache_control"], function["cache_control"]); cacheControl != nil {
			converted["cache_control"] = cacheControl
		}
		tools = append(tools, converted)
	}
	return tools
}

// cleanAnthropicToolSchema 仅清理 schema 节点，不删除同名属性或 default/enum 中的业务数据。
// 非 strict 时按最小兼容范围仅删除 maxItems/minItems；strict 时再清理其余不支持约束。
func cleanAnthropicToolSchema(schema map[string]any, strict bool) {
	for _, key := range []string{"maxItems", "minItems"} {
		delete(schema, key)
	}
	if strict {
		for _, key := range []string{"uniqueItems", "contains", "$schema", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minLength", "maxLength", "pattern"} {
			delete(schema, key)
		}
	}
	for _, key := range []string{"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"} {
		if entries, ok := schema[key].(map[string]any); ok {
			for _, entry := range entries {
				if child, ok := entry.(map[string]any); ok {
					cleanAnthropicToolSchema(child, strict)
				}
			}
		}
	}
	for _, key := range []string{"items", "prefixItems", "allOf", "anyOf", "oneOf", "not", "if", "then", "else", "additionalProperties", "additionalItems", "unevaluatedProperties", "unevaluatedItems", "propertyNames", "contains", "contentSchema"} {
		switch child := schema[key].(type) {
		case map[string]any:
			cleanAnthropicToolSchema(child, strict)
		case []any:
			for _, entry := range child {
				if node, ok := entry.(map[string]any); ok {
					cleanAnthropicToolSchema(node, strict)
				}
			}
		}
	}
}

func openAIToolDefinition(tool map[string]any) map[string]any {
	if function, ok := tool["function"].(map[string]any); ok {
		return function
	}
	if custom, ok := tool["custom"].(map[string]any); ok {
		return custom
	}
	return tool
}

func convertOpenAIToolChoice(raw any) (map[string]any, error) {
	switch choice := raw.(type) {
	case nil:
		return nil, nil
	case string:
		switch choice {
		case "auto", "none":
			return map[string]any{"type": choice}, nil
		case "required":
			return map[string]any{"type": "any"}, nil
		default:
			return nil, fmt.Errorf("OpenAI tool_choice %q has no Anthropic mapping", choice)
		}
	case map[string]any:
		if choice["type"] != "function" {
			return nil, fmt.Errorf("OpenAI tool_choice type has no Anthropic mapping")
		}
		for key := range choice {
			if key != "type" && key != "function" {
				return nil, fmt.Errorf("OpenAI tool_choice extension has no Anthropic mapping")
			}
		}
		function, _ := choice["function"].(map[string]any)
		name, _ := function["name"].(string)
		if name == "" || len(function) != 1 {
			return nil, fmt.Errorf("OpenAI tool_choice requires one named function")
		}
		return map[string]any{"type": "tool", "name": name}, nil
	default:
		return nil, fmt.Errorf("OpenAI tool_choice has no Anthropic mapping")
	}
}

// convertOpenAIAssistantMessage 返回 ok=false 表示这一轮既没有文本也没有工具调用，
// 调用方应整条丢弃（Messages API 不接受空 content）。
func convertOpenAIAssistantMessage(message map[string]any) (map[string]any, bool) {
	blocks := contentBlocks(convertOpenAIContent(message["content"]))
	for _, rawCall := range anySlice(message["tool_calls"]) {
		call, _ := rawCall.(map[string]any)
		id, name, input, ok := openAIToolCall(call)
		if !ok {
			continue
		}
		blocks = append(blocks, map[string]any{
			"type":  "tool_use",
			"id":    id,
			"name":  name,
			"input": input,
		})
	}
	if len(blocks) == 0 {
		return nil, false
	}
	return map[string]any{"role": "assistant", "content": blocks}, true
}

// openAIToolCall accepts the historical Chat Completions function shape as
// well as clients that expose custom tools with a top-level or custom payload.
// Anthropic/Kiro requires all three fields to be present and an object input.
func openAIToolCall(call map[string]any) (id, name string, input map[string]any, ok bool) {
	if call == nil {
		return "", "", nil, false
	}
	id = compatStringValue(call["id"])
	carrier := call
	if function, exists := call["function"].(map[string]any); exists {
		carrier = function
	} else if custom, exists := call["custom"].(map[string]any); exists {
		carrier = custom
	}
	name = compatStringValue(carrier["name"])
	if id == "" || name == "" {
		return "", "", nil, false
	}
	input = map[string]any{}
	rawInput, hasInput := carrier["arguments"]
	if !hasInput {
		rawInput, hasInput = carrier["input"]
	}
	if !hasInput {
		rawInput = carrier["parameters"]
	}
	switch value := rawInput.(type) {
	case string:
		if strings.TrimSpace(value) != "" && json.Unmarshal([]byte(value), &input) != nil {
			input = map[string]any{"input": value}
		}
	case map[string]any:
		input = value
	}
	return id, name, input, true
}

// convertOpenAIContent 把 Chat 的 content 转成 Messages 的 content。
// 空白文本块会被跳过：Messages API 要求 text 块必须包含非空白字符。
func convertOpenAIContent(raw any) any {
	if text, ok := raw.(string); ok {
		return text
	}
	blocks := make([]any, 0)
	for _, item := range anySlice(raw) {
		block, _ := item.(map[string]any)
		if block == nil {
			continue
		}
		switch block["type"] {
		case "text", "input_text":
			if text, ok := block["text"].(string); ok && strings.TrimSpace(text) != "" {
				converted := map[string]any{"type": "text", "text": text}
				if cacheControl, present := block["cache_control"]; present {
					converted["cache_control"] = cacheControl
				}
				blocks = append(blocks, converted)
			}
		case "image_url":
			if image := convertOpenAIImage(block["image_url"]); image != nil {
				blocks = append(blocks, image)
			}
		}
	}
	return blocks
}

func anthropicContentEmpty(content any) bool {
	switch value := content.(type) {
	case string:
		return strings.TrimSpace(value) == ""
	case []any:
		return len(value) == 0
	default:
		return content == nil
	}
}

func convertOpenAIImage(raw any) map[string]any {
	url := ""
	switch image := raw.(type) {
	case string:
		url = image
	case map[string]any:
		url, _ = image["url"].(string)
	}
	if url == "" {
		return nil
	}
	const dataPrefix = "data:"
	if strings.HasPrefix(url, dataPrefix) {
		parts := strings.SplitN(strings.TrimPrefix(url, dataPrefix), ";base64,", 2)
		if len(parts) == 2 {
			return map[string]any{"type": "image", "source": map[string]any{"type": "base64", "media_type": parts[0], "data": parts[1]}}
		}
	}
	return map[string]any{"type": "image", "source": map[string]any{"type": "url", "url": url}}
}

func contentBlocks(content any) []any {
	if text, ok := content.(string); ok {
		if strings.TrimSpace(text) == "" {
			return nil
		}
		return []any{map[string]any{"type": "text", "text": text}}
	}
	return anySlice(content)
}

func appendOrMergeAnthropicToolResult(messages []any, current map[string]any) []any {
	if len(messages) == 0 {
		return append(messages, current)
	}
	last, _ := messages[len(messages)-1].(map[string]any)
	lastContent, lastIsBlocks := last["content"].([]any)
	currentContent, _ := current["content"].([]any)
	if last["role"] == "user" && lastIsBlocks && allToolResults(lastContent) {
		last["content"] = append(lastContent, currentContent...)
		return messages
	}
	return append(messages, current)
}

func allToolResults(blocks []any) bool {
	if len(blocks) == 0 {
		return false
	}
	for _, item := range blocks {
		block, _ := item.(map[string]any)
		if block["type"] != "tool_result" {
			return false
		}
	}
	return true
}

func anthropicToolResultContent(raw any) any {
	if raw == nil {
		return ""
	}
	if text, ok := raw.(string); ok {
		return text
	}
	if parts, ok := raw.([]any); ok {
		if converted := convertOpenAIContent(parts); len(anySlice(converted)) > 0 {
			return converted
		}
		// 全是空白文本块：tool_result 允许空字符串，但不允许空 text 块。
		if allOpenAITextParts(parts) {
			return ""
		}
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return fmt.Sprint(raw)
	}
	return string(encoded)
}

func allOpenAITextParts(parts []any) bool {
	if len(parts) == 0 {
		return false
	}
	for _, item := range parts {
		block, _ := item.(map[string]any)
		if block == nil || (block["type"] != "text" && block["type"] != "input_text") {
			return false
		}
	}
	return true
}

func openAIContentText(raw any) string {
	if text, ok := raw.(string); ok {
		return text
	}
	parts := make([]string, 0)
	for _, item := range anySlice(raw) {
		block, _ := item.(map[string]any)
		if text, ok := block["text"].(string); ok && text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "\n")
}

func compatStringValue(raw any) string {
	value, _ := raw.(string)
	return value
}

func firstNonNil(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

// openAIContentCacheControl 返回 Chat content 块数组里客户端打的第一个缓存标记。
func openAIContentCacheControl(raw any) any {
	for _, item := range anySlice(raw) {
		block, _ := item.(map[string]any)
		if cacheControl := block["cache_control"]; cacheControl != nil {
			return cacheControl
		}
	}
	return nil
}

// anthropicChatPromptCacheEnv 控制 Chat -> Messages 转换时是否自动加提示缓存断点，默认开启，
// 设为 off/false/0 关闭（上游不认 cache_control 时的回退开关）。Chat 协议没有块级缓存标记，
// CodeBuddy/WorkBuddy 这类客户端每轮重发上万字的系统提示词和几百条历史，不加断点上游一次都
// 不会命中缓存（客户现场 7 天 chat 1883 次请求缓存全为 0，同上游 messages 端点九成命中）。
const anthropicChatPromptCacheEnv = "UAG_ANTHROPIC_CHAT_PROMPT_CACHE"

// anthropicMaxCacheBreakpoints 是 Messages API 单个请求允许的缓存断点上限，超出直接 400。
const anthropicMaxCacheBreakpoints = 4

func anthropicChatPromptCacheEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(anthropicChatPromptCacheEnv))) {
	case "0", "false", "off", "no", "disabled":
		return false
	default:
		return true
	}
}

// applyAnthropicChatPromptCache 按 Claude Code 的做法放断点：
//   - system 末尾：渲染顺序是 tools -> system -> messages，这一个断点连带缓存全部工具定义；
//   - 本轮最后一条消息的最后一个块：写入整段前缀，供下一轮读取；
//   - 倒数第二条 user 消息：正好是上一轮请求的结尾，一轮新增超过 20 个块（超出上游回看窗口）时也能读到。
//
// 断点标记不参与缓存键，挪动位置不影响命中；不足最小可缓存长度时上游静默不缓存，不会报错。
// 客户端自己打了块级标记时不再自动加（避免和客户端的 ttl 排布冲突）。客户端顶层 cache_control
// （自动缓存写法）中转上游未必支持，统一换成同取值的块级标记，开关关闭时也照此处理。
func applyAnthropicChatPromptCache(request map[string]any, topLevel any) {
	existing := countAnthropicCacheBreakpoints(request)
	marker := topLevel
	if marker == nil {
		if existing > 0 || !anthropicChatPromptCacheEnabled() {
			return
		}
		marker = map[string]any{"type": "ephemeral"}
	}
	available := anthropicMaxCacheBreakpoints - existing
	if available <= 0 {
		return
	}
	if text, ok := request["system"].(string); ok && strings.TrimSpace(text) != "" {
		request["system"] = []any{map[string]any{"type": "text", "text": text, "cache_control": marker}}
		available--
	}
	messages := anySlice(request["messages"])
	last := len(messages) - 1
	if available > 0 && last >= 0 && markAnthropicMessageCacheBreakpoint(messages[last], marker) {
		available--
	}
	if available <= 0 {
		return
	}
	for index := last - 1; index >= 0; index-- {
		message, _ := messages[index].(map[string]any)
		if message["role"] == "user" {
			markAnthropicMessageCacheBreakpoint(message, marker)
			return
		}
	}
}

// markAnthropicMessageCacheBreakpoint 给消息最后一个可缓存块打标记；已有标记或没有可缓存块时返回 false。
func markAnthropicMessageCacheBreakpoint(raw any, marker any) bool {
	message, _ := raw.(map[string]any)
	if message == nil {
		return false
	}
	blocks := contentBlocks(message["content"])
	for index := len(blocks) - 1; index >= 0; index-- {
		block, _ := blocks[index].(map[string]any)
		switch block["type"] {
		case "text", "image", "document", "tool_use", "tool_result":
		default:
			// thinking/redacted_thinking 块不允许打缓存标记。
			continue
		}
		if block["cache_control"] != nil {
			return false
		}
		block["cache_control"] = marker
		message["content"] = blocks
		return true
	}
	return false
}

func countAnthropicCacheBreakpoints(value any) int {
	count := 0
	switch current := value.(type) {
	case map[string]any:
		if current["cache_control"] != nil {
			count++
		}
		for _, child := range current {
			count += countAnthropicCacheBreakpoints(child)
		}
	case []any:
		for _, child := range current {
			count += countAnthropicCacheBreakpoints(child)
		}
	}
	return count
}
