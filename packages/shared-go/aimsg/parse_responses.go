package aimsg

import (
	"bytes"
	"encoding/json"
	"strings"
)

type openAIResponsesRequest struct {
	Model        string          `json:"model"`
	Instructions json.RawMessage `json:"instructions"`
	Input        json.RawMessage `json:"input"`
	Tools        []responsesTool `json:"tools"`
}

type responsesTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
	Function    *struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type responsesInputItem struct {
	Type      string          `json:"type"`
	Role      string          `json:"role"`
	Name      string          `json:"name"`
	Content   json.RawMessage `json:"content"`
	Text      json.RawMessage `json:"text"`
	Arguments json.RawMessage `json:"arguments"`
	Output    json.RawMessage `json:"output"`
}

type responsesContentPart struct {
	Type    string          `json:"type"`
	Text    string          `json:"text"`
	Content json.RawMessage `json:"content"`
}

// ParseOpenAIResponsesRequest 解析 OpenAI /v1/responses 请求体。
// 可信运行上下文、工具定义、历史回答、工具结果与当前用户消息使用统一 source 契约，
// 从根上避免把整包 JSON 中的 Skill/工具 schema 当成用户指令送入语义裁判。
func ParseOpenAIResponsesRequest(body []byte) (ParsedChat, bool) {
	var request openAIResponsesRequest
	if err := json.Unmarshal(body, &request); err != nil {
		return ParsedChat{}, false
	}
	if len(bytes.TrimSpace(request.Input)) == 0 {
		return ParsedChat{}, false
	}

	out := ParsedChat{Model: strings.TrimSpace(request.Model)}
	var systemParts []string

	for _, tool := range request.Tools {
		name, description, parameters := tool.Name, tool.Description, tool.Parameters
		if tool.Function != nil {
			if name == "" {
				name = tool.Function.Name
			}
			if description == "" {
				description = tool.Function.Description
			}
			if len(parameters) == 0 {
				parameters = tool.Function.Parameters
			}
		}
		content := "[tool_def:" + strings.TrimSpace(name) + "] " + strings.TrimSpace(description)
		if len(parameters) > 0 {
			content += "\n" + compactJSON(parameters)
		}
		content = strings.TrimSpace(content)
		if content != "" {
			out.Messages = append(out.Messages, newConvMessage("tool", SourceToolDef, content))
		}
	}

	if instructions := responsesText(request.Instructions); instructions != "" {
		systemParts = append(systemParts, instructions)
		out.Messages = append(out.Messages, newConvMessage("system", SourceSystemPrompt, instructions))
	}

	var inputString string
	if err := json.Unmarshal(request.Input, &inputString); err == nil {
		if text := strings.TrimSpace(inputString); text != "" {
			out.Messages = append(out.Messages, newConvMessage("user", SourceUser, text))
			anchorMessages(out.Messages[len(out.Messages)-1:], 0, "input")
		}
	} else {
		var items []responsesInputItem
		if err := json.Unmarshal(request.Input, &items); err != nil {
			var item responsesInputItem
			if err := json.Unmarshal(request.Input, &item); err != nil {
				return ParsedChat{}, false
			}
			items = []responsesInputItem{item}
		}
		for messageIndex, item := range items {
			start := len(out.Messages)
			for _, message := range responsesItemMessages(item) {
				if message.Source == SourceSystemPrompt {
					systemParts = append(systemParts, message.Content)
				}
				out.Messages = append(out.Messages, message)
			}
			if strings.EqualFold(strings.TrimSpace(item.Role), "user") {
				out.Artifacts = openAIArtifactCandidates(
					item.Content, "input",
				)
				hasUser := false
				for _, m := range out.Messages[start:] {
					if m.Source == SourceUser {
						hasUser = true
					}
				}
				if len(out.Artifacts) > 0 && !hasUser {
					m := newConvMessage("user", SourceUser, "")
					m.HasAttachments = true
					m.RawContent = item.Content
					out.Messages = append(out.Messages, m)
				}
			}
			anchorMessages(out.Messages[start:], messageIndex, "input")
		}
	}

	if len(out.Messages) == 0 {
		return ParsedChat{}, false
	}
	out.SystemText = strings.Join(systemParts, "\n")
	finalizeParsedChat(&out)
	if len(out.Messages) == 0 || (out.LastUserText == "" && len(systemParts) == 0 && out.ToolsDigest == "") {
		// 只有 reasoning 等不可展示/不可检测协议块时不宣称解析成功。
		hasMeaningful := false
		for _, message := range out.Messages {
			if strings.TrimSpace(message.Content) != "" || message.HasAttachments {
				hasMeaningful = true
				break
			}
		}
		if !hasMeaningful {
			return ParsedChat{}, false
		}
	}
	return out, true
}

func responsesItemMessages(item responsesInputItem) []ConvMessage {
	itemType := strings.ToLower(strings.TrimSpace(item.Type))
	role := strings.ToLower(strings.TrimSpace(item.Role))

	switch itemType {
	case "function_call", "computer_call", "web_search_call", "file_search_call":
		content := "[tool_use:" + strings.TrimSpace(item.Name) + "]"
		if arguments := responsesText(item.Arguments); arguments != "" {
			content += " " + arguments
		}
		return []ConvMessage{newConvMessage("assistant", SourceAssistantHistory, strings.TrimSpace(content))}
	case "function_call_output", "computer_call_output":
		content := responsesText(item.Output)
		if content == "" {
			content = responsesText(item.Content)
		}
		if content == "" {
			return nil
		}
		m := newConvMessage("tool", SourceToolResult, content)
		m.RawContent = item.Output
		if len(m.RawContent) == 0 {
			m.RawContent = item.Content
		}
		return []ConvMessage{m}
	case "reasoning":
		return nil
	}

	rawContent := item.Content
	if len(bytes.TrimSpace(rawContent)) == 0 {
		rawContent = item.Text
	}
	knownParts, unknownParts := responsesMessageParts(rawContent)
	knownContent := strings.TrimSpace(strings.Join(knownParts, "\n"))
	unknownContent := strings.TrimSpace(strings.Join(unknownParts, "\n"))
	messages := make([]ConvMessage, 0, 2)
	if knownContent != "" {
		source := SourceUnknown
		messageRole := role
		switch role {
		case "system", "developer":
			source = SourceSystemPrompt
		case "user":
			source = SourceUser
			messageRole = "user"
		case "assistant":
			source = SourceAssistantHistory
			messageRole = "assistant"
		case "tool", "function":
			source = SourceToolResult
		}
		messages = append(messages, newConvMessage(messageRole, source, knownContent))
	}
	if unknownContent != "" {
		messages = append(messages, newConvMessage(role, SourceUnknown, unknownContent))
	}
	for i := range messages {
		messages[i].RawContent = rawContent
	}
	return messages
}

// responsesMessageParts extracts only documented text content shapes. Unknown
// objects remain available to deterministic scanners under SourceUnknown
// instead of being promoted to user text or silently discarded.
func responsesMessageParts(raw json.RawMessage) ([]string, []string) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err == nil {
		known := make([]string, 0, len(elements))
		unknown := make([]string, 0, len(elements))
		for _, element := range elements {
			text, extra := responsesMessagePart(element)
			if text != "" {
				known = append(known, text)
			}
			if extra != "" {
				unknown = append(unknown, extra)
			}
		}
		return known, unknown
	}
	text, extra := responsesMessagePart(raw)
	if text == "" && extra == "" {
		return nil, nil
	}
	known, unknown := []string(nil), []string(nil)
	if text != "" {
		known = append(known, text)
	}
	if extra != "" {
		unknown = append(unknown, extra)
	}
	return known, unknown
}

func responsesMessagePart(raw json.RawMessage) (string, string) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return strings.TrimSpace(text), ""
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return "", compactJSON(raw)
	}
	partType := ""
	if rawType, ok := object["type"]; ok {
		if err := json.Unmarshal(rawType, &partType); err != nil {
			return "", compactJSON(raw)
		}
	}
	switch strings.ToLower(strings.TrimSpace(partType)) {
	case "", "text", "input_text", "output_text":
	case "image_url", "input_image", "image_generation_call", "image",
		"input_file", "file", "document":
		// 多模态载体（图片/文件，常是数 MB 的 base64 data URI）不进文本检测流：
		// 字节经 compactJSON 落进 unknown 文本后会被 4KB 滑窗裁成数百个语义裁判
		// 任务/请求（2026-09 生产事故：每张内联图每回合 505 个队列分片）。这些
		// 载体由 artifact 候选通道（openAIArtifactCandidates）承担留证与附件安检，
		// 此处文本与 unknown 都不产出。
		return "", ""
	default:
		return "", compactJSON(raw)
	}
	rawText, hasText := object["text"]
	if hasText {
		if err := json.Unmarshal(rawText, &text); err != nil {
			return "", compactJSON(raw)
		}
	}
	delete(object, "type")
	delete(object, "text")
	extra := ""
	if len(object) > 0 {
		if encoded, err := json.Marshal(object); err == nil {
			extra = strings.TrimSpace(string(encoded))
		}
	}
	if !hasText && extra == "" {
		return "", ""
	}
	return strings.TrimSpace(text), extra
}

func responsesText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return strings.TrimSpace(text)
	}
	var parts []responsesContentPart
	if err := json.Unmarshal(raw, &parts); err == nil {
		texts := make([]string, 0, len(parts))
		for _, part := range parts {
			switch strings.ToLower(strings.TrimSpace(part.Type)) {
			case "", "text", "input_text", "output_text":
				if value := strings.TrimSpace(part.Text); value != "" {
					texts = append(texts, value)
				}
			case "tool_result":
				if value := responsesText(part.Content); value != "" {
					texts = append(texts, value)
				}
			}
		}
		return strings.Join(texts, "\n")
	}
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	if bytes, err := json.Marshal(value); err == nil {
		return strings.TrimSpace(string(bytes))
	}
	return ""
}
