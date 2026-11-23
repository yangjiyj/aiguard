package handler

import (
	"encoding/base64"
	"encoding/json"
	"mime"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

// extractedFromParsedChat 把 aimsg 解析产物折算成 ExtractedContent 双形态：
// Messages（带 source，喂会话键/留证）+ 平铺 Text（内部完整审计表示）+
// SecurityText（去掉平台 system/tool definition 后送 DLP 的表示）。
// ConversationID 不在此填：由 enrichAPIConversationKey 在留证写入前用 aiconvo.ConversationKey
// 计算（需要 tenant/agent 上下文，解码器拿不到）。
func extractedFromParsedChat(parsed aimsg.ParsedChat) (ExtractedContent, bool) {
	content := ExtractedContent{
		Text:              aimsg.FlattenMessages(parsed.Messages),
		SecurityText:      securityTextFromMessages(parsed.Messages),
		SecurityTextKnown: true,
		ContentType:       "json",
		Model:             parsed.Model,
		Messages:          parsed.Messages,
	}
	// 同一张内联图常在多条消息里重复出现（如 WorkBuddy user 粘贴图 + tool 回显同一张），
	// 按 base64 字节去重，避免一条留证里同图冒出多个附件。
	seenImg := make(map[string]struct{}, len(parsed.Images))
	for _, img := range parsed.Images {
		if _, dup := seenImg[img.DataBase64]; dup {
			continue
		}
		seenImg[img.DataBase64] = struct{}{}
		decoded, err := base64.StdEncoding.DecodeString(img.DataBase64)
		if err != nil {
			continue
		}
		content.Attachments = append(content.Attachments, attachmentFromBytes("inline_image_block", "messages.content.image", "", img.MediaType, decoded))
	}
	for _, artifact := range artifactAttachmentsFromCandidates(parsed.Artifacts) {
		duplicate := false
		for _, existing := range content.Attachments {
			if artifact.SHA256 != "" && artifact.SHA256 == existing.SHA256 {
				duplicate = true
				break
			}
		}
		if !duplicate {
			content.Attachments = append(content.Attachments, artifact)
		}
	}
	if content.Text == "" && len(content.Attachments) == 0 {
		return ExtractedContent{}, false
	}
	anchorExtractedAttachments(&content)
	return content, true
}

// securityTextFromMessages removes platform-owned system prompts and tool
// definitions from the DLP input while retaining user/history/tool-result
// text that may contain customer data. User text is never reclassified by markers;
// actual detection targets are selected separately from this legacy representation.
func securityTextFromMessages(messages []aimsg.ConvMessage) string {
	parts := make([]string, 0, len(messages))
	for _, message := range messages {
		if message.Source == aimsg.SourceSystemPrompt || message.Source == aimsg.SourceToolDef {
			continue
		}
		content := strings.TrimSpace(message.Content)
		if content == "" {
			continue
		}
		parts = append(parts, content)
	}
	return strings.Join(parts, "\n")
}

// decodeAnthropicMessagesRequest 解析 Anthropic /v1/messages API 请求（Claude Code 等编码代理主入口）。
// catalog（aiadapters/adapters/anthropic.json 的 anthropic_api 条目）从一开始就声明了
// anthropic_messages 解码器，但注册表始终没有这个 key（投诉①病根之一），一直静默回退到
// 通用抽取器把 system+tools+全量历史平铺。本函数是它的真实现：双形态产物见 extractedFromParsedChat。
// 形态不符（无 messages 数组）返回 false，embeddings 等端点照走原回退路径。
func decodeAnthropicMessagesRequest(req *http.Request, body []byte, contentType string) (ExtractedContent, bool) {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	parsed, ok := aimsg.ParseAnthropicMessagesRequest(body)
	if !ok {
		return ExtractedContent{}, false
	}
	return extractedFromParsedChat(parsed)
}

// decodeAnthropicMessagesResponse 解析 /v1/messages 响应：非流式 JSON（content blocks）与 SSE 事件流。
func decodeAnthropicMessagesResponse(body []byte, contentType string) (ExtractedContent, bool) {
	if isEventStream(contentType, body) {
		return reassembleAnthropicMessagesStream(parseSSEDataEvents(body))
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	var payload struct {
		Type    string `json:"type"`
		Model   string `json:"model"`
		Content []struct {
			Type     string          `json:"type"`
			Text     string          `json:"text"`
			Thinking string          `json:"thinking"`
			Name     string          `json:"name"`
			Input    json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ExtractedContent{}, false
	}
	if payload.Type != "message" || len(payload.Content) == 0 {
		return ExtractedContent{}, false
	}
	var parts, visibleParts []string
	var toolInvocations []ToolInvocation
	for _, block := range payload.Content {
		switch block.Type {
		case "text":
			if s := strings.TrimSpace(block.Text); s != "" {
				parts = append(parts, s)
				visibleParts = append(visibleParts, s)
			}
		case "thinking":
			if s := strings.TrimSpace(block.Thinking); s != "" {
				parts = append(parts, "[reasoning] "+s)
			}
		case "tool_use":
			part := "[tool_use:" + block.Name + "]"
			if len(block.Input) > 0 {
				part += " " + string(block.Input)
			}
			parts = append(parts, part)
			if len(block.Input) > 0 {
				toolInvocations = append(toolInvocations, ToolInvocation{Name: block.Name, Arguments: string(block.Input)})
			}
		}
	}
	if len(parts) == 0 {
		return ExtractedContent{}, false
	}
	extracted := buildExtracted(parts, nil, "json")
	extracted.Model = payload.Model
	extracted.VisibleText = strings.Join(visibleParts, "\n")
	extracted.VisibleTextKnown = true
	extracted.ToolInvocations = toolInvocations
	return extracted, true
}

// reassembleAnthropicMessagesStream 重组 Anthropic SSE 事件流：
// message_start(model) / content_block_start(tool_use 名) /
// content_block_delta(text_delta / thinking_delta / input_json_delta)。
// 其余协议帧（content_block_stop/message_delta/message_stop/ping）一律忽略，
// 与 reassembleOpenAIResponsesStream 的处理姿势一致。
func reassembleAnthropicMessagesStream(events []sseEvent) (ExtractedContent, bool) {
	matched := false
	model := ""
	var answer, reasoning, toolInput strings.Builder
	toolName := ""
	var toolArgs strings.Builder
	for _, ev := range events {
		m, ok := ev.decoded.(map[string]interface{})
		if !ok {
			continue
		}
		typ, _ := m["type"].(string)
		switch typ {
		case "message_start":
			if msg, ok := m["message"].(map[string]interface{}); ok {
				if s, ok := msg["model"].(string); ok {
					model = s
				}
			}
			matched = true
		case "content_block_start":
			if cb, ok := m["content_block"].(map[string]interface{}); ok {
				if cbType, _ := cb["type"].(string); cbType == "tool_use" {
					name, _ := cb["name"].(string)
					toolInput.WriteString("[tool_use:" + name + "] ")
					if toolName == "" {
						toolName = name
					}
					matched = true
				}
			}
		case "content_block_delta":
			delta, ok := m["delta"].(map[string]interface{})
			if !ok {
				continue
			}
			deltaType, _ := delta["type"].(string)
			switch deltaType {
			case "text_delta":
				if s, ok := delta["text"].(string); ok {
					matched = true
					answer.WriteString(s)
				}
			case "thinking_delta":
				if s, ok := delta["thinking"].(string); ok {
					matched = true
					reasoning.WriteString(s)
				}
			case "input_json_delta":
				if s, ok := delta["partial_json"].(string); ok {
					matched = true
					toolInput.WriteString(s)
					toolArgs.WriteString(s)
				}
			}
		}
	}
	if !matched || (answer.Len() == 0 && reasoning.Len() == 0 && toolInput.Len() == 0) {
		return ExtractedContent{}, false
	}
	extracted := buildReassembledExtractedWithTool(answer.String(), reasoning.String(), toolInput.String(), nil)
	extracted.Model = model
	if args := strings.TrimSpace(toolArgs.String()); args != "" {
		extracted.ToolInvocations = []ToolInvocation{{Name: toolName, Arguments: args}}
	}
	return extracted, true
}
