package handler

import (
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"mime"
	"strings"
)

// chatgptRecognizedContentTypes 是 ChatGPT 网页版会话消息的 content_type 取值。
// 只认这些值才解析，避免本解码器在 requestSniffWebDecoderNames 探测时误吞别站请求
// （守住「别影响别的网站适配」）。
var chatgptRecognizedContentTypes = map[string]bool{
	"text":            true,
	"multimodal_text": true,
}

// decodeChatGPTConversationRequest 解析 chatgpt.com 网页版「发送侧」会话请求
// （POST /backend-api/f/conversation 的 JSON 正文）：
//   - content_type=text：messages[].content.parts[] 为字符串(用户文字)
//   - content_type=multimodal_text：parts 含 {content_type:image_asset_pointer, asset_pointer, size_bytes, ...}
//     图片占位 + 文字字符串；metadata.attachments 给出文件/图片元数据(name, mime_type, id, size)
//
// 图片/文件原始字节在 /backend-api/files 上传请求里（留作后续增量接 OCR），此处只取文字与引用。
func decodeChatGPTConversationRequest(body []byte, contentType string) (ExtractedContent, bool) {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if !isJSONContent(strings.ToLower(mediaType), body) {
		return ExtractedContent{}, false
	}
	var payload struct {
		Messages []struct {
			Role   string `json:"role"`
			Author struct {
				Role string `json:"role"`
			} `json:"author"`
			Content struct {
				ContentType string        `json:"content_type"`
				Parts       []interface{} `json:"parts"`
			} `json:"content"`
			Metadata struct {
				Attachments []map[string]interface{} `json:"attachments"`
			} `json:"metadata"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || len(payload.Messages) == 0 {
		return ExtractedContent{}, false
	}

	var parts []string
	var attachments []ExtractedAttachment
	var messages []ConvMessage
	matched := false

	for messageIndex, msg := range payload.Messages {
		textStart, attachmentStart := len(parts), len(attachments)
		if !chatgptRecognizedContentTypes[msg.Content.ContentType] {
			continue
		}
		for _, p := range msg.Content.Parts {
			switch v := p.(type) {
			case string:
				if strings.TrimSpace(v) != "" {
					parts = append(parts, v)
					matched = true
				}
			case map[string]interface{}:
				// multimodal 占位对象（image_asset_pointer / audio_asset_pointer 等）
				att := ExtractedAttachment{Source: "chatgpt_web_part"}
				if ct, ok := v["content_type"].(string); ok {
					att.ContentType = ct
				}
				if ap, ok := v["asset_pointer"].(string); ok {
					att.ReferenceID = ap
				}
				if sz, ok := v["size_bytes"].(float64); ok {
					att.Size = int64(sz)
				}
				if att.ReferenceID != "" || att.ContentType != "" {
					attachments = append(attachments, att)
					matched = true
				}
			}
		}
		// metadata.attachments：文件/图片元数据
		for _, a := range msg.Metadata.Attachments {
			att := ExtractedAttachment{Source: "chatgpt_web_attachment"}
			if v, ok := a["name"].(string); ok {
				att.FileName = v
			}
			if v, ok := a["mime_type"].(string); ok {
				att.ContentType = v
			}
			if v, ok := a["id"].(string); ok {
				att.ReferenceID = v
			}
			if v, ok := a["size"].(float64); ok {
				att.Size = int64(v)
			}
			attachments = append(attachments, att)
			matched = true
		}
		role := strings.ToLower(strings.TrimSpace(msg.Author.Role))
		if role == "" {
			role = strings.ToLower(strings.TrimSpace(msg.Role))
		}
		if role == "" {
			role = "user"
		}
		source := "unknown"
		switch role {
		case "user":
			source = "user"
		case "assistant":
			source = "assistant_history"
		case "system", "developer":
			source = "system_prompt"
		case "tool", "function":
			source = "tool_result"
		}
		text := strings.Join(parts[textStart:], "\n")
		messages = append(messages, ConvMessage{Role: role, Source: source, Content: text, ContentSHA256: aimsg.ContentSHA256Hex(text), MessageIndex: &messageIndex, SourcePath: fmt.Sprintf("/messages/%d", messageIndex), HasAttachments: len(attachments) > attachmentStart})
		for i := attachmentStart; i < len(attachments); i++ {
			attachments[i].MessageIndex = &messageIndex
			attachments[i].MessageRole = role
			attachments[i].ContentSource = source
			attachments[i].SourcePath = fmt.Sprintf("/messages/%d", messageIndex)
		}
	}

	if !matched {
		return ExtractedContent{}, false
	}
	latest := aimsg.LatestUserPosition(messages)
	for i := range attachments {
		for j, m := range messages {
			if m.MessageIndex != nil && attachments[i].MessageIndex != nil && *m.MessageIndex == *attachments[i].MessageIndex {
				attachments[i].IsLatestUser = aimsg.IsLatestUser(messages, j, latest)
				attachments[i].InspectionIsHistory = aimsg.InspectionIsHistory(messages, j, latest)
				break
			}
		}
	}
	out := buildExtracted(parts, attachments, "json")
	out.Messages = messages
	return out, true
}
