package aimsg

import (
	"encoding/json"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

// anthropicContentBlock 是 /v1/messages 消息 content 数组元素的宽松形态。
type anthropicContentBlock struct {
	Type     string          `json:"type"`
	Text     string          `json:"text"`
	Thinking string          `json:"thinking"`
	Name     string          `json:"name"`
	Input    json.RawMessage `json:"input"`
	Title    string          `json:"title"`
	Content  json.RawMessage `json:"content"` // tool_result 的内容：string 或 blocks
	Source   *struct {
		Type      string `json:"type"`
		MediaType string `json:"media_type"`
		Data      string `json:"data"`
		URL       string `json:"url"`
	} `json:"source"`
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"` // string 或 []anthropicContentBlock
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type anthropicMessagesRequest struct {
	Model    string             `json:"model"`
	System   json.RawMessage    `json:"system"` // string 或 [{type:text,text:...}]
	Messages []anthropicMessage `json:"messages"`
	Tools    []anthropicTool    `json:"tools"`
}

// ParseAnthropicMessagesRequest 解析 Anthropic /v1/messages 请求体为统一消息数组。
// 产物顺序：system → tools（tool_def）→ messages 原序。
// source 归类（确定性）：system→system_prompt；tools→tool_def；role=assistant→assistant_history
// （text/thinking/tool_use 合并一条）；role=user 文本→user；user 内嵌 tool_result 块→独立 tool_result 条。
// 无 messages / 非 JSON → 不匹配（让 embeddings 等端点走原回退路径）。
func ParseAnthropicMessagesRequest(body []byte) (ParsedChat, bool) {
	var req anthropicMessagesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return ParsedChat{}, false
	}
	if len(req.Messages) == 0 {
		return ParsedChat{}, false
	}
	out := ParsedChat{Model: strings.TrimSpace(req.Model)}

	if systemText := anthropicSystemText(req.System); systemText != "" {
		out.SystemText = systemText
		out.Messages = append(out.Messages, newConvMessage("system", SourceSystemPrompt, systemText))
	}
	for _, tool := range req.Tools {
		content := "[tool_def:" + tool.Name + "] " + strings.TrimSpace(tool.Description)
		if len(tool.InputSchema) > 0 {
			content += "\n" + compactJSON(tool.InputSchema)
		}
		out.Messages = append(out.Messages, newConvMessage("tool", SourceToolDef, content))
	}
	for messageIndex, msg := range req.Messages {
		start := len(out.Messages)
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		source := SourceUnknown
		switch role {
		case "user":
			source = SourceUser
		case "assistant":
			source = SourceAssistantHistory
		case "system", "developer":
			source = SourceSystemPrompt
		}
		if role == "user" {
			out.Artifacts = nil
		}
		var plain string
		if err := json.Unmarshal(msg.Content, &plain); err == nil {
			if strings.TrimSpace(plain) != "" {
				out.Messages = append(out.Messages, newConvMessage(role, source, plain))
			}
			anchorMessages(out.Messages[start:], messageIndex, "messages")
			for i := start; i < len(out.Messages); i++ {
				out.Messages[i].RawContent = msg.Content
			}
			continue
		}
		var blocks []anthropicContentBlock
		if err := json.Unmarshal(msg.Content, &blocks); err != nil {
			continue // 未知形态：跳过该条，不整包失败
		}
		if role == "user" {
			out.Artifacts = anthropicArtifactCandidates(blocks, "input")
		}
		var textParts []string
		var ownBlocks []anthropicContentBlock
		for _, b := range blocks {
			if b.Type != "tool_result" {
				ownBlocks = append(ownBlocks, b)
			}
			switch b.Type {
			case "text":
				if s := strings.TrimSpace(b.Text); s != "" {
					textParts = append(textParts, s)
				}
			case "thinking":
				if s := strings.TrimSpace(b.Thinking); s != "" {
					textParts = append(textParts, "[reasoning] "+s)
				}
			case "tool_use":
				part := "[tool_use:" + b.Name + "]"
				if len(b.Input) > 0 {
					part += " " + compactJSON(b.Input)
				}
				textParts = append(textParts, part)
			case "tool_result":
				if s := anthropicToolResultText(b.Content); s != "" || len(b.Content) > 0 {
					out.Messages = append(out.Messages, newConvMessage(role, SourceToolResult, s))
					out.Messages[len(out.Messages)-1].RawContent = b.Content
					out.Messages[len(out.Messages)-1].HasAttachments = true
					// §3.8：tool_result.content 里嵌套的 image/document 块抽成附件，
					// 让文件内容 DLP 与留证看得见（Claude Code 的 Read 读 PDF/图片走这里）。
					var nested []anthropicContentBlock
					if err := json.Unmarshal(b.Content, &nested); err == nil {
						for _, nb := range nested {
							switch nb.Type {
							case "image":
								if nb.Source != nil && nb.Source.Type == "base64" && nb.Source.Data != "" {
									out.Images = append(out.Images, InlineImage{MediaType: nb.Source.MediaType, DataBase64: nb.Source.Data})
								}
							case "document":
								if nb.Source != nil && nb.Source.Type == "base64" && nb.Source.Data != "" {
									name := strings.TrimSpace(nb.Title)
									if name == "" {
										name = strings.TrimSpace(nb.Name)
									}
									if name == "" {
										name = "tool_result_" + strings.TrimSpace(b.Name)
									}
									if candidate, ok := artifactCandidateFromBase64(nb.Source.Data, retentionartifact.DirectionInput, retentionartifact.KindFile, name, nb.Source.MediaType); ok {
										candidate.Ordinal = len(out.Artifacts)
										out.Artifacts = append(out.Artifacts, candidate)
									}
								}
							}
						}
					}
				}
			case "image":
				if b.Source != nil && b.Source.Type == "base64" && b.Source.Data != "" {
					out.Images = append(out.Images, InlineImage{MediaType: b.Source.MediaType, DataBase64: b.Source.Data})
				}
			}
		}
		if len(textParts) > 0 {
			out.Messages = append(out.Messages, newConvMessage(role, source, strings.Join(textParts, "\n")))
		}
		if role == "user" && len(textParts) == 0 && len(out.Artifacts) > 0 {
			m := newConvMessage(role, source, "")
			m.HasAttachments = true
			out.Messages = append(out.Messages, m)
		}
		anchorMessages(out.Messages[start:], messageIndex, "messages")
		for i := start; i < len(out.Messages); i++ {
			if out.Messages[i].Source != SourceToolResult {
				out.Messages[i].RawContent, _ = json.Marshal(ownBlocks)
			}
		}
	}
	if len(out.Messages) == 0 {
		return ParsedChat{}, false
	}
	finalizeParsedChat(&out)
	return out, true
}

// anthropicSystemText 解 system 字段：string 或 [{type:text,text}] 两种形态。
func anthropicSystemText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var blocks []anthropicContentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return ""
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" || b.Type == "" {
			if t := strings.TrimSpace(b.Text); t != "" {
				parts = append(parts, t)
			}
		}
	}
	return strings.Join(parts, "\n")
}

// anthropicToolResultText 解 tool_result.content：string 或 [{type:text,text}]。
func anthropicToolResultText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var blocks []anthropicContentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return ""
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" {
			if t := strings.TrimSpace(b.Text); t != "" {
				parts = append(parts, t)
			}
		}
	}
	return strings.Join(parts, "\n")
}
