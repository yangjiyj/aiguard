package aimsg

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
)

type openAIToolCall struct {
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type openAIMessage struct {
	Role      string           `json:"role"`
	Content   json.RawMessage  `json:"content"` // string、null 或 parts 数组
	ToolCalls []openAIToolCall `json:"tool_calls"`
}

type openAITool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type openAIChatRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
	Tools    []openAITool    `json:"tools"`
}

// ParseOpenAIChatRequest 解析标准 /v1/chat/completions 请求体。
// source 归类：system/developer→system_prompt；user→user；assistant→assistant_history
// （content 与 tool_calls.arguments 合并）；tool→tool_result；tools[]→tool_def（前置）。
// system 消息在 messages 内出现（OpenAI 形态），全部拼进 SystemText。
func ParseOpenAIChatRequest(body []byte) (ParsedChat, bool) {
	var req openAIChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return ParsedChat{}, false
	}
	if len(req.Messages) == 0 {
		return ParsedChat{}, false
	}
	out := ParsedChat{Model: strings.TrimSpace(req.Model)}
	for _, tool := range req.Tools {
		content := "[tool_def:" + tool.Function.Name + "] " + strings.TrimSpace(tool.Function.Description)
		if len(tool.Function.Parameters) > 0 {
			content += "\n" + compactJSON(tool.Function.Parameters)
		}
		out.Messages = append(out.Messages, newConvMessage("tool", SourceToolDef, content))
	}
	var systemParts []string
	for messageIndex, msg := range req.Messages {
		start := len(out.Messages)
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		content := openAIMessageText(msg.Content)
		// 内嵌图片（OpenAI vision 形态 image_url data URI，如 WorkBuddy 粘贴截图）——不分角色收集，
		// 由 extractedFromParsedChat 转成留证附件；此前 openAIMessageText 只取 text、丢 image_url，
		// 导致走结构化解码器的工具（WorkBuddy 等）图片从留证消失（回归）。与 Anthropic 路对称。
		images := openAIImagesFromContent(msg.Content)
		out.Images = append(out.Images, images...)
		switch role {
		case "system", "developer":
			if content != "" {
				systemParts = append(systemParts, content)
				out.Messages = append(out.Messages, newConvMessage(role, SourceSystemPrompt, content))
			}
		case "tool", "function":
			if content != "" {
				out.Messages = append(out.Messages, newConvMessage(role, SourceToolResult, content))
			}
		case "assistant":
			var parts []string
			if content != "" {
				parts = append(parts, content)
			}
			for _, tc := range msg.ToolCalls {
				part := "[tool_use:" + tc.Function.Name + "]"
				if args := strings.TrimSpace(tc.Function.Arguments); args != "" {
					part += " " + args
				}
				parts = append(parts, part)
			}
			if len(parts) > 0 {
				out.Messages = append(out.Messages, newConvMessage("assistant", SourceAssistantHistory, strings.Join(parts, "\n")))
			}
		case "user":
			if content != "" || len(images) > 0 || len(openAIArtifactCandidates(msg.Content, retentionartifact.DirectionInput)) > 0 {
				out.Messages = append(out.Messages, newConvMessage("user", SourceUser, content))
				out.Messages[len(out.Messages)-1].HasAttachments = len(images) > 0 || len(openAIArtifactCandidates(msg.Content, retentionartifact.DirectionInput)) > 0
			}
			out.Artifacts = openAIArtifactCandidates(msg.Content, retentionartifact.DirectionInput)
		default:
			// 未知角色不能伪装成真实用户。安全引擎对 unknown 继续确定性扫描，
			// 已知 LLM/Agent 协议不对它运行指令覆盖语义裁判。
			if content != "" {
				out.Messages = append(out.Messages, newConvMessage(role, SourceUnknown, content))
			}
		}
		anchorMessages(out.Messages[start:], messageIndex, "messages")
		for i := start; i < len(out.Messages); i++ {
			out.Messages[i].RawContent = msg.Content
		}
	}
	out.SystemText = strings.Join(systemParts, "\n")
	if len(out.Messages) == 0 {
		return ParsedChat{}, false
	}
	finalizeParsedChat(&out)
	return out, true
}

// openAIMessageText 解 content：string、null 或 parts 数组（type=text/input_text 取 text；image_url 忽略）。
func openAIMessageText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return ""
	}
	var texts []string
	for _, p := range parts {
		if (p.Type == "text" || p.Type == "input_text" || p.Type == "") && strings.TrimSpace(p.Text) != "" {
			texts = append(texts, strings.TrimSpace(p.Text))
		}
	}
	return strings.Join(texts, "\n")
}

// openAIImagesFromContent 从 message.content 的 parts 数组抽内嵌图片（image_url 形态）。
// image_url 可为对象 {url,detail} 或裸字符串；仅收 data:...;base64,... 内联图（InlineImage 只存
// base64 字节），远程 URL 图跳过（走文本引用，不在此结构化收集）。非 parts 数组（string/null）无图。
func openAIImagesFromContent(raw json.RawMessage) []InlineImage {
	if len(raw) == 0 {
		return nil
	}
	var parts []struct {
		Type     string          `json:"type"`
		ImageURL json.RawMessage `json:"image_url"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil
	}
	var imgs []InlineImage
	for _, p := range parts {
		if len(p.ImageURL) == 0 {
			continue
		}
		url := openAIImageURLString(p.ImageURL)
		if img, ok := inlineImageFromDataURL(url); ok {
			imgs = append(imgs, img)
		}
	}
	return imgs
}

// openAIImageURLString 取 image_url 字段里的 url：对象 {url:...} 或裸字符串两种形态。
func openAIImageURLString(raw json.RawMessage) string {
	var obj struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && obj.URL != "" {
		return obj.URL
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return ""
}

// inlineImageFromDataURL 解 data:<mediatype>;base64,<payload> 内联图 URI。
// 非 data:/非 base64/无逗号分隔 → 不匹配（返回 false）。
func inlineImageFromDataURL(url string) (InlineImage, bool) {
	url = strings.TrimSpace(url)
	if !strings.HasPrefix(strings.ToLower(url), "data:") {
		return InlineImage{}, false
	}
	comma := strings.IndexByte(url, ',')
	if comma < 0 {
		return InlineImage{}, false
	}
	meta := url[len("data:"):comma]
	payload := strings.TrimSpace(url[comma+1:])
	if payload == "" || !strings.Contains(strings.ToLower(meta), "base64") {
		return InlineImage{}, false
	}
	mediaType := meta
	if i := strings.IndexByte(meta, ';'); i >= 0 {
		mediaType = meta[:i]
	}
	return InlineImage{MediaType: strings.TrimSpace(mediaType), DataBase64: payload}, true
}

// ParseChatRequest 是形态自适应入口：按路径提示选首选解析器，失败再试另一形态。
// /v1/messages → anthropic 优先；其余（chat/completions 及兼容端点）→ openai 优先。
// 两形态字段有交叠但互斥关键字段不同（anthropic: 顶层 system/tool_use 块；openai: role=system/tool、
// tool_calls），误配基本只会解析失败而非误读；首选成功即返回，不做二次猜测。
func ParseChatRequest(path string, body []byte) (ParsedChat, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ParsedChat{}, false
	}
	lowerPath := strings.ToLower(path)
	if strings.Contains(lowerPath, "/v1/responses") {
		if parsed, ok := ParseOpenAIResponsesRequest(body); ok {
			return parsed, true
		}
		return ParsedChat{}, false
	}
	if strings.Contains(lowerPath, "/v1/messages") {
		if parsed, ok := ParseAnthropicMessagesRequest(body); ok {
			return parsed, true
		}
		return ParseOpenAIChatRequest(body)
	}
	if parsed, ok := ParseOpenAIChatRequest(body); ok {
		return parsed, true
	}
	if parsed, ok := ParseGeminiGenerateContentRequest(body); ok {
		return parsed, true
	}
	return ParseAnthropicMessagesRequest(body)
}
