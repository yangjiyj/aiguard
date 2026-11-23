package handler

import (
	"encoding/json"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

type openAIResponsesRequest struct {
	Model        string          `json:"model"`
	Instructions string          `json:"instructions"`
	Input        json.RawMessage `json:"input"`
}

type openAIResponsesInputMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
	Text    json.RawMessage `json:"text"`
}

func decodeOpenAIResponsesRequest(body []byte) (ExtractedContent, bool) {
	parsed, ok := aimsg.ParseOpenAIResponsesRequest(body)
	if !ok {
		return ExtractedContent{}, false
	}
	return extractedFromParsedChat(parsed)
}

func openAIResponsesRole(raw string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "system", "developer":
		return strings.ToLower(strings.TrimSpace(raw)), aimsg.SourceSystemPrompt
	case "assistant":
		return "assistant", aimsg.SourceAssistantHistory
	case "tool", "function":
		return "tool", aimsg.SourceToolResult
	default:
		return "user", aimsg.SourceUser
	}
}

func newOpenAIResponsesMessage(role, source, content string) aimsg.ConvMessage {
	return aimsg.ConvMessage{
		Role:          role,
		Source:        source,
		Content:       content,
		ContentSHA256: aimsg.ContentSHA256Hex(content),
	}
}

func openAIMessageText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text)
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var texts []string
	for _, part := range parts {
		if (part.Type == "" || part.Type == "text" || part.Type == "input_text") && strings.TrimSpace(part.Text) != "" {
			texts = append(texts, strings.TrimSpace(part.Text))
		}
	}
	return strings.Join(texts, "\n")
}
