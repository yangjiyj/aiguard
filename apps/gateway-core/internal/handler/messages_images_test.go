package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

type openAIMessageContentPart struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	ImageURL struct {
		URL string `json:"url"`
	} `json:"image_url,omitempty"`
}

func anthropicBase64Image(mediaType, data string) map[string]interface{} {
	return map[string]interface{}{
		"type": "image",
		"source": map[string]interface{}{
			"type":       "base64",
			"media_type": mediaType,
			"data":       data,
		},
	}
}

func decodeOpenAIContentParts(t *testing.T, raw json.RawMessage) []openAIMessageContentPart {
	t.Helper()
	var parts []openAIMessageContentPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		t.Fatalf("OpenAI multimodal content is invalid: %v; raw=%s", err, raw)
	}
	return parts
}

func TestConvertToChatRequestForwardsDirectAnthropicBase64Image(t *testing.T) {
	h := &MessagesHandler{}
	chat, err := h.convertToChatRequest(&AnthropicMessagesRequest{
		Model: "vision-model",
		Messages: []AnthropicRequestMessage{{
			Role: "user",
			Content: []interface{}{
				anthropicBase64Image("image/png", "AQID"),
			},
		}},
	})
	if err != nil {
		t.Fatalf("convert direct image: %v", err)
	}
	if len(chat.Messages) != 1 || chat.Messages[0].Role != "user" {
		t.Fatalf("direct image must produce one user message, got %#v", chat.Messages)
	}
	parts := decodeOpenAIContentParts(t, chat.Messages[0].Content)
	if len(parts) != 1 || parts[0].Type != "image_url" {
		t.Fatalf("direct image must produce one image_url part, got %#v", parts)
	}
	if got := parts[0].ImageURL.URL; got != "data:image/png;base64,AQID" {
		t.Fatalf("image data URL changed: %q", got)
	}
	serialized, err := json.Marshal(chat)
	if err != nil {
		t.Fatalf("serialize OpenAI request: %v", err)
	}
	if !bytes.Contains(serialized, []byte(`"url":"data:image/png;base64,AQID"`)) {
		t.Fatalf("serialized upstream request lost image data URL: %s", serialized)
	}
	if got := messageText(chat.Messages[0].Content); got != "" {
		t.Fatalf("image-only content must not enter ordinary text logs, got %q", got)
	}
}

func TestConvertToChatRequestPreservesTextImageTextOrder(t *testing.T) {
	h := &MessagesHandler{}
	chat, err := h.convertToChatRequest(&AnthropicMessagesRequest{
		Model: "vision-model",
		Messages: []AnthropicRequestMessage{{
			Role: "user",
			Content: []interface{}{
				map[string]interface{}{"type": "text", "text": "before"},
				anthropicBase64Image("image/jpeg", "/9j/2Q=="),
				map[string]interface{}{"type": "text", "text": "after"},
			},
		}},
	})
	if err != nil {
		t.Fatalf("convert mixed content: %v", err)
	}
	if len(chat.Messages) != 1 {
		t.Fatalf("mixed content must stay in one message, got %#v", chat.Messages)
	}
	parts := decodeOpenAIContentParts(t, chat.Messages[0].Content)
	if len(parts) != 3 {
		t.Fatalf("mixed content block count changed: %#v", parts)
	}
	if parts[0].Type != "text" || parts[0].Text != "before" ||
		parts[1].Type != "image_url" || parts[1].ImageURL.URL != "data:image/jpeg;base64,/9j/2Q==" ||
		parts[2].Type != "text" || parts[2].Text != "after" {
		t.Fatalf("text/image/text order or content changed: %#v", parts)
	}
	if got := messageText(chat.Messages[0].Content); got != "before\nafter" {
		t.Fatalf("ordinary text extraction leaked or lost content: %q", got)
	}
}

func TestConvertToChatRequestSupportsRequiredImageMediaTypes(t *testing.T) {
	cases := []struct {
		name      string
		mediaType string
	}{
		{name: "jpeg", mediaType: "image/jpeg"},
		{name: "png", mediaType: "image/png"},
		{name: "gif", mediaType: "image/gif"},
		{name: "webp", mediaType: "image/webp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &MessagesHandler{}
			chat, err := h.convertToChatRequest(&AnthropicMessagesRequest{
				Model: "vision-model",
				Messages: []AnthropicRequestMessage{{
					Role:    "user",
					Content: []interface{}{anthropicBase64Image(tc.mediaType, "AQID")},
				}},
			})
			if err != nil {
				t.Fatalf("convert %s image: %v", tc.mediaType, err)
			}
			parts := decodeOpenAIContentParts(t, chat.Messages[0].Content)
			want := "data:" + tc.mediaType + ";base64,AQID"
			if len(parts) != 1 || parts[0].ImageURL.URL != want {
				t.Fatalf("%s image was not forwarded: %#v", tc.mediaType, parts)
			}
		})
	}
}

func TestConvertToChatRequestKeepsToolResultAndAppendsImageUserMessage(t *testing.T) {
	h := &MessagesHandler{}
	chat, err := h.convertToChatRequest(&AnthropicMessagesRequest{
		Model: "vision-model",
		Messages: []AnthropicRequestMessage{
			{
				Role: "assistant",
				Content: []interface{}{
					map[string]interface{}{
						"type":  "tool_use",
						"id":    "toolu_read_image",
						"name":  "Read",
						"input": map[string]interface{}{"file_path": "/tmp/screenshot.png"},
					},
				},
			},
			{
				Role: "user",
				Content: []interface{}{
					map[string]interface{}{
						"type":        "tool_result",
						"tool_use_id": "toolu_read_image",
						"content": []interface{}{
							map[string]interface{}{"type": "text", "text": "read image"},
							anthropicBase64Image("image/png", "AQID"),
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("convert tool_result image: %v", err)
	}
	if len(chat.Messages) != 3 {
		t.Fatalf("want assistant tool call, tool result, image user message; got %#v", chat.Messages)
	}
	assistant, toolResult, imageMessage := chat.Messages[0], chat.Messages[1], chat.Messages[2]
	if assistant.Role != "assistant" || len(assistant.ToolCalls) != 1 ||
		assistant.ToolCalls[0].ID != "toolu_read_image" {
		t.Fatalf("assistant tool call changed: %#v", assistant)
	}
	if toolResult.Role != "tool" || toolResult.ToolCallID != "toolu_read_image" ||
		string(toolResult.Content) != `"read image"` {
		t.Fatalf("tool result correlation or text changed: %#v", toolResult)
	}
	if imageMessage.Role != "user" {
		t.Fatalf("tool image must immediately follow as user message: %#v", imageMessage)
	}
	parts := decodeOpenAIContentParts(t, imageMessage.Content)
	if len(parts) != 1 || parts[0].ImageURL.URL != "data:image/png;base64,AQID" {
		t.Fatalf("tool image was not forwarded: %#v", parts)
	}
}

func TestMessagesHandlerRejectsInvalidAnthropicImagesAsInvalidRequest(t *testing.T) {
	cases := []struct {
		name            string
		source          map[string]interface{}
		wantMessagePart string
		sensitive       string
	}{
		{
			name: "invalid base64",
			source: map[string]interface{}{
				"type": "base64", "media_type": "image/png", "data": "not-valid-%%%",
			},
			wantMessagePart: "invalid image base64 data",
			sensitive:       "not-valid-%%%",
		},
		{
			name: "empty data",
			source: map[string]interface{}{
				"type": "base64", "media_type": "image/png", "data": "",
			},
			wantMessagePart: "image data must not be empty",
		},
		{
			name: "unsupported MIME",
			source: map[string]interface{}{
				"type": "base64", "media_type": "image/svg+xml", "data": "PHN2Zz4=",
			},
			wantMessagePart: "unsupported image media_type",
			sensitive:       "PHN2Zz4=",
		},
		{
			name: "non base64 source",
			source: map[string]interface{}{
				"type": "url", "url": "https://example.invalid/image.png",
			},
			wantMessagePart: "image source type must be base64",
			sensitive:       "https://example.invalid/image.png",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(AnthropicMessagesRequest{
				Model: "vision-model",
				Messages: []AnthropicRequestMessage{{
					Role: "user",
					Content: []interface{}{
						map[string]interface{}{"type": "image", "source": tc.source},
					},
				}},
			})
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}

			audit := &MockAuditWriter{}
			h := &MessagesHandler{cfg: &config.Config{}, auditWriter: audit}
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("invalid image must return 400, got %d body=%s", w.Code, w.Body.String())
			}
			var response struct {
				Type  string `json:"type"`
				Error struct {
					Type    string `json:"type"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode error response: %v body=%s", err, w.Body.String())
			}
			if response.Type != "error" || response.Error.Type != "invalid_request_error" {
				t.Fatalf("invalid image error=%#v, want Anthropic invalid_request_error", response)
			}
			if !strings.Contains(response.Error.Message, tc.wantMessagePart) {
				t.Fatalf("error message=%q, want sanitized reason containing %q", response.Error.Message, tc.wantMessagePart)
			}
			if tc.sensitive != "" && strings.Contains(w.Body.String(), tc.sensitive) {
				t.Fatalf("error response leaked image data or URL")
			}
			if len(audit.RequestLogFinalizes) != 1 ||
				audit.RequestLogFinalizes[0].Status != "invalid_request" ||
				audit.RequestLogFinalizes[0].StatusCode != http.StatusBadRequest {
				t.Fatalf("invalid image audit boundary changed: %#v", audit.RequestLogFinalizes)
			}
		})
	}
}

func TestConvertToChatRequestPlainTextUnchanged(t *testing.T) {
	h := &MessagesHandler{}
	chat, err := h.convertToChatRequest(&AnthropicMessagesRequest{
		Model:    "text-model",
		Messages: []AnthropicRequestMessage{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("convert plain text: %v", err)
	}
	if len(chat.Messages) != 1 || chat.Messages[0].Role != "user" ||
		string(chat.Messages[0].Content) != `"hello"` {
		t.Fatalf("plain text conversion changed: %#v", chat.Messages)
	}
}
