package handler

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnthropicDocumentBlockIsPreservedForDLP(t *testing.T) {
	messages := anthropicMessageToOpenAI(AnthropicRequestMessage{
		Role: "user",
		Content: []interface{}{
			map[string]interface{}{
				"type": "document",
				"source": map[string]interface{}{
					"type":       "base64",
					"media_type": "application/pdf",
					"data":       "JVBERi0xLjQ=",
				},
				"title": "report.pdf",
			},
		},
	})
	if len(messages) != 1 {
		t.Fatalf("document message was dropped: %+v", messages)
	}
	atts := extractAttachments(messages[0].Content)
	if len(atts) != 1 {
		t.Fatalf("document attachment was not preserved: %+v", atts)
	}
	if atts[0]["content_type"] != "application/pdf" || atts[0]["data_base64"] != "JVBERi0xLjQ=" {
		t.Fatalf("document attachment=%+v", atts[0])
	}
}

func TestConvertAnthropicDocumentToChatKeepsAttachment(t *testing.T) {
	h := &MessagesHandler{}
	chat, err := h.convertToChatRequest(&AnthropicMessagesRequest{
		Model: "claude",
		Messages: []AnthropicRequestMessage{{
			Role: "user",
			Content: []interface{}{
				map[string]interface{}{
					"type": "document",
					"source": map[string]interface{}{
						"type":       "base64",
						"media_type": "application/pdf",
						"data":       "JVBERi0xLjQ=",
					},
					"title": "report.pdf",
				},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(chat.Messages) != 1 {
		t.Fatalf("document message was dropped: %+v", chat.Messages)
	}
	atts := extractAttachments(chat.Messages[0].Content)
	if len(atts) != 1 || atts[0]["content_type"] != "application/pdf" || atts[0]["data_base64"] != "JVBERi0xLjQ=" {
		t.Fatalf("document attachment=%+v", atts)
	}
}

func TestExtractAttachmentsAcceptsSingleFileObject(t *testing.T) {
	att := extractAttachments(json.RawMessage(`{"type":"file","file_data":{"base64":"aGVsbG8=","mime_type":"text/plain"},"filename":"a.txt"}`))
	if len(att) != 1 || att[0]["data_base64"] != "aGVsbG8=" {
		t.Fatalf("single file object was not collected: %+v", att)
	}
}

func TestNativeMessagesDocumentIsCollectedForDLP(t *testing.T) {
	raw := []byte(`{"model":"claude","messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBERi0xLjQ="},"title":"report.pdf"}]}]}`)
	document, err := parseNativeMessagesDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.request.Messages) != 1 {
		t.Fatalf("native document was dropped before security: %+v", document.request.Messages)
	}
	atts := extractAttachments(document.request.Messages[0].Content)
	if len(atts) != 1 || atts[0]["content_type"] != "application/pdf" {
		t.Fatalf("native document attachment=%+v", atts)
	}
}

func TestNativeResponsesSecurityViewAcceptsUnknownContentShapes(t *testing.T) {
	final := []byte(`{"id":"resp_1","object":"response","status":"completed","model":"gpt-5.6","output":[{"id":"file_1","type":"message","content":{"type":"output_file","file_id":"file-1","filename":"report.pdf"}},{"id":"msg_1","type":"message","content":[{"type":"output_text","text":"answer"}]}],"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3},"provider_extension":{"keep":true}}`)
	view, err := nativeResponsesSecurityView(final)
	if err != nil {
		t.Fatalf("unknown/file output content must not invalidate Responses payload: %v", err)
	}
	var response ChatCompletionResponse
	if err := json.Unmarshal(view, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Choices) != 1 || !strings.Contains(response.Choices[0].Message.Content, "answer") {
		t.Fatalf("security view=%s", view)
	}
}
