package handler

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestAnthropicMessageToOpenAI_EmptyStringToolResultIsPreserved(t *testing.T) {
	messages := anthropicMessageToOpenAI(AnthropicRequestMessage{
		Role: "user",
		Content: []interface{}{
			map[string]interface{}{
				"type":        "tool_result",
				"tool_use_id": "toolu_empty_string",
				"content":     "",
			},
		},
	})

	if len(messages) != 1 {
		t.Fatalf("empty string tool_result must produce one tool message, got %#v", messages)
	}
	if messages[0].Role != "tool" || messages[0].ToolCallID != "toolu_empty_string" {
		t.Fatalf("tool result correlation was not preserved: %#v", messages[0])
	}
	if got := string(messages[0].Content); got != `""` {
		t.Fatalf("empty tool result must use JSON empty string content, got %s", got)
	}
}

func TestAnthropicMessageToOpenAI_EmptyArrayToolResultIsPreserved(t *testing.T) {
	messages := anthropicMessageToOpenAI(AnthropicRequestMessage{
		Role: "user",
		Content: []interface{}{
			map[string]interface{}{
				"type":        "tool_result",
				"tool_use_id": "toolu_empty_array",
				"content":     []interface{}{},
			},
		},
	})

	if len(messages) != 1 {
		t.Fatalf("empty array tool_result must produce one tool message, got %#v", messages)
	}
	if messages[0].Role != "tool" || messages[0].ToolCallID != "toolu_empty_array" {
		t.Fatalf("tool result correlation was not preserved: %#v", messages[0])
	}
	if got := string(messages[0].Content); got != `""` {
		t.Fatalf("empty tool result must use JSON empty string content, got %s", got)
	}
}

func TestAnthropicMessageToOpenAI_UnknownToolResultIsPreserved(t *testing.T) {
	messages := anthropicMessageToOpenAI(AnthropicRequestMessage{
		Role: "user",
		Content: []interface{}{
			map[string]interface{}{
				"type":        "tool_result",
				"tool_use_id": "toolu_unextractable",
				"content":     map[string]interface{}{"type": "unknown"},
			},
		},
	})

	if len(messages) != 1 {
		t.Fatalf("unextractable tool_result must produce one tool message, got %#v", messages)
	}
	if messages[0].Role != "tool" || messages[0].ToolCallID != "toolu_unextractable" {
		t.Fatalf("tool result correlation was not preserved: %#v", messages[0])
	}
	if got := string(messages[0].Content); got != `""` {
		t.Fatalf("unextractable tool result must use JSON empty string content, got %s", got)
	}
}

func TestAnthropicMessageToOpenAI_TextToolResultIsUnchanged(t *testing.T) {
	messages := anthropicMessageToOpenAI(AnthropicRequestMessage{
		Role: "user",
		Content: []interface{}{
			map[string]interface{}{
				"type":        "tool_result",
				"tool_use_id": "toolu_text",
				"content":     "command completed",
			},
		},
	})

	if len(messages) != 1 {
		t.Fatalf("text tool_result must produce one tool message, got %#v", messages)
	}
	if messages[0].Role != "tool" || messages[0].ToolCallID != "toolu_text" {
		t.Fatalf("tool result correlation was not preserved: %#v", messages[0])
	}
	if got := string(messages[0].Content); got != `"command completed"` {
		t.Fatalf("text tool result changed, got %s", got)
	}
}

func TestAnthropicMessageToOpenAI_MissingToolUseIDDoesNotCreateToolMessage(t *testing.T) {
	messages := anthropicMessageToOpenAI(AnthropicRequestMessage{
		Role: "user",
		Content: []interface{}{
			map[string]interface{}{
				"type":    "tool_result",
				"content": "must not be synthesized",
			},
		},
	})

	if len(messages) != 0 {
		t.Fatalf("tool_result without tool_use_id must not produce a tool message, got %#v", messages)
	}
}

func TestAnthropicMessageToOpenAI_WhitespaceToolUseIDDoesNotCreateToolMessage(t *testing.T) {
	messages := anthropicMessageToOpenAI(AnthropicRequestMessage{
		Role: "user",
		Content: []interface{}{
			map[string]interface{}{
				"type":        "tool_result",
				"tool_use_id": "  \t ",
				"content":     "must not be synthesized",
			},
		},
	})

	if len(messages) != 0 {
		t.Fatalf("tool_result with whitespace-only tool_use_id must not produce a tool message, got %#v", messages)
	}
}

func TestConvertToChatRequest_KeepsEmptyToolResultAdjacentAndSerialized(t *testing.T) {
	h := &MessagesHandler{}
	chat, err := h.convertToChatRequest(&AnthropicMessagesRequest{
		Model: "test-model",
		Messages: []AnthropicRequestMessage{
			{Role: "user", Content: "run the quiet command"},
			{
				Role: "assistant",
				Content: []interface{}{
					map[string]interface{}{
						"type":  "tool_use",
						"id":    "toolu_quiet",
						"name":  "shell",
						"input": map[string]interface{}{"command": "true"},
					},
				},
			},
			{
				Role: "user",
				Content: []interface{}{
					map[string]interface{}{
						"type":        "tool_result",
						"tool_use_id": "toolu_quiet",
						"content":     "",
					},
				},
			},
			{Role: "user", Content: "continue after the quiet command"},
		},
	})
	if err != nil {
		t.Fatalf("convertToChatRequest returned error: %v", err)
	}
	if len(chat.Messages) != 4 {
		t.Fatalf("assistant tool_use and empty tool_result must remain adjacent, got %#v", chat.Messages)
	}
	assistant, toolResult := chat.Messages[1], chat.Messages[2]
	if assistant.Role != "assistant" || len(assistant.ToolCalls) != 1 {
		t.Fatalf("expected converted assistant tool call, got %#v", assistant)
	}
	if toolResult.Role != "tool" || toolResult.ToolCallID != assistant.ToolCalls[0].ID {
		t.Fatalf("tool result must immediately match prior tool call: assistant=%#v tool=%#v", assistant, toolResult)
	}
	if got := string(toolResult.Content); got != `""` {
		t.Fatalf("empty tool result must use JSON empty string content, got %s", got)
	}

	payload, err := json.Marshal(chat)
	if err != nil {
		t.Fatalf("marshal OpenAI request: %v", err)
	}
	if !bytes.Contains(payload, []byte(`"content":""`)) {
		t.Fatalf("serialized OpenAI request must retain explicit empty content, got %s", payload)
	}
}
